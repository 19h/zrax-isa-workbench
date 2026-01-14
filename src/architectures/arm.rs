//! ARM32 architecture analysis.

/// ARM condition codes.
pub mod condition {
    pub const EQ: u8 = 0x0;  // Equal
    pub const NE: u8 = 0x1;  // Not equal
    pub const CS: u8 = 0x2;  // Carry set / unsigned higher or same
    pub const CC: u8 = 0x3;  // Carry clear / unsigned lower
    pub const MI: u8 = 0x4;  // Negative
    pub const PL: u8 = 0x5;  // Positive or zero
    pub const VS: u8 = 0x6;  // Overflow
    pub const VC: u8 = 0x7;  // No overflow
    pub const HI: u8 = 0x8;  // Unsigned higher
    pub const LS: u8 = 0x9;  // Unsigned lower or same
    pub const GE: u8 = 0xA;  // Signed greater or equal
    pub const LT: u8 = 0xB;  // Signed less than
    pub const GT: u8 = 0xC;  // Signed greater than
    pub const LE: u8 = 0xD;  // Signed less or equal
    pub const AL: u8 = 0xE;  // Always
    pub const NV: u8 = 0xF;  // Never / unconditional
}

/// ARM instruction patterns.
pub mod patterns {
    pub const NOP: u32 = 0xE1A00000;      // MOV R0, R0
    pub const NOP_HINT: u32 = 0xE320F000; // NOP (hint)
    pub const BX_LR: u32 = 0xE12FFF1E;    // BX LR (return)
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

/// Score likelihood of ARM32 code.
///
/// Analyzes raw bytes for patterns characteristic of ARM32:
/// - Condition codes in bits [31:28]
/// - Common instructions (NOP, BX LR, PUSH, POP)
/// - Data processing patterns
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // ARM32 instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

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

        // Invalid - all zeros or all ones
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 10;
        }
    }

    score.max(0)
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
