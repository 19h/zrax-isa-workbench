//! Alpha (DEC Alpha) architecture support.
//!
//! Alpha is a 64-bit RISC architecture developed by Digital Equipment Corporation.
//! It uses little-endian 32-bit fixed-width instructions.

/// NOP instruction: `bis $31, $31, $31` (OR zero with zero into zero)
pub const ALPHA_NOP: u32 = 0x47FF_041F;

/// Alternative NOP: `unop` (universal NOP)
pub const ALPHA_UNOP: u32 = 0x2FFE_0000;

/// RET instruction: `ret $31, ($26), 1`
pub const ALPHA_RET: u32 = 0x6BFA_8001;

/// CALL_PAL opcode - privileged architecture library call
pub const OP_CALL_PAL: u32 = 0x00;

/// Opcode ranges for common instruction classes
pub const OP_LOAD_STORE_START: u32 = 0x08;
pub const OP_LOAD_STORE_END: u32 = 0x0F;
pub const OP_INT_ARITH: u32 = 0x10;
pub const OP_INT_LOGICAL: u32 = 0x11;
pub const OP_INT_SHIFT: u32 = 0x12;
pub const OP_INT_MULTIPLY: u32 = 0x13;
pub const OP_JUMP: u32 = 0x1A;
pub const OP_FLOATING: u32 = 0x1C;
pub const OP_BRANCH_START: u32 = 0x30;
pub const OP_BRANCH_END: u32 = 0x3F;

/// Score likelihood of Alpha code.
///
/// Alpha uses little-endian 32-bit instructions with a 6-bit opcode field
/// in bits 26-31.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut last_word = 0u32;
    let mut repeat_count = 0u32;
    let mut zero_run = 0u32;

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Track zero runs
        if word == 0x00000000 {
            zero_run += 1;
            if zero_run > 2 {
                score -= 3;
            }
            last_word = word;
            continue;
        }
        zero_run = 0;

        // Track repeated patterns (padding)
        if word == last_word {
            repeat_count += 1;
            if repeat_count > 4 {
                continue; // Skip padding
            }
        } else {
            repeat_count = 0;
        }
        last_word = word;

        let opcode = (word >> 26) & 0x3F;

        // NOP (bis $31, $31, $31 or unop)
        if word == ALPHA_NOP || word == ALPHA_UNOP {
            score += 25;
        }

        // RET (ret $31, ($26), 1)
        if word == ALPHA_RET {
            score += 30;
        }

        // CALL_PAL
        if opcode == OP_CALL_PAL {
            score += 15;
        }

        // Common opcodes
        match opcode {
            OP_LOAD_STORE_START..=OP_LOAD_STORE_END => score += 3, // Load/Store
            OP_INT_ARITH => score += 5,                            // Integer arithmetic
            OP_INT_LOGICAL => score += 3,                          // Integer logical
            OP_INT_SHIFT => score += 3,                            // Integer shift
            OP_INT_MULTIPLY => score += 3,                         // Integer multiply
            OP_JUMP => score += 5,                                 // Jump
            OP_FLOATING => score += 3,                             // Floating
            OP_BRANCH_START..=OP_BRANCH_END => score += 4,         // Branch
            _ => {}
        }

        if word == 0xFFFF_FFFF {
            score -= 5;
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpha_nop() {
        let code = ALPHA_NOP.to_le_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_alpha_ret() {
        let code = ALPHA_RET.to_le_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_alpha_sequence() {
        // NOP + RET
        let mut code = Vec::new();
        code.extend_from_slice(&ALPHA_NOP.to_le_bytes());
        code.extend_from_slice(&ALPHA_RET.to_le_bytes());
        assert!(score(&code) >= 55); // 25 + 30
    }
}
