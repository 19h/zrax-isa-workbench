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
/// in bits 26-31. Scoring is conservative to avoid false positives since
/// Alpha's opcode ranges cover ~44% of the 6-bit space.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut last_word = 0u32;
    let mut repeat_count = 0u32;
    let mut zero_run = 0u32;
    let mut ret_count = 0u32;
    let mut nop_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;

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
                continue;
            }
        } else {
            repeat_count = 0;
        }
        last_word = word;

        let opcode = (word >> 26) & 0x3F;
        let ra = (word >> 21) & 0x1F;
        let rb = (word >> 16) & 0x1F;

        // NOP (bis $31, $31, $31 or unop) - exact patterns
        if word == ALPHA_NOP || word == ALPHA_UNOP {
            score += 25;
            nop_count += 1;
            continue;
        }

        // RET (ret $31, ($26), 1) - exact pattern
        if word == ALPHA_RET {
            score += 30;
            ret_count += 1;
            continue;
        }

        // JSR/RET/JMP family (opcode 0x1A) - validate function code
        if opcode == OP_JUMP {
            let func = (word >> 14) & 0x3;
            match func {
                0 => { score += 8; call_count += 1; }
                1 => { score += 8; ret_count += 1; }
                2 => { score += 5; }
                3 => { score += 6; call_count += 1; }
                _ => { score += 3; }
            }
            continue;
        }

        // CALL_PAL - validate function code is in known range
        if opcode == OP_CALL_PAL as u32 {
            let func = word & 0x03FFFFFF;
            // Known PAL codes: halt(0), cflush(1), draina(2), etc.
            if func < 0x100 {
                score += 10;
                call_count += 1;
            }
            continue;
        }

        if word == 0xFFFF_FFFF {
            score -= 5;
            continue;
        }

        // --- Cross-architecture penalties ---
        // AArch64 (LE)
        if word == 0xD65F03C0 { score -= 15; continue; }  // RET
        if word == 0xD503201F { score -= 10; continue; }  // NOP
        if (word >> 26) == 0x25 { score -= 5; }           // BL

        // RISC-V (LE)
        if word == 0x00008067 { score -= 12; continue; }  // RET
        if word == 0x00000013 { score -= 8; continue; }   // NOP

        // Thumb-2 32-bit patterns
        {
            let hw_low = (word & 0xFFFF) as u16;
            let hw_high = (word >> 16) as u16;
            if hw_low == 0xE92D { score -= 10; continue; }  // PUSH.W
            if hw_low == 0xE8BD { score -= 10; continue; }  // POP.W
            if (hw_low & 0xF800) == 0xF000 && (hw_high & 0xD000) == 0xD000 {
                score -= 8; continue;  // Thumb-2 BL
            }
        }

        // ARM32 patterns
        {
            let cond = (word >> 28) & 0xF;
            if word == 0xE12FFF1E { score -= 15; }  // BX LR
            if word == 0xE1A00000 { score -= 12; }  // NOP
            if cond == 0xE && ((word & 0x0FFF0000) == 0x092D0000 || (word & 0x0FFF0000) == 0x08BD0000) {
                score -= 8;
            }
        }

        // Common opcodes - reduced scores, require structural validation
        let mut matched = true;
        match opcode {
            OP_LOAD_STORE_START..=OP_LOAD_STORE_END => {
                if ra <= 30 {
                    score += 2;
                }
            }
            OP_INT_ARITH => {
                let func = (word >> 5) & 0x7F;
                if matches!(func, 0x00 | 0x02 | 0x09 | 0x0B | 0x0F | 0x12 | 0x1B | 0x1D | 0x20 | 0x22 | 0x29 | 0x2B | 0x2D | 0x32 | 0x3B | 0x3D | 0x40 | 0x49 | 0x4D | 0x60 | 0x69 | 0x6D) {
                    score += 4;
                } else {
                    score += 1;
                }
            }
            OP_INT_LOGICAL => {
                score += 2;
            }
            OP_INT_SHIFT => {
                score += 2;
            }
            OP_INT_MULTIPLY => {
                score += 2;
            }
            OP_FLOATING => {
                score += 2;
            }
            OP_BRANCH_START..=OP_BRANCH_END => {
                if ra <= 31 {
                    score += 2;
                    branch_count += 1;
                }
            }
            _ => { matched = false; }
        }

        if !matched {
            score -= 1;
        }
    }

    // Structural requirement
    let num_words = data.len() / 4;
    if num_words > 20 {
        let distinctive = ret_count + call_count;
        if distinctive == 0 && branch_count == 0 {
            score = (score as f64 * 0.10) as i64;
        } else if distinctive == 0 {
            score = (score as f64 * 0.25) as i64;
        }
    }

    // Bonus for seeing distinctive Alpha patterns
    if ret_count >= 1 && nop_count >= 1 {
        score += 15;
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
