//! Lanai architecture support.
//!
//! Lanai is a 32-bit RISC architecture (big-endian) with fixed-width
//! 32-bit instructions.

/// NOP instruction (0x00000001)
pub const LANAI_NOP: u32 = 0x0000_0001;

/// Prologue: st %fp, [--%sp]
pub const LANAI_PUSH_FP: u32 = 0x9293_FFFC;

/// Epilogue return: ld -4[%fp], %pc
pub const LANAI_RET_PC: u32 = 0x8116_FFFC;

/// Epilogue: ld -8[%fp], %fp
pub const LANAI_RESTORE_FP: u32 = 0x8296_FFF8;

/// Return value zeroing: or %r0, 0x0, %rv
pub const LANAI_RETVAL_ZERO: u32 = 0x5400_0000;

/// add %sp, imm, %fp
pub const LANAI_ADD_SP_FP_MASK: u32 = 0xFFFF_0000;
pub const LANAI_ADD_SP_FP_PATTERN: u32 = 0x0290_0000;

/// sub %sp, imm, %sp
pub const LANAI_SUB_SP_MASK: u32 = 0xFFFF_0000;
pub const LANAI_SUB_SP_PATTERN: u32 = 0x2210_0000;

/// add %fp, imm, %sp
pub const LANAI_ADD_FP_SP_MASK: u32 = 0xFFFF_0000;
pub const LANAI_ADD_FP_SP_PATTERN: u32 = 0x0214_0000;

/// Call stub patterns
pub const LANAI_CALL_ADD_PC: u32 = 0x0788_0010; // add %pc, 0x10, %rca
pub const LANAI_CALL_PUSH_RCA: u32 = 0x9793_FFFC; // st %rca, [--%sp]

/// Score likelihood of Lanai code.
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 4 {
        return 0;
    }

    let mut words = Vec::new();
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        words.push(word);
    }

    let mut score: i64 = 0;

    for &word in &words {
        if word == LANAI_NOP {
            score += 15;
        }
        if word == LANAI_PUSH_FP {
            score += 35;
        }
        if word == LANAI_RET_PC {
            score += 45;
        }
        if word == LANAI_RESTORE_FP {
            score += 25;
        }
        if word == LANAI_RETVAL_ZERO {
            score += 8;
        }
        if (word & LANAI_ADD_SP_FP_MASK) == LANAI_ADD_SP_FP_PATTERN {
            score += 4;
        }
        if (word & LANAI_SUB_SP_MASK) == LANAI_SUB_SP_PATTERN {
            score += 4;
        }
        if (word & LANAI_ADD_FP_SP_MASK) == LANAI_ADD_FP_SP_PATTERN {
            score += 4;
        }

        let top = word & 0xFF00_0000;
        if matches!(top, 0xE000_0000 | 0xE400_0000 | 0xE600_0000) {
            score += 6; // bt/bult/beq/bne
        }

        let top_byte = (word >> 24) as u8;
        if matches!(top_byte, 0x71 | 0x74 | 0x76 | 0x78 | 0x7A) {
            score += 4; // sh/sha family
        }

        if word == LANAI_CALL_ADD_PC {
            score += 10;
        }
        if word == LANAI_CALL_PUSH_RCA {
            score += 10;
        }

        if word == 0x0000_0000 || word == 0xFFFF_FFFF {
            score -= 6;
        }
    }

    for i in 0..words.len() {
        if i + 2 < words.len()
            && words[i] == LANAI_PUSH_FP
            && (words[i + 1] & LANAI_ADD_SP_FP_MASK) == LANAI_ADD_SP_FP_PATTERN
            && (words[i + 2] & LANAI_SUB_SP_MASK) == LANAI_SUB_SP_PATTERN
        {
            score += 40; // common function prologue
        }

        if i + 2 < words.len()
            && words[i] == LANAI_RET_PC
            && (words[i + 1] & LANAI_ADD_FP_SP_MASK) == LANAI_ADD_FP_SP_PATTERN
            && words[i + 2] == LANAI_RESTORE_FP
        {
            score += 35; // common function epilogue
        }

        if i + 2 < words.len()
            && words[i] == LANAI_CALL_ADD_PC
            && words[i + 1] == LANAI_CALL_PUSH_RCA
            && (words[i + 2] & 0xFF00_0000) == 0xE000_0000
        {
            score += 30; // call stub
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lanai_nop() {
        let code = [0x00, 0x00, 0x00, 0x01];
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_lanai_prologue_sequence() {
        let code = [
            0x92, 0x93, 0xFF, 0xFC, // st %fp, [--%sp]
            0x02, 0x90, 0x00, 0x08, // add %sp, 0x8, %fp
            0x22, 0x10, 0x00, 0x08, // sub %sp, 0x8, %sp
        ];
        assert!(score(&code) >= 40);
    }

    #[test]
    fn test_lanai_epilogue_sequence() {
        let code = [
            0x81, 0x16, 0xFF, 0xFC, // ld -4[%fp], %pc
            0x02, 0x14, 0x00, 0x00, // add %fp, 0x0, %sp
            0x82, 0x96, 0xFF, 0xF8, // ld -8[%fp], %fp
        ];
        assert!(score(&code) >= 35);
    }
}
