//! Nios II architecture support.
//!
//! Nios II is a soft processor core for Intel (formerly Altera) FPGAs.
//! It uses little-endian 32-bit fixed-width instructions.

/// NOP instruction
pub const NIOS2_NOP: u32 = 0x0001_883A;

/// RET instruction - return from subroutine
pub const NIOS2_RET: u32 = 0xF800_283A;

/// ERET instruction - return from exception
pub const NIOS2_ERET: u32 = 0xE800_003A;

/// BREAK instruction mask/pattern
pub const MASK_BREAK: u32 = 0x07FF_FFFF;
pub const PATTERN_BREAK: u32 = 0x003A_003A;

/// R-type opcode (used for register-register operations)
pub const OP_RTYPE: u32 = 0x3A;

/// R-type OPX field values
pub const OPX_ADD: u32 = 0x31;
pub const OPX_SUB: u32 = 0x39;
pub const OPX_AND: u32 = 0x0E;
pub const OPX_OR: u32 = 0x16;
pub const OPX_XOR: u32 = 0x1E;
pub const OPX_JMP_RET: u32 = 0x05;
pub const OPX_CALL: u32 = 0x1D;

/// I-type opcodes
pub const OP_ADDI: u32 = 0x04;
pub const OP_ANDI: u32 = 0x0C;
pub const OP_ORI: u32 = 0x14;
pub const OP_LDW: u32 = 0x17;
pub const OP_STW: u32 = 0x15;
pub const OP_BR: u32 = 0x06;
pub const OP_BEQ: u32 = 0x26;
pub const OP_BNE: u32 = 0x1E;
pub const OP_CALL: u32 = 0x00;

/// Score likelihood of Nios II code.
///
/// Nios II uses little-endian 32-bit instructions with a 6-bit opcode
/// field in bits 0-5.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = word & 0x3F;

        if word == NIOS2_NOP {
            score += 25; // NOP
        }
        if word == NIOS2_RET {
            score += 30; // RET
        }
        if word == NIOS2_ERET {
            score += 20; // ERET
        }
        if (word & MASK_BREAK) == PATTERN_BREAK {
            score += 10; // BREAK
        }

        if opcode == OP_RTYPE {
            let opx = (word >> 6) & 0x3F;
            match opx {
                OPX_ADD => score += 8,     // ADD
                OPX_SUB => score += 8,     // SUB
                OPX_AND => score += 6,     // AND
                OPX_OR => score += 6,      // OR
                OPX_XOR => score += 6,     // XOR
                OPX_JMP_RET => score += 10, // RET/JMP
                OPX_CALL => score += 10,   // CALL
                _ => score += 2,
            }
        }

        match opcode {
            OP_ADDI => score += 4, // ADDI
            OP_ANDI => score += 4, // ANDI
            OP_ORI => score += 4,  // ORI
            OP_LDW => score += 5,  // LDW
            OP_STW => score += 5,  // STW
            OP_BR => score += 5,   // BR
            OP_BEQ => score += 5,  // BEQ
            OP_BNE => score += 5,  // BNE
            OP_CALL => score += 8, // CALL
            _ => {}
        }

        if word == 0x0000_0000 || word == 0xFFFF_FFFF {
            score -= 5;
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nios2_nop() {
        let code = NIOS2_NOP.to_le_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_nios2_ret() {
        let code = NIOS2_RET.to_le_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_nios2_sequence() {
        // NOP + RET
        let mut code = Vec::new();
        code.extend_from_slice(&NIOS2_NOP.to_le_bytes());
        code.extend_from_slice(&NIOS2_RET.to_le_bytes());
        assert!(score(&code) >= 55); // 25 + 30
    }
}
