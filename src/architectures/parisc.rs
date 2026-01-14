//! PA-RISC (HP Precision Architecture) support.
//!
//! PA-RISC is a RISC architecture developed by Hewlett-Packard.
//! It uses big-endian 32-bit fixed-width instructions.

/// NOP instruction: `OR 0,0,0`
pub const PARISC_NOP: u32 = 0x0800_0240;

/// Return with nullify: `BV,N 0(%rp)`
pub const PARISC_RET_NULLIFY: u32 = 0xE840_C002;

/// Return without nullify: `BV 0(%rp)`
pub const PARISC_RET: u32 = 0xE840_C000;

/// Mask for BE,L (branch external with link) detection
pub const MASK_BE_L: u32 = 0xFC00_E000;
pub const PATTERN_BE_L: u32 = 0xE000_0000;

/// BL opcode - branch and link
pub const OP_BL: u32 = 0x3A;

/// LDW opcode - load word
pub const OP_LDW: u32 = 0x12;

/// STW opcode - store word
pub const OP_STW: u32 = 0x1A;

/// LDWM opcode - load word and modify
pub const OP_LDWM: u32 = 0x13;

/// STWM opcode - store word and modify
pub const OP_STWM: u32 = 0x1B;

/// ADD/SUB/AND/OR opcode
pub const OP_ALU: u32 = 0x02;

/// COMIB opcode - compare immediate and branch
pub const OP_COMIB: u32 = 0x21;

/// COMB opcode - compare and branch
pub const OP_COMB: u32 = 0x23;

/// ADDI opcode - add immediate
pub const OP_ADDI: u32 = 0x2D;

/// SUBI opcode - subtract immediate
pub const OP_SUBI: u32 = 0x25;

/// Score likelihood of PA-RISC code.
///
/// PA-RISC uses big-endian 32-bit instructions with a 6-bit opcode field
/// in bits 26-31.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        // NOP (OR 0,0,0)
        if word == PARISC_NOP {
            score += 25;
        }

        // BV,N 0(%rp) - common return
        if word == PARISC_RET_NULLIFY {
            score += 30;
        }

        // BV 0(%rp) - return without nullify
        if word == PARISC_RET {
            score += 25;
        }

        // BE,L - branch external with link
        if (word & MASK_BE_L) == PATTERN_BE_L {
            score += 10;
        }

        // BL - branch and link
        if opcode == OP_BL {
            score += 10;
        }

        // LDW/STW
        if opcode == OP_LDW || opcode == OP_STW {
            score += 3;
        }

        // LDWM/STWM
        if opcode == OP_LDWM || opcode == OP_STWM {
            score += 4;
        }

        // ADD/SUB/AND/OR
        if opcode == OP_ALU {
            score += 3;
        }

        // COMIB/COMB
        if opcode == OP_COMIB || opcode == OP_COMB {
            score += 5;
        }

        // ADDI/SUBI
        if opcode == OP_ADDI || opcode == OP_SUBI {
            score += 3;
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
    fn test_parisc_nop() {
        let code = PARISC_NOP.to_be_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_parisc_ret() {
        let code = PARISC_RET_NULLIFY.to_be_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_parisc_sequence() {
        // NOP + RET
        let mut code = Vec::new();
        code.extend_from_slice(&PARISC_NOP.to_be_bytes());
        code.extend_from_slice(&PARISC_RET_NULLIFY.to_be_bytes());
        assert!(score(&code) >= 55); // 25 + 30
    }
}
