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
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        if word == 0x0000_0000 || word == 0xFFFF_FFFF {
            score -= 5;
            continue;
        }

        // --- Cross-architecture penalties (BE ISAs) ---
        // PPC
        if word == 0x60000000 {
            score -= 12;
            continue;
        } // NOP
        if word == 0x4E800020 {
            score -= 15;
            continue;
        } // BLR
        if (word >> 26) == 18 {
            score -= 5;
        } // B/BL
          // SPARC
        if word == 0x01000000 {
            score -= 10;
            continue;
        } // NOP
        if word == 0x81C7E008 {
            score -= 15;
            continue;
        } // RET
          // MIPS BE
        if word == 0x03E00008 {
            score -= 12;
            continue;
        } // JR $ra
          // S390x
        if (word >> 16) == 0x07FE {
            score -= 12;
            continue;
        } // BR %r14

        // Exact matches
        if word == PARISC_NOP {
            score += 25;
            continue;
        }
        if word == PARISC_RET_NULLIFY {
            score += 30;
            ret_count += 1;
            continue;
        }
        if word == PARISC_RET {
            score += 25;
            ret_count += 1;
            continue;
        }

        // Opcode-based scoring
        let mut matched = true;
        match opcode {
            _ if (word & MASK_BE_L) == PATTERN_BE_L => {
                score += 10;
                branch_count += 1;
            }
            OP_BL => {
                score += 10;
                call_count += 1;
            }
            OP_LDW | OP_STW => score += 3,
            OP_LDWM | OP_STWM => score += 4,
            OP_ALU => score += 3,
            OP_COMIB | OP_COMB => {
                score += 5;
                branch_count += 1;
            }
            OP_ADDI | OP_SUBI => score += 3,
            _ => {
                matched = false;
            }
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
