//! MicroBlaze architecture support.
//!
//! MicroBlaze is a soft processor core for Xilinx FPGAs.
//! It uses big-endian 32-bit fixed-width instructions.

/// NOP instruction (encoding)
pub const MICROBLAZE_NOP: u32 = 0x8000_0000;

/// RTSD r15, 8 - standard return from subroutine
pub const MICROBLAZE_RTSD_R15_8: u32 = 0xB60F_0008;

/// Mask for RTSD instruction detection
pub const MASK_RTSD: u32 = 0xFFFF_0000;
pub const PATTERN_RTSD: u32 = 0xB60F_0000;

/// Mask for RTID instruction detection
pub const MASK_RTID: u32 = 0xFFFF_0000;
pub const PATTERN_RTID: u32 = 0xB620_0000;

/// BRI/BRAI opcode - branch immediate
pub const OP_BRI: u32 = 0x2E;
pub const OP_BRAI: u32 = 0x2F;

/// Mask for BRLID/BRALD detection (branch and link)
pub const MASK_BRLID: u32 = 0x0010_0000;

/// ADD opcode
pub const OP_ADD: u32 = 0x00;
/// RSUB opcode
pub const OP_RSUB: u32 = 0x01;
/// ADDC opcode
pub const OP_ADDC: u32 = 0x02;

/// ADDI opcode
pub const OP_ADDI: u32 = 0x08;
/// RSUBI opcode
pub const OP_RSUBI: u32 = 0x09;

/// AND opcode
pub const OP_AND: u32 = 0x21;
/// OR opcode
pub const OP_OR: u32 = 0x20;
/// XOR opcode
pub const OP_XOR: u32 = 0x22;

/// LW opcode - load word
pub const OP_LW: u32 = 0x32;
/// SW opcode - store word
pub const OP_SW: u32 = 0x36;
/// LWI opcode - load word immediate
pub const OP_LWI: u32 = 0x30;
/// SWI opcode - store word immediate
pub const OP_SWI: u32 = 0x34;

/// IMM opcode - immediate prefix
pub const OP_IMM: u32 = 0x2C;

/// Score likelihood of MicroBlaze code.
///
/// MicroBlaze uses big-endian 32-bit instructions with a 6-bit opcode
/// field in bits 26-31.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

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

        if word == 0x0000_0000 || word == 0xFFFF_FFFF {
            score -= 5;
            continue;
        }

        // Exact matches
        if word == MICROBLAZE_NOP {
            score += 25;
            continue;
        }
        if word == MICROBLAZE_RTSD_R15_8 {
            score += 30;
            ret_count += 1;
            continue;
        }
        if (word & MASK_RTSD) == PATTERN_RTSD {
            score += 20;
            ret_count += 1;
            continue;
        }
        if (word & MASK_RTID) == PATTERN_RTID {
            score += 15;
            ret_count += 1;
            continue;
        }

        // Opcode-based scoring
        let mut matched = true;
        match opcode {
            OP_BRI | OP_BRAI => {
                if opcode == OP_BRI && (word & MASK_BRLID) != 0 {
                    score += 10;
                    call_count += 1;
                } else {
                    score += 8;
                    branch_count += 1;
                }
            }
            OP_ADD | OP_RSUB | OP_ADDC => score += 3,
            OP_ADDI | OP_RSUBI => score += 3,
            OP_AND | OP_OR | OP_XOR => score += 3,
            OP_LW | OP_SW => score += 4,
            OP_LWI | OP_SWI => score += 4,
            OP_IMM => score += 5,
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
    fn test_microblaze_nop() {
        let code = MICROBLAZE_NOP.to_be_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_microblaze_rtsd() {
        let code = MICROBLAZE_RTSD_R15_8.to_be_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_microblaze_sequence() {
        // NOP + RTSD
        let mut code = Vec::new();
        code.extend_from_slice(&MICROBLAZE_NOP.to_be_bytes());
        code.extend_from_slice(&MICROBLAZE_RTSD_R15_8.to_be_bytes());
        assert!(score(&code) >= 55); // 25 + 30
    }
}
