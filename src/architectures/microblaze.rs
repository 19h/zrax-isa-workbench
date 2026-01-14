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

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        if word == MICROBLAZE_NOP {
            score += 25; // NOP
        }
        if word == MICROBLAZE_RTSD_R15_8 {
            score += 30; // RTSD r15,8
        }
        if (word & MASK_RTSD) == PATTERN_RTSD {
            score += 20; // RTSD with other offsets
        }
        if (word & MASK_RTID) == PATTERN_RTID {
            score += 15; // RTID
        }
        if opcode == OP_BRI || opcode == OP_BRAI {
            score += 8; // BRI/BRAI
        }
        if opcode == OP_BRI && (word & MASK_BRLID) != 0 {
            score += 10; // BRLID/BRALD
        }
        if opcode == OP_ADD || opcode == OP_RSUB || opcode == OP_ADDC {
            score += 3; // ADD/RSUB/ADDC
        }
        if opcode == OP_ADDI || opcode == OP_RSUBI {
            score += 3; // ADDI/RSUBI
        }
        if opcode == OP_AND || opcode == OP_OR || opcode == OP_XOR {
            score += 3; // AND/OR/XOR
        }
        if opcode == OP_LW || opcode == OP_SW {
            score += 4; // LW/SW
        }
        if opcode == OP_LWI || opcode == OP_SWI {
            score += 4; // LWI/SWI
        }
        if opcode == OP_IMM {
            score += 5; // IMM
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
