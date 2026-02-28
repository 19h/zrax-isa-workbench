//! Heuristic scoring for Infineon TriCore architecture.
//!
//! TriCore instructions are either 16 or 32 bits long.
//! The LSB of the first 16-bit word determines the length:
//! - LSB == 0: 16-bit instruction
//! - LSB == 1: 32-bit instruction
//!
//! Instructions are little-endian.

use std::cmp;

/// Score raw data as TriCore code.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    if data.len() < 4 {
        return 0;
    }

    let mut i = 0;
    let mut zero_run = 0;

    while i < data.len() - 1 {
        // Read the first 16-bit word
        let insn_lo = u16::from_le_bytes([data[i], data[i + 1]]);

        let is_32bit = (insn_lo & 1) == 1;
        let major_op = (insn_lo & 0xFF) as u8;

        if is_32bit {
            if i + 3 >= data.len() {
                break;
            }
            let insn_hi = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            let insn = ((insn_hi as u32) << 16) | (insn_lo as u32);

            // Score 32-bit instruction
            score += score_32bit(insn);

            if insn == 0 {
                zero_run += 1;
                if zero_run > 3 {
                    score -= 5;
                }
            } else {
                zero_run = 0;
            }

            i += 4;
        } else {
            // Score 16-bit instruction
            score += score_16bit(insn_lo);

            if insn_lo == 0 {
                zero_run += 1;
                if zero_run > 3 {
                    score -= 5;
                }
            } else {
                zero_run = 0;
            }

            i += 2;
        }
    }

    cmp::max(0, score)
}

fn score_16bit(insn: u16) -> i64 {
    let mut score = 0;
    let major_op = (insn & 0xFF) as u8;

    // Penalize invalid major opcodes (bit 0 must be 0)
    if (major_op & 1) != 0 {
        return -10;
    }

    // NOP (16-bit): 0x0000
    if insn == 0x0000 {
        return 5;
    }

    // RET (16-bit): 0x9000
    if insn == 0x9000 {
        return 20; // High confidence for 16-bit RET
    }

    // RFE (16-bit): 0x8000
    if insn == 0x8000 {
        return 10;
    }

    // Typical 16-bit instruction scoring based on valid major opcodes
    match major_op {
        0x00 => score += 2, // OPCM_16_SR_SYSTEM
        0x32 => score += 2, // OPCM_16_SR_ACCU
        0x5c => score += 5, // OPC1_16_SB_CALL
        0x3c => score += 2, // OPC1_16_SB_J
        0x16 | 0x26 | 0xe0 | 0x8a | 0xca | 0xaa | 0x2a | 0xea | 0x6a | 0xba | 0x3a => score += 2,
        0xc2 | 0x92 | 0x9a | 0x42 | 0x12 | 0x1a | 0xb0 | 0x30 | 0x22 | 0x10 => score += 2, // ADD variations
        0x6e | 0xee | 0x76 | 0xf6 => score += 2, // JZ/JNZ variations
        0xd8 | 0xd4 => score += 2,               // LD.A variations
        _ => score -= 2,                         // Unknown major opcode
    }

    score
}

fn score_32bit(insn: u32) -> i64 {
    let mut score = 0;
    let major_op = (insn & 0xFF) as u8;

    // Penalize invalid major opcodes (bit 0 must be 1)
    if (major_op & 1) == 0 {
        return -10;
    }

    // SYS format: OPCM_32_SYS_INTERRUPTS = 0x0d
    if major_op == 0x0d {
        score += 3;
        let op2 = (insn >> 22) & 0x3F; // bits 22..27
        match op2 {
            0x00 => score += 5,  // NOP
            0x06 => score += 20, // RET (32-bit)
            0x07 => score += 10, // RFE
            0x08 => score += 20, // SVLCX (Context save)
            0x09 => score += 20, // RSLCX (Context restore)
            0x03 => score += 10, // FRET
            0x0c | 0x0d | 0x0e | 0x0f | 0x12 | 0x13 | 0x14 | 0x15 => score += 5,
            _ => score -= 5,
        }
    } else {
        // Valid 32-bit major opcodes
        match major_op {
            0x6d => score += 5, // CALL
            0xed => score += 5, // CALLA
            0x61 => score += 2, // FCALL
            0xe1 => score += 2, // FCALLA
            0x1d => score += 2, // J
            0x9d => score += 2, // JA
            0x5d => score += 2, // JL
            0xdd => score += 2, // JLA
            // Load/Store variations
            0x85 | 0x05 | 0xe5 | 0x15 | 0xa5 | 0x25 | 0x65 | 0x45 | 0xc5 | 0xd5 => score += 2,
            0x89 | 0xa9 | 0x09 | 0x29 | 0x49 | 0x69 => score += 2,
            0x99 | 0x19 | 0xd9 | 0x59 | 0xb5 | 0x79 | 0x39 | 0xc9 | 0xb9 | 0xe9 | 0xf9 => {
                score += 2
            }
            // ALU variations
            0x47 | 0x87 | 0x67 | 0x07 | 0xc7 | 0x27 | 0xa7 => score += 2,
            0xdf => score += 2,
            0x0b => score += 2,
            _ => score -= 2, // Unrecognized major opcode
        }
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tricore_nop_ret() {
        let code = [
            0x00, 0x00, // NOP 16-bit
            0x00, 0x90, // RET 16-bit
            0x0d, 0x00, 0x00, 0x00, // NOP 32-bit (major 0x0d, op2 = 0)
            0x0d, 0x00, 0x80, 0x01, // RET 32-bit (major 0x0d, op2 = 0x06 in bits 22-27)
        ];

        // 0x0180000d: major=0x0d. >> 22 = 0x06. Yes, bits 22-27.
        // Let's verify bits 22-27 of 0x0180000d.
        // 0x0180000d = 0b0000_0001_1000_0000_0000_0000_0000_1101
        // bit 22 is 1. Wait!
        // bit 22: 0x00400000 is bit 22.
        // 0x01800000 is 1_1000_0000_0000_0000_0000_0000.
        // So bit 23 and 24 are 1.
        // Let's check: 0x06 = 0b110. 0x06 << 22 = 0b110 << 22 = 0x0180_0000.
        // Wait, 0x0180_0000 in little endian is 0x00 0x00 0x80 0x01.
        // Bytes: data[0]=0x0d, data[1]=0x00, data[2]=0x80, data[3]=0x01.
        assert!(score(&code) > 0);
    }
}
