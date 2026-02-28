//! Heuristic scoring for NXP/Freescale S12Z architecture.
//!
//! S12Z is a big-endian CISC architecture that evolved from HCS12.
//! It features a 24-bit linear address space and variable-length instructions
//! without the paging overhead of HCS12X.
//!
//! Instruction encoding is completely different from HC12/HCS12X.
//! Key distinctive opcodes (1-byte page 1):
//! - `0x01` : NOP
//! - `0x05` : RTS (Return from subroutine)
//! - `0x00` : BGND
//! - `0x20` : BRA (Branch)
//! - `0x21` : BSR (Branch to subroutine)
//! - `0x22`-`0x2F` : Conditional branches (BHI, BLS, BCC, BCS, BNE, BEQ, etc.)
//! - `0x90` : RTI (Return from interrupt)
//! - `0x1C`-`0x1F` : MOV instructions
//! - Many TRAP instructions: `0x92..=0x9F`, `0xA8..=0xAF`, `0xB8..=0xFF`

use std::cmp;

/// Score raw data as S12Z code.
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 16 {
        return 0;
    }

    let mut score: i64 = 0;
    let mut i = 0;

    let mut rts_count = 0;
    let mut nop_count = 0;
    let mut branch_count = 0;
    let mut invalid_count = 0;
    let mut valid_insn = 0;

    while i < data.len() {
        let opcode = data[i];

        if opcode == 0x00 || opcode == 0xFF {
            // Padding or BGND
            i += 1;
            continue;
        }

        match opcode {
            0x01 => {
                // NOP
                score += 3;
                nop_count += 1;
                valid_insn += 1;
                i += 1;
            }
            0x05 => {
                // RTS
                score += 15;
                rts_count += 1;
                valid_insn += 1;
                i += 1;
            }
            0x90 => {
                // RTI
                score += 10;
                valid_insn += 1;
                i += 1;
            }
            0x20..=0x2F => {
                // BRA, BSR, and conditional branches
                // Typical length depends on following byte but we'll approximate
                score += 5;
                branch_count += 1;
                valid_insn += 1;
                i += 2; // conservative skip
            }
            0x1C..=0x1F => {
                // MOV
                score += 2;
                valid_insn += 1;
                i += 2;
            }
            0x92..=0x9F | 0xA8..=0xAF | 0xB8..=0xFF => {
                // TRAP - Unlikely to see many of these in normal execution flow
                invalid_count += 1;
                score -= 2;
                i += 1;
            }
            _ => {
                // Unknown/unhandled
                score -= 1;
                i += 1;
            }
        }
    }

    if valid_insn > 10 {
        if rts_count > 0 {
            score += (rts_count as i64) * 5;
        }
        if branch_count > 5 {
            score += (branch_count as i64) * 2;
        }

        let valid_ratio = valid_insn as f64 / (valid_insn + invalid_count) as f64;
        if valid_ratio > 0.5 {
            score += valid_insn as i64;
        }
    }

    if data.len() > 4096 && rts_count == 0 { return 0; }
    cmp::max(0, score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s12z_scoring() {
        let code = [
            0x01, // NOP
            0x01, // NOP
            0x20, 0x05, // BRA +5
            0x05, // RTS
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(score(&code) > 0);
    }
}
