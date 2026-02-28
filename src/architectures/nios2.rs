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
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;

    // --- Cross-architecture penalties ---
    // 16-bit LE ISAs (Thumb, AVR, MSP430)
    {
        let mut j = 0;
        while j + 1 < data.len() {
            let hw = u16::from_le_bytes([data[j], data[j + 1]]);
            // Thumb patterns
            if hw == 0x4770 {
                score -= 15;
            } // BX LR
            if hw == 0xBF00 {
                score -= 10;
            } // NOP
            if matches!(hw, 0xB672 | 0xB662 | 0xB673 | 0xB663) {
                score -= 12;
            } // CPSID/CPSIE
            if matches!(hw, 0xBF30 | 0xBF20 | 0xBF40) {
                score -= 10;
            } // WFI/WFE/SEV
            if (hw & 0xFF00) == 0xB500 {
                score -= 8;
            } // PUSH {.., LR}
            if (hw & 0xFF00) == 0xBD00 {
                score -= 8;
            } // POP {.., PC}
              // AVR patterns
            if hw == 0x9508 {
                score -= 12;
            } // AVR RET
            if hw == 0x9518 {
                score -= 10;
            } // AVR RETI
              // MSP430 patterns
            if hw == 0x4130 {
                score -= 12;
            } // MSP430 RET
            if hw == 0x4303 {
                score -= 8;
            } // MSP430 NOP
            j += 2;
        }
    }

    // 32-bit cross-architecture penalties
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // AArch64 (LE)
        if word == 0xD65F03C0 {
            score -= 15;
            continue;
        } // RET
        if word == 0xD503201F {
            score -= 10;
            continue;
        } // NOP
        if (word >> 26) == 0x25 {
            score -= 5;
        } // BL
          // RISC-V (LE)
        if word == 0x00008067 {
            score -= 12;
            continue;
        } // RET
        if word == 0x00000013 {
            score -= 8;
            continue;
        } // NOP

        // Thumb-2 32-bit patterns
        {
            let hw_low = (word & 0xFFFF) as u16;
            let hw_high = (word >> 16) as u16;
            if hw_low == 0xE92D {
                score -= 10;
                continue;
            } // PUSH.W
            if hw_low == 0xE8BD {
                score -= 10;
                continue;
            } // POP.W
            if (hw_low & 0xF800) == 0xF000 && (hw_high & 0xD000) == 0xD000 {
                score -= 8; // Thumb-2 BL
                continue;
            }
        }
        // MIPS LE patterns
        if word == 0x03E00008 {
            score -= 15;
            continue;
        } // JR $ra
        if (word & 0xFFFF0000) == 0x27BD0000 {
            score -= 10;
        } // ADDIU $sp
        if (word & 0xFFFF0000) == 0xAFBF0000 {
            score -= 10;
        } // SW $ra
        if (word & 0xFFFF0000) == 0x8FBF0000 {
            score -= 10;
        } // LW $ra
          // MIPS BE patterns (read as LE)
        {
            let be32 = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            if be32 == 0x03E00008 {
                score -= 15;
            } // JR $ra
            if (be32 & 0xFFFF0000) == 0x27BD0000 {
                score -= 10;
            } // ADDIU $sp
            if (be32 & 0xFFFF0000) == 0xAFBF0000 {
                score -= 10;
            } // SW $ra
        }
        // PPC BLR (BE 0x4E800020)
        {
            let be32 = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            if be32 == 0x4E800020 {
                score -= 12;
            }
            if be32 == 0x60000000 {
                score -= 8;
            } // PPC NOP
        }
        // LoongArch
        if word == 0x4C000020 {
            score -= 10;
        } // RET
        if word == 0x03400000 {
            score -= 8;
        } // NOP

        // --- Nios II instruction scoring ---
        let opcode = word & 0x3F;

        // Exact matches (high confidence)
        if word == NIOS2_NOP {
            score += 25;
            continue;
        }
        if word == NIOS2_RET {
            score += 30;
            ret_count += 1;
            continue;
        }
        if word == NIOS2_ERET {
            score += 20;
            ret_count += 1;
            continue;
        }
        if (word & MASK_BREAK) == PATTERN_BREAK {
            score += 10;
            continue;
        }

        // R-type instructions (opcode 0x3A = 1/64 of space)
        if opcode == OP_RTYPE {
            let opx = (word >> 6) & 0x3F;
            match opx {
                OPX_ADD | OPX_SUB => score += 5,
                OPX_AND | OPX_OR | OPX_XOR => score += 4,
                OPX_JMP_RET => {
                    score += 8;
                    ret_count += 1;
                }
                OPX_CALL => {
                    score += 8;
                    call_count += 1;
                }
                _ => score += 1,
            }
            continue;
        }

        // I-type instructions
        let mut matched = true;
        match opcode {
            OP_ADDI => score += 3,
            OP_ANDI => score += 3,
            OP_ORI => score += 3,
            OP_LDW => score += 4,
            OP_STW => score += 4,
            OP_BR => {
                score += 4;
                branch_count += 1;
            }
            OP_BEQ => {
                score += 4;
                branch_count += 1;
            }
            OP_BNE => {
                score += 4;
                branch_count += 1;
            }
            OP_CALL => {
                // CALL target is bits 31:6 — require non-zero target
                // (word 0x00000000 is not a real CALL)
                if (word >> 6) != 0 {
                    score += 5;
                    call_count += 1;
                }
            }
            _ => {
                matched = false;
            }
        }

        // Penalty for unrecognized instructions
        if !matched {
            score -= 1;
        }

        // Padding penalty
        if word == 0x0000_0000 || word == 0xFFFF_FFFF {
            score -= 5;
        }
    }

    // Structural requirement: Nios II opcode field is only 6 bits,
    // so each opcode matches 1/64 of random data. Without distinctive
    // patterns (returns, calls), the score likely comes from random matches.
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
