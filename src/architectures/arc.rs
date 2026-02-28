//! ARC (Argonaut RISC Core) architecture support.
//!
//! ARC is a configurable RISC processor family by Synopsys.
//! It uses little-endian instructions with 16 or 32-bit lengths.

/// 16-bit NOP_S instruction
pub const ARC_NOP_S: u16 = 0x78E0;

/// J_S [blink] - return from subroutine (16-bit)
pub const ARC_RET_S: u16 = 0x7EE0;

/// J_S.D [blink] - return with delay slot (16-bit)
pub const ARC_RET_D_S: u16 = 0x7FE0;

/// POP_S blink - pop return address (16-bit)
pub const ARC_POP_BLINK: u16 = 0xC0D1;

/// PUSH_S blink - push return address (16-bit)
pub const ARC_PUSH_BLINK: u16 = 0xC0F1;

/// Mask/pattern for MOV_S detection
pub const MASK_MOV_S: u16 = 0xF8E0;
pub const PATTERN_MOV_S: u16 = 0x7000;

/// Mask/pattern for ADD_S/SUB_S detection
pub const MASK_ADD_SUB_S: u16 = 0xF800;
pub const PATTERN_ADD_SUB_S: u16 = 0x6000;

/// 32-bit NOP variations
pub const ARC_NOP_32_LE: u32 = 0x264A_7000;
pub const ARC_NOP_32_BE: u32 = 0x7000_264A;

/// Major opcode boundary between 16-bit and 32-bit instructions
pub const MAJOR_16BIT_START: u16 = 0x0C;
pub const MAJOR_16BIT_END: u16 = 0x1F;

/// Score likelihood of ARC code.
///
/// ARC uses little-endian instructions with variable length.
/// 16-bit instructions have major opcode 0x0C-0x1F.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut i = 0;
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;

    while i < data.len() {
        if i + 2 > data.len() {
            break;
        }

        let half = u16::from_le_bytes([data[i], data[i + 1]]);
        let major = (half >> 11) & 0x1F;

        // --- 16-bit cross-architecture penalties ---
        // Thumb
        if half == 0x4770 {
            score -= 15;
            i += 2;
            continue;
        } // BX LR
        if half == 0xBF00 {
            score -= 10;
            i += 2;
            continue;
        } // NOP
        if matches!(half, 0xB672 | 0xB662 | 0xB673 | 0xB663) {
            score -= 12;
            i += 2;
            continue;
        } // CPSID/CPSIE
        if (half & 0xFF00) == 0xB500 {
            score -= 8;
            i += 2;
            continue;
        } // PUSH {.., LR}
        if (half & 0xFF00) == 0xBD00 {
            score -= 8;
            i += 2;
            continue;
        } // POP {.., PC}
          // AVR
        if half == 0x9508 {
            score -= 12;
            i += 2;
            continue;
        } // RET
        if half == 0x9518 {
            score -= 10;
            i += 2;
            continue;
        } // RETI
          // MSP430
        if half == 0x4130 {
            score -= 12;
            i += 2;
            continue;
        } // RET
        if half == 0x4303 {
            score -= 8;
            i += 2;
            continue;
        } // NOP

        if major >= MAJOR_16BIT_START && major <= MAJOR_16BIT_END {
            // 16-bit instruction
            if half == ARC_NOP_S {
                score += 20;
            } else if half == ARC_RET_S {
                score += 25;
                ret_count += 1;
            } else if half == ARC_RET_D_S {
                score += 25;
                ret_count += 1;
            } else if half == ARC_POP_BLINK {
                score += 15;
                ret_count += 1;
            } else if half == ARC_PUSH_BLINK {
                score += 15;
                call_count += 1;
            } else if (half & MASK_MOV_S) == PATTERN_MOV_S {
                score += 3;
            } else if (half & MASK_ADD_SUB_S) == PATTERN_ADD_SUB_S {
                score += 3;
            } else {
                score -= 1; // Unrecognized 16-bit
            }
            i += 2;
        } else {
            // 32-bit instruction
            if i + 4 > data.len() {
                break;
            }

            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

            // --- 32-bit cross-architecture penalties ---
            // AArch64
            if word == 0xD65F03C0 {
                score -= 15;
                i += 4;
                continue;
            } // RET
            if word == 0xD503201F {
                score -= 10;
                i += 4;
                continue;
            } // NOP
            if (word >> 26) == 0x25 {
                score -= 5;
            } // BL
              // RISC-V
            if word == 0x00008067 {
                score -= 12;
                i += 4;
                continue;
            } // RET
            if word == 0x00000013 {
                score -= 8;
                i += 4;
                continue;
            } // NOP
              // Thumb-2
            {
                let hw_low = (word & 0xFFFF) as u16;
                let hw_high = (word >> 16) as u16;
                if hw_low == 0xE92D {
                    score -= 10;
                    i += 4;
                    continue;
                } // PUSH.W
                if hw_low == 0xE8BD {
                    score -= 10;
                    i += 4;
                    continue;
                } // POP.W
                if (hw_low & 0xF800) == 0xF000 && (hw_high & 0xD000) == 0xD000 {
                    score -= 8;
                    i += 4;
                    continue; // BL
                }
            }
            // ARM32
            if word == 0xE12FFF1E {
                score -= 15;
                i += 4;
                continue;
            } // BX LR
            if word == 0xE1A00000 {
                score -= 12;
                i += 4;
                continue;
            } // NOP

            if word == ARC_NOP_32_LE || word == ARC_NOP_32_BE {
                score += 20;
            } else {
                let major32 = (word >> 27) & 0x1F;
                match major32 {
                    0x04 | 0x05 => score += 3,
                    0x01 | 0x00 => {
                        score += 4;
                        branch_count += 1;
                    }
                    0x02 | 0x03 => score += 3,
                    _ => {
                        score -= 1;
                    } // Unrecognized 32-bit
                }
            }

            if word == 0x0000_0000 || word == 0xFFFF_FFFF {
                score -= 5;
            }

            i += 4;
        }
    }

    // Structural requirement
    let num_halfwords = data.len() / 2;
    if num_halfwords > 40 {
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
    fn test_arc_nop_s() {
        let code = ARC_NOP_S.to_le_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_arc_ret_s() {
        let code = ARC_RET_S.to_le_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_arc_sequence() {
        // NOP_S + RET_S
        let mut code = Vec::new();
        code.extend_from_slice(&ARC_NOP_S.to_le_bytes());
        code.extend_from_slice(&ARC_RET_S.to_le_bytes());
        assert!(score(&code) >= 45); // 20 + 25
    }
}
