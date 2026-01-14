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

    while i < data.len() {
        if i + 2 > data.len() {
            break;
        }

        let half = u16::from_le_bytes([data[i], data[i + 1]]);
        let major = (half >> 11) & 0x1F;

        if major >= MAJOR_16BIT_START && major <= MAJOR_16BIT_END {
            // 16-bit instruction
            if half == ARC_NOP_S {
                score += 20; // NOP_S
            }
            if half == ARC_RET_S {
                score += 25; // J_S [blink]
            }
            if half == ARC_RET_D_S {
                score += 25; // J_S.D [blink]
            }
            if half == ARC_POP_BLINK {
                score += 15; // POP_S blink
            }
            if half == ARC_PUSH_BLINK {
                score += 15; // PUSH_S blink
            }
            if (half & MASK_MOV_S) == PATTERN_MOV_S {
                score += 3; // MOV_S
            }
            if (half & MASK_ADD_SUB_S) == PATTERN_ADD_SUB_S {
                score += 3; // ADD_S/SUB_S
            }
            i += 2;
        } else {
            // 32-bit instruction
            if i + 4 > data.len() {
                break;
            }

            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

            if word == ARC_NOP_32_LE || word == ARC_NOP_32_BE {
                score += 20; // 32-bit NOP
            }

            let major32 = (word >> 27) & 0x1F;
            match major32 {
                0x04 | 0x05 => score += 3, // General ops
                0x01 | 0x00 => score += 4, // Branch
                0x02 | 0x03 => score += 3, // Load/Store
                _ => {}
            }

            if word == 0x0000_0000 || word == 0xFFFF_FFFF {
                score -= 5;
            }

            i += 4;
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
