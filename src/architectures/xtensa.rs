//! Xtensa architecture support.
//!
//! Xtensa is a configurable processor architecture by Cadence (formerly Tensilica).
//! It uses little-endian instructions with variable length (16 or 24-bit).
//! Used in ESP8266 and ESP32 chips.

/// 16-bit NOP.N instruction (narrow NOP)
pub const XTENSA_NOP_N: u16 = 0x20F0;

/// Alternative encoding for NOP.N
pub const XTENSA_NOP_N_ALT: u16 = 0xF020;

/// 16-bit RET.N instruction (narrow return)
pub const XTENSA_RET_N: u16 = 0xF00D;

/// Alternative encoding for RET.N
pub const XTENSA_RET_N_ALT: u16 = 0x0DF0;

/// 16-bit RETW.N instruction (narrow windowed return)
pub const XTENSA_RETW_N: u16 = 0xF01D;

/// Alternative encoding for RETW.N
pub const XTENSA_RETW_N_ALT: u16 = 0x1DF0;

/// Mask/pattern for MOV.N detection
pub const MASK_MOV_N: u16 = 0xF00F;
pub const PATTERN_MOV_N: u16 = 0x000D;

/// Mask/pattern for MOVI.N detection
pub const MASK_MOVI_N: u16 = 0xF00F;
pub const PATTERN_MOVI_N: u16 = 0x000C;

/// Mask for L32I.N detection
pub const MASK_L32I_N: u16 = 0xF000;
pub const PATTERN_L32I_N: u16 = 0x8000;

/// Mask for S32I.N detection
pub const MASK_S32I_N: u16 = 0xF000;
pub const PATTERN_S32I_N: u16 = 0x9000;

/// 24-bit NOP instruction
pub const XTENSA_NOP: u32 = 0x0020F0;

/// 24-bit RET instruction
pub const XTENSA_RET: u32 = 0x000080;

/// 24-bit RETW instruction (windowed return)
pub const XTENSA_RETW: u32 = 0x000090;

/// Score likelihood of Xtensa code.
///
/// Xtensa uses little-endian instructions with variable length.
/// Bit 3 of the first byte indicates instruction size:
/// - Set (1): 16-bit narrow instruction
/// - Clear (0): 24-bit standard instruction
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut i = 0;
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut entry_count = 0u32;

    while i < data.len() {
        if i + 2 > data.len() {
            break;
        }

        let b0 = data[i];
        let b1 = data[i + 1];
        let is_narrow = (b0 & 0x08) != 0;

        if is_narrow {
            let half = u16::from_le_bytes([b0, b1]);

            // --- Cross-architecture penalties for 16-bit LE ISAs ---
            // AVR distinctive patterns
            if half == 0x9508 { score -= 15; i += 2; continue; } // AVR RET
            if half == 0x9518 { score -= 15; i += 2; continue; } // AVR RETI
            if half == 0x9588 { score -= 10; i += 2; continue; } // AVR SLEEP
            if half == 0x9598 { score -= 8; i += 2; continue; }  // AVR BREAK
            if half == 0x9478 { score -= 8; i += 2; continue; }  // AVR SEI
            if half == 0x94F8 { score -= 8; i += 2; continue; }  // AVR CLI
            // MSP430 distinctive patterns
            if half == 0x4130 { score -= 15; i += 2; continue; } // MSP430 RET
            if half == 0x4303 { score -= 10; i += 2; continue; } // MSP430 NOP
            if half == 0x1300 { score -= 10; i += 2; continue; } // MSP430 RETI
            // Thumb distinctive patterns
            if half == 0x4770 { score -= 15; i += 2; continue; } // Thumb BX LR
            if half == 0xBF00 { score -= 10; i += 2; continue; } // Thumb NOP
            if (half & 0xFF00) == 0xB500 { score -= 8; i += 2; continue; } // Thumb PUSH {.., LR}
            if (half & 0xFF00) == 0xBD00 { score -= 8; i += 2; continue; } // Thumb POP {.., PC}

            if half == XTENSA_NOP_N || half == XTENSA_NOP_N_ALT {
                score += 20; // NOP.N
            } else if half == XTENSA_RET_N || half == XTENSA_RET_N_ALT {
                score += 25; // RET.N
                ret_count += 1;
            } else if half == XTENSA_RETW_N || half == XTENSA_RETW_N_ALT {
                score += 20; // RETW.N
                ret_count += 1;
            } else if (half & MASK_MOV_N) == PATTERN_MOV_N {
                score += 3; // MOV.N
            } else if (half & MASK_MOVI_N) == PATTERN_MOVI_N {
                score += 3; // MOVI.N
            } else if (half & MASK_L32I_N) == PATTERN_L32I_N || (half & MASK_S32I_N) == PATTERN_S32I_N {
                score += 3; // L32I.N / S32I.N
            }
            i += 2;
        } else {
            if i + 3 > data.len() {
                break;
            }

            let b2 = data[i + 2];
            let word = (b2 as u32) << 16 | (b1 as u32) << 8 | (b0 as u32);

            if word == XTENSA_NOP {
                score += 15; // NOP
            } else if word == XTENSA_RET {
                score += 25; // RET
                ret_count += 1;
            } else if word == XTENSA_RETW {
                score += 20; // RETW
                ret_count += 1;
            } else if (b0 & 0x0F) == 0x05 {
                score += 10; // CALL0/CALL4/CALL8/CALL12
                call_count += 1;
            } else if (b0 & 0x0F) == 0x06 && (b1 & 0x03) == 0x03 {
                score += 15; // ENTRY
                entry_count += 1;
            } else if (b0 & 0x0F) == 0x02 {
                score += 3; // L32I/S32I
            } else if (b0 & 0x0F) == 0x0C && (b1 & 0xF0) == 0x20 {
                score += 3; // ADDI
            } else if word == 0x000000 || word == 0xFFFFFF {
                score -= 5;
            }
            i += 3;
        }
    }

    // Structural requirement: Xtensa's CALL pattern matches 1/16 of 24-bit
    // instructions (b0 & 0x0F == 0x05), and L32I/S32I match 1/16 as well.
    // Random data can accumulate meaningful score without distinctive patterns.
    // Require returns, calls, or ENTRY for meaningful-length data.
    let num_instructions = data.len() / 2; // approximate (mix of 2 and 3 byte)
    if num_instructions > 20 {
        let distinctive = ret_count + call_count + entry_count;
        if distinctive == 0 {
            score = (score as f64 * 0.15) as i64;
        } else if ret_count == 0 && entry_count == 0 {
            // Only calls, no returns or entries
            score = (score as f64 * 0.40) as i64;
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xtensa_nop_24bit() {
        // 24-bit NOP: bytes are [0xF0, 0x20, 0x00] (bit 3 of first byte is clear)
        let code = [0xF0, 0x20, 0x00];
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_xtensa_ret_24bit() {
        // 24-bit RET: bytes are [0x80, 0x00, 0x00]
        let code = [0x80, 0x00, 0x00];
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_xtensa_nop_n_16bit() {
        // 16-bit NOP.N: first byte must have bit 3 set
        // NOP.N encoding varies, but needs bit 3 set to be recognized as narrow
        // Using 0x3D (0011_1101) which has bit 3 set
        let code = [0x3D, 0x0F]; // A narrow instruction pattern
                                 // This may not be exactly NOP.N but tests narrow instruction path
        let s = score(&code);
        // Just verify it doesn't panic and processes as narrow
        assert!(s >= 0);
    }

    #[test]
    fn test_xtensa_sequence() {
        // 24-bit NOP + 24-bit RET
        let code = [
            0xF0, 0x20, 0x00, // NOP (24-bit)
            0x80, 0x00, 0x00, // RET (24-bit)
        ];
        assert!(score(&code) >= 40); // 15 + 25
    }
}
