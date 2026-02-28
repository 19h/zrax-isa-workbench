//! Heuristic scoring for PowerPC VLE architecture.
//!
//! Big-endian 16-bit and 32-bit instructions.
//! Key opcodes:
//! - `0x0004`: se_blr (Return)
//! - `0x4400`: se_nop
//! - `0x0006`: se_bctr
//! - `0xE8xx`: se_b (8-bit displacement)
//! - `0x78xxxxxx`: e_b (24-bit displacement)
//! - `0x7Axxxxxx`: e_bl (24-bit displacement)

use std::cmp;

/// Score raw data as PPC VLE code.
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 4 {
        return 0;
    }

    let mut score: i64 = 0;
    let mut i = 0;
    let mut zero_run = 0;

    let mut ret_count = 0;
    let mut valid_insn = 0;

    while i + 1 < data.len() {
        let hw = u16::from_be_bytes([data[i], data[i + 1]]);

        if hw == 0x0000 || hw == 0xFFFF {
            zero_run += 1;
            if zero_run > 2 {
                score -= 2;
            }
            i += 2;
            continue;
        }
        zero_run = 0;

        match hw {
            0x4400 => {
                // se_nop
                score += 10;
                valid_insn += 1;
                i += 2;
                continue;
            }
            0x0004 => {
                // se_blr (return)
                score += 25;
                ret_count += 1;
                valid_insn += 1;
                i += 2;
                continue;
            }
            0x0006 => {
                // se_bctr
                score += 15;
                valid_insn += 1;
                i += 2;
                continue;
            }
            0xE800..=0xE8FF => {
                // se_b (8-bit displacement)
                score += 5;
                valid_insn += 1;
                i += 2;
                continue;
            }
            0x7800..=0x7BFF => {
                // e_b / e_bl (32-bit instruction)
                if i + 3 < data.len() {
                    let w = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                    let op = w >> 26;
                    if op == 30 {
                        score += 10;
                        valid_insn += 1;
                        i += 4;
                        continue;
                    }
                }
            }
            _ => {
                i += 2;
            }
        }
    }

    if ret_count > 0 {
        score += (ret_count as i64) * 10;
    }

    if valid_insn > 5 {
        score += (valid_insn as i64) * 3;
    }

    cmp::max(0, score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ppcvle_scoring() {
        let code = [
            0x44, 0x00, // se_nop
            0x78, 0x00, 0x00, 0x04, // e_b +4
            0x00, 0x04, // se_blr
        ];
        assert!(score(&code) > 0);
    }
}
