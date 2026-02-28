//! Heuristic scoring for Fujitsu FR30 architecture.
//!
//! 16-bit big-endian architecture.
//! Key distinctive opcodes:
//! - `0x9FA0`: NOP
//! - `0x9720`: RET
//! - `0x9730`: RETI
//! - `0x8B00`..`0x8BFF`: MOV Rj, Ri

use std::cmp;

/// Score raw data as FR30 code.
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
            0x9FA0 => {
                // NOP
                score += 10;
                valid_insn += 1;
                i += 2;
                continue;
            }
            0x9720 => {
                // RET
                score += 20;
                ret_count += 1;
                valid_insn += 1;
                i += 2;
                continue;
            }
            0x9730 => {
                // RETI
                score += 15;
                ret_count += 1;
                valid_insn += 1;
                i += 2;
                continue;
            }
            0x8B00..=0x8BFF => {
                // MOV Rj, Ri
                score += 5;
                valid_insn += 1;
                i += 2;
                continue;
            }
            0x9F80..=0x9F8F => {
                // LDI:32 $i32, Ri
                if i + 5 < data.len() {
                    score += 5;
                    valid_insn += 1;
                    i += 6;
                    continue;
                }
            }
            0x9B00..=0x9B0F => {
                // LDI:20 $i20, Ri
                if i + 3 < data.len() {
                    score += 5;
                    valid_insn += 1;
                    i += 4;
                    continue;
                }
            }
            0xC000..=0xCFFF => {
                // LDI:8 $i8, Ri
                score += 4;
                valid_insn += 1;
                i += 2;
                continue;
            }
            _ => {
                // Just step to next word
                i += 2;
            }
        }
    }

    if ret_count > 0 {
        score += (ret_count as i64) * 10;
    }

    if valid_insn > 10 {
        score += (valid_insn as i64) * 2;
    }

    if data.len() > 4096 && ret_count == 0 { return 0; }
    cmp::max(0, score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr30_scoring() {
        let code = [
            0x9F, 0xA0, // NOP
            0xC0, 0x12, // LDI:8
            0x97, 0x20, // RET
        ];
        assert!(score(&code) > 0);
    }
}
