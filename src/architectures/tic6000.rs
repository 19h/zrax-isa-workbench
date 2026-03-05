//! Heuristic scoring for TI TMS320C6000 (C6x) DSP binaries.

use std::cmp;

/// Score raw data as TI C6000 code.
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 64 {
        return 0;
    }

    let mut score: i64 = 0;
    let mut i = 0usize;

    let mut strong_hits = 0u32;
    let mut opcode_hits = 0u32;
    let mut non_padding_words = 0u32;
    let mut distinct_strong = std::collections::HashSet::new();

    while i + 3 < data.len() {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        if w == 0 || w == 0xFFFF_FFFF {
            i += 4;
            continue;
        }
        non_padding_words += 1;

        match w {
            // High-signal words observed repeatedly in C6x firmware/code sections.
            0x0000_6000 | 0x1182_4100 | 0x008C_A362 | 0x007C_0362 | 0x0208_C168 | 0x0F88_C16A
            | 0x01BC_52E6 | 0xE100_0080 | 0xE080_0020 | 0x0C6E_0C6E => {
                score += 150;
                strong_hits += 1;
                distinct_strong.insert(w);
            }
            _ => {
                // Broad C6x opcode envelope: many instructions in observed corpora
                // have high byte in 0xE0..=0xEF and a mostly non-zero middle field.
                let hi = (w >> 24) as u8;
                if (0xE0..=0xEF).contains(&hi) && ((w >> 8) & 0x00FF_FF) != 0 {
                    score += 3;
                    opcode_hits += 1;
                }
            }
        }

        i += 4;
    }

    if strong_hits >= 6 {
        score += (strong_hits as i64) * 24;
    }
    if opcode_hits >= 24 {
        score += (opcode_hits as i64) / 6;
    }

    if data.len() > 4096 {
        if strong_hits < 8 || distinct_strong.len() < 4 {
            return 0;
        }
    } else if strong_hits < 3 {
        return 0;
    }

    if non_padding_words > 0 {
        let strong_density = strong_hits as f64 / non_padding_words as f64;
        if strong_density < 0.01 && data.len() > 4096 {
            return 0;
        }
    }

    cmp::max(0, score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tic6000_signature_stream_scores() {
        let mut code = Vec::new();
        let words: [u32; 10] = [
            0x0000_6000,
            0x1182_4100,
            0x008C_A362,
            0x007C_0362,
            0x0208_C168,
            0x0F88_C16A,
            0x01BC_52E6,
            0xE080_0020,
            0x0C6E_0C6E,
            0xE100_0080,
        ];
        for _ in 0..3 {
            for w in words {
                code.extend_from_slice(&w.to_le_bytes());
            }
        }

        assert!(score(&code) > 0);
    }
}
