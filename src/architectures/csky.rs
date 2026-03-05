//! Heuristic scoring for C-SKY firmware blobs.

use std::cmp;

/// Score raw data as C-SKY code.
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 32 {
        return 0;
    }

    let mut score: i64 = 0;
    let mut i = 0usize;

    let mut ret_like = 0u32;
    let mut pair_hits = 0u32;
    let mut signature_hits = 0u32;
    let mut word_signature_hits = 0u32;
    let mut valid_halfwords = 0u32;

    let mut prev_hw = 0u16;
    let mut have_prev = false;

    let mut j = 0usize;
    while j + 3 < data.len() {
        let w = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
        match w {
            // Strong 32-bit motifs seen repeatedly in C-SKY firmware payloads.
            0x783C_3000 | 0x6C03_6C03 | 0xE000_14D0 | 0xE000_0C04 => {
                score += 24;
                word_signature_hits += 1;
            }
            _ => {}
        }
        j += 4;
    }

    while i + 1 < data.len() {
        let hw = u16::from_le_bytes([data[i], data[i + 1]]);

        if hw == 0x0000 {
            i += 2;
            continue;
        }

        if hw == 0xFFFF {
            i += 2;
            continue;
        }

        match hw {
            0x783C => {
                score += 14;
                ret_like += 1;
                signature_hits += 1;
            }
            0x871C | 0x8707 | 0x071C | 0xA707 | 0x0760 | 0x1266 | 0x1280 | 0x6C13 => {
                score += 7;
                signature_hits += 1;
            }
            0x6C03 | 0xE3FF | 0xE000 | 0x1490 | 0x14D0 | 0xE280 => {
                score += 2;
                signature_hits += 1;
            }
            _ => {
                // Dense low-byte control-transfer/ALU-style halfwords are common in C-SKY
                // firmware but weak on their own, so keep this signal small.
                let lo = hw & 0x00FF;
                if matches!(lo, 0x07 | 0x1C | 0x12 | 0x90) {
                    score += 1;
                }
            }
        }

        if have_prev && prev_hw == 0x071C && hw == 0x8707 {
            pair_hits += 1;
            score += 6;
        }

        prev_hw = hw;
        have_prev = true;
        valid_halfwords += 1;
        i += 2;
    }

    if ret_like >= 2 {
        score += (ret_like as i64) * 7;
    }
    if pair_hits >= 2 {
        score += (pair_hits as i64) * 9;
    }
    if word_signature_hits >= 8 {
        score += (word_signature_hits as i64) * 8;
    }

    if data.len() > 4096 {
        if signature_hits < 16 && word_signature_hits < 6 {
            return 0;
        }
        if ret_like == 0 && pair_hits < 3 && signature_hits < 128 && word_signature_hits < 24 {
            return 0;
        }
    } else if data.len() > 1024 {
        if signature_hits < 8 && word_signature_hits < 4 {
            return 0;
        }
    }

    if valid_halfwords > 0 {
        let density = signature_hits as f64 / valid_halfwords as f64;
        if density < 0.001 && data.len() > 2048 && signature_hits < 1024 && word_signature_hits < 64
        {
            return 0;
        }
    }

    if signature_hits >= 1024 && ret_like >= 64 {
        score += (signature_hits as i64) * 2;
    }
    if word_signature_hits >= 64 {
        score += word_signature_hits as i64;
    }

    cmp::max(0, score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csky_signature_stream_scores() {
        let unit = [
            0x1C, 0x07, 0x07, 0x87, // 0x071C, 0x8707 pair
            0x3C, 0x78, // 0x783C ret-like
            0x66, 0x12, 0x80, 0x12, // 0x1266, 0x1280
            0x07, 0xA7, 0x60, 0x07, // 0xA707, 0x0760
            0x1C, 0x87, 0x3C, 0x78, // 0x871C, 0x783C
        ];

        let mut code = Vec::new();
        for _ in 0..64 {
            code.extend_from_slice(&unit);
        }

        assert!(score(&code) > 0);
    }
}
