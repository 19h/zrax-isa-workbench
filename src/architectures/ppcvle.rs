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

    // Structural evidence: for non-trivial data, require at least one return
    if data.len() > 512 && ret_count == 0 {
        score = score / 4;
    }

    // Cross-architecture penalty: s390x
    // Both PPC VLE and s390x are big-endian with variable-length (2/4/6 byte)
    // instructions. s390x 2-byte opcodes like BCR (0x07xx) can produce
    // halfwords that coincidentally match VLE patterns.
    let s390_penalty = detect_s390x_cross_arch_penalty(data);
    if s390_penalty < 1.0 {
        score = (score as f64 * s390_penalty) as i64;
    }

    // Cross-architecture penalty: big-endian RISC (MIPS, SPARC, PPC classic)
    let be_penalty = detect_be_risc_cross_arch_penalty(data);
    if be_penalty < 1.0 {
        score = (score as f64 * be_penalty) as i64;
    }

    // Cross-architecture penalty: LoongArch (32-bit LE)
    let la_penalty = detect_loongarch_cross_arch_penalty(data);
    if la_penalty < 1.0 {
        score = (score as f64 * la_penalty) as i64;
    }

    cmp::max(0, score)
}

/// Detect s390x code patterns in big-endian data.
///
/// s390x uses variable-length instructions (2, 4, or 6 bytes), all big-endian.
/// Key patterns: BCR 15,14 (0x07FE = return), BALR (0x05xx), BASR (0x0Dxx),
/// STM/LM (0x90xx/0x98xx), STMG/LMG (0xEBxx with specific function codes).
fn detect_s390x_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 32 {
        return 1.0;
    }

    let mut evidence = 0u32;
    let mut bcr_count = 0u32;
    let mut stm_lm = 0u32;
    let mut balr_basr = 0u32;
    let mut larl = 0u32;
    let mut stmg_lmg = 0u32;

    let mut j = 0;
    while j + 1 < data.len() {
        let hw = u16::from_be_bytes([data[j], data[j + 1]]);
        let hi = data[j];

        // BCR 15,14 = 0x07FE (standard return)
        if hw == 0x07FE {
            bcr_count += 1;
        }
        // BCR with other masks (conditional returns): 0x07xx
        else if hi == 0x07 {
            bcr_count += 1;
        }
        // BALR = 0x05xx (branch and link register)
        else if hi == 0x05 {
            balr_basr += 1;
        }
        // BASR = 0x0Dxx (branch and save register)
        else if hi == 0x0D {
            balr_basr += 1;
        }
        // STM = 0x90xx (store multiple)
        else if hi == 0x90 {
            stm_lm += 1;
        }
        // LM = 0x98xx (load multiple)
        else if hi == 0x98 {
            stm_lm += 1;
        }
        // LARL = 0xC0x0 (load address relative long)
        else if hi == 0xC0 && (data[j + 1] & 0x0F) == 0x00 {
            larl += 1;
        }
        // STMG/LMG prefix = 0xEB (extended)
        else if hi == 0xEB {
            stmg_lmg += 1;
        }

        j += 2;
    }

    if bcr_count >= 2 {
        evidence += 3;
    } else if bcr_count >= 1 {
        evidence += 2;
    }
    if stm_lm >= 2 {
        evidence += 2;
    } else if stm_lm >= 1 {
        evidence += 1;
    }
    if balr_basr >= 2 {
        evidence += 2;
    } else if balr_basr >= 1 {
        evidence += 1;
    }
    if larl >= 2 {
        evidence += 1;
    }
    if stmg_lmg >= 2 {
        evidence += 1;
    }

    if evidence >= 5 {
        0.05
    } else if evidence >= 4 {
        0.10
    } else if evidence >= 3 {
        0.20
    } else {
        1.0
    }
}

/// Detect big-endian RISC code patterns (MIPS BE, SPARC, LoongArch).
fn detect_be_risc_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 32 {
        return 1.0;
    }

    let mut evidence = 0u32;
    let mut sparc_save = 0u32;
    let mut sparc_ret = 0u32;
    let mut mips_jr_ra = 0u32;
    let mut mips_lui = 0u32;

    let mut j = 0;
    while j + 3 < data.len() {
        let w = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);

        // SPARC save = 0x9DE3xxxx (save %sp, imm, %sp)
        if (w & 0xFFFF0000) == 0x9DE30000 {
            sparc_save += 1;
        }
        // SPARC ret = jmpl %i7+8, %g0 = 0x81C7E008
        if w == 0x81C7E008 {
            sparc_ret += 1;
        }
        // SPARC restore = 0x81E80000
        if w == 0x81E80000 {
            sparc_ret += 1;
        }
        // MIPS JR $ra = 0x03E00008
        if w == 0x03E00008 {
            mips_jr_ra += 1;
        }
        // MIPS LUI: opcode 0x0F in bits 31:26
        if (w >> 26) == 0x0F {
            mips_lui += 1;
        }

        j += 4;
    }

    if sparc_save >= 1 {
        evidence += 2;
    }
    if sparc_ret >= 1 {
        evidence += 2;
    }
    if mips_jr_ra >= 1 {
        evidence += 2;
    }
    if mips_lui >= 3 {
        evidence += 2;
    } else if mips_lui >= 1 {
        evidence += 1;
    }

    if evidence >= 4 {
        0.10
    } else if evidence >= 3 {
        0.20
    } else {
        1.0
    }
}

/// Detect LoongArch (32-bit LE) code patterns.
///
/// LoongArch uses fixed 32-bit LE instructions. When read as BE halfwords
/// (as PPC VLE does), the byte-swapped patterns can coincidentally match
/// VLE opcode ranges.
fn detect_loongarch_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 32 {
        return 1.0;
    }

    let mut evidence = 0u32;
    let mut la_ret = 0u32;
    let mut la_nop = 0u32;
    let mut la_bl = 0u32;
    let mut la_addi = 0u32;
    let mut la_st_ld = 0u32;

    let mut j = 0;
    while j + 3 < data.len() {
        let w = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);

        // LoongArch JIRL r0, r1, 0 (return) = 0x4C000020
        if w == 0x4C000020 {
            la_ret += 1;
        }
        // LoongArch NOP (ANDI r0, r0, 0) = 0x03400000
        else if w == 0x03400000 {
            la_nop += 1;
        }
        // LoongArch BL (opcode 0x15 in bits 31:26)
        else if (w >> 26) == 0x15 {
            la_bl += 1;
        }
        // LoongArch ADDI.D (opcode bits 31:22 = 0x00B)
        else if (w >> 22) == 0x00B {
            la_addi += 1;
        }
        // LoongArch ST.D (opcode bits 31:22 = 0x0A7)
        else if (w >> 22) == 0x0A7 {
            la_st_ld += 1;
        }
        // LoongArch LD.D (opcode bits 31:22 = 0x0A3)
        else if (w >> 22) == 0x0A3 {
            la_st_ld += 1;
        }
        // LoongArch B (opcode 0x14 in bits 31:26)
        else if (w >> 26) == 0x14 {
            la_bl += 1;
        }
        // LoongArch PCADDU12I (opcode bits 31:25 = 0x0E)
        else if (w >> 25) == 0x0E {
            la_addi += 1;
        }

        j += 4;
    }

    if la_ret >= 1 {
        evidence += 3;
    }
    if la_nop >= 1 {
        evidence += 1;
    }
    if la_bl >= 2 {
        evidence += 2;
    } else if la_bl >= 1 {
        evidence += 1;
    }
    if la_addi >= 3 {
        evidence += 2;
    } else if la_addi >= 1 {
        evidence += 1;
    }
    if la_st_ld >= 2 {
        evidence += 1;
    }

    if evidence >= 5 {
        0.05
    } else if evidence >= 4 {
        0.10
    } else if evidence >= 3 {
        0.20
    } else {
        1.0
    }
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
