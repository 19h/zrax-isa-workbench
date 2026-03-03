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
///
/// S12Z is a niche architecture. We must keep per-instruction scores very low
/// because S12Z's opcode space overlaps significantly with MIPS, x86, ARM, etc.
/// The 0x92-0xFF range is all TRAP instructions, which helps reject non-S12Z data,
/// but the common opcodes (branches 0x20-0x2F, RTS 0x05, NOP 0x01) are too generic
/// on their own to be distinctive.
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 16 {
        return 0;
    }

    let mut score: i64 = 0;
    let mut i = 0;

    let mut rts_count: u32 = 0;
    let mut bsr_count: u32 = 0;
    let mut branch_count: u32 = 0;
    let mut invalid_count: u32 = 0;
    let mut valid_insn: u32 = 0;

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
                score += 1;
                valid_insn += 1;
                i += 1;
            }
            0x05 => {
                // RTS
                score += 4;
                rts_count += 1;
                valid_insn += 1;
                i += 1;
            }
            0x90 => {
                // RTI
                score += 4;
                valid_insn += 1;
                i += 1;
            }
            0x21 => {
                // BSR — subroutine call
                if i + 1 < data.len() {
                    score += 2;
                    bsr_count += 1;
                    valid_insn += 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            0x20 | 0x22..=0x2F => {
                // BRA and conditional branches
                if i + 1 < data.len() {
                    score += 1;
                    branch_count += 1;
                    valid_insn += 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            0x1C..=0x1F => {
                // MOV
                score += 1;
                valid_insn += 1;
                i += 2;
            }
            0x92..=0x9F | 0xA8..=0xAF | 0xB8..=0xFF => {
                // TRAP — heavy penalty, these dominate in non-S12Z data
                invalid_count += 1;
                score -= 3;
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
        if rts_count > 3 {
            score += (rts_count as i64) * 2;
        }
        if branch_count > 8 {
            score += (branch_count as i64) * 1;
        }

        let valid_ratio = valid_insn as f64 / (valid_insn + invalid_count) as f64;
        if valid_ratio > 0.70 {
            score += (valid_insn as i64) / 4;
        }
    }

    // Structural evidence: require returns + calls for larger files
    if data.len() > 2048 {
        if rts_count < 2 || bsr_count < 2 {
            return 0;
        }
    } else if data.len() > 512 {
        if rts_count == 0 || bsr_count == 0 {
            return 0;
        }
    }

    // ─── Cross-architecture penalties ───
    let arm_penalty = detect_arm_cross_arch_penalty(data);
    if arm_penalty < 1.0 {
        score = (score as f64 * arm_penalty) as i64;
    }

    let be_penalty = detect_big_endian_cross_arch_penalty(data);
    if be_penalty < 1.0 {
        score = (score as f64 * be_penalty) as i64;
    }

    let x86_penalty = detect_x86_cross_arch_penalty(data);
    if x86_penalty < 1.0 {
        score = (score as f64 * x86_penalty) as i64;
    }

    let rv_penalty = detect_riscv_cross_arch_penalty(data);
    if rv_penalty < 1.0 {
        score = (score as f64 * rv_penalty) as i64;
    }

    cmp::max(0, score)
}

/// Detect ARM32/AArch64 code and penalize S12Z.
fn detect_arm_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(8192);
    let mut arm32_cond_e: u32 = 0;
    let mut aarch64_ret: u32 = 0;
    let mut arm_bx_lr: u32 = 0;
    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if (w >> 28) == 0xE {
            arm32_cond_e += 1;
        }
        if w == 0xE12FFF1E {
            arm_bx_lr += 1;
        }
        if w == 0xD65F03C0 {
            aarch64_ret += 1;
        }
        i += 4;
    }
    let total_words = (check_len / 4) as f64;
    let mut evidence: u32 = 0;
    if arm32_cond_e as f64 / total_words > 0.25 {
        evidence += 3;
    } else if arm32_cond_e as f64 / total_words > 0.15 {
        evidence += 2;
    }
    if arm_bx_lr >= 3 {
        evidence += 2;
    } else if arm_bx_lr >= 1 {
        evidence += 1;
    }
    if aarch64_ret >= 3 {
        evidence += 3;
    } else if aarch64_ret >= 1 {
        evidence += 2;
    }
    if evidence >= 4 {
        0.05
    } else if evidence >= 3 {
        0.10
    } else if evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect big-endian RISC architectures (MIPS, PPC, SPARC, s390x).
fn detect_big_endian_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(8192);
    let mut mips_jr_ra: u32 = 0;
    let mut mips_lui: u32 = 0;
    let mut ppc_blr: u32 = 0;
    let mut sparc_ret: u32 = 0;
    let mut s390_bcr: u32 = 0;
    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if w == 0x03E00008 {
            mips_jr_ra += 1;
        }
        if (w >> 26) == 0x0F {
            mips_lui += 1;
        }
        if w == 0x4E800020 {
            ppc_blr += 1;
        }
        if w == 0x81C7E008 {
            sparc_ret += 1;
        }
        if i + 1 < check_len {
            let hw = u16::from_be_bytes([data[i], data[i + 1]]);
            if hw == 0x07FE {
                s390_bcr += 1;
            }
        }
        i += 4;
    }
    let mut evidence: u32 = 0;
    if mips_jr_ra >= 3 {
        evidence += 3;
    } else if mips_jr_ra >= 1 {
        evidence += 2;
    }
    if mips_lui >= 10 {
        evidence += 2;
    } else if mips_lui >= 3 {
        evidence += 1;
    }
    if ppc_blr >= 3 {
        evidence += 3;
    } else if ppc_blr >= 1 {
        evidence += 2;
    }
    if sparc_ret >= 2 {
        evidence += 3;
    } else if sparc_ret >= 1 {
        evidence += 2;
    }
    if s390_bcr >= 5 {
        evidence += 3;
    } else if s390_bcr >= 2 {
        evidence += 2;
    }
    if evidence >= 4 {
        0.05
    } else if evidence >= 3 {
        0.10
    } else if evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect x86/x86_64 code and penalize S12Z.
fn detect_x86_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(8192);
    let mut x86_ret: u32 = 0;
    let mut x86_push_ebp: u32 = 0;
    let mut x86_call: u32 = 0;
    let mut x86_mov_rsp: u32 = 0;
    let mut i = 0;
    while i < check_len {
        let b = data[i];
        match b {
            0xC3 => x86_ret += 1,
            0x55 => x86_push_ebp += 1,
            0xE8 => x86_call += 1,
            0x89 if i + 1 < check_len && data[i + 1] == 0xE5 => x86_mov_rsp += 1,
            0x48 if i + 2 < check_len && data[i + 1] == 0x89 && data[i + 2] == 0xE5 => {
                x86_mov_rsp += 1;
            }
            _ => {}
        }
        i += 1;
    }
    let byte_count = check_len as f64;
    let mut evidence: u32 = 0;
    if x86_ret as f64 / byte_count > 0.005 && x86_ret >= 3 {
        evidence += 2;
    } else if x86_ret >= 2 {
        evidence += 1;
    }
    if x86_push_ebp >= 3 && x86_mov_rsp >= 2 {
        evidence += 3;
    } else if x86_push_ebp >= 2 && x86_mov_rsp >= 1 {
        evidence += 2;
    }
    if x86_call as f64 / byte_count > 0.005 && x86_call >= 5 {
        evidence += 2;
    } else if x86_call >= 3 {
        evidence += 1;
    }
    if evidence >= 4 {
        0.05
    } else if evidence >= 3 {
        0.10
    } else if evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect RISC-V code and penalize S12Z.
fn detect_riscv_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(8192);
    let mut rv_ret: u32 = 0;
    let mut rv_auipc: u32 = 0;
    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if w == 0x00008067 {
            rv_ret += 1;
        }
        if (w & 0x7F) == 0x17 {
            rv_auipc += 1;
        }
        i += 4;
    }
    let total_words = (check_len / 4) as f64;
    let mut evidence: u32 = 0;
    if rv_ret >= 3 {
        evidence += 3;
    } else if rv_ret >= 1 {
        evidence += 2;
    }
    if rv_auipc as f64 / total_words > 0.03 && rv_auipc >= 5 {
        evidence += 2;
    } else if rv_auipc >= 3 {
        evidence += 1;
    }
    if evidence >= 4 {
        0.05
    } else if evidence >= 3 {
        0.10
    } else if evidence >= 2 {
        0.25
    } else {
        1.0
    }
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
