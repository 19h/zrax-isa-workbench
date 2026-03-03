//! Heuristic scoring for Infineon TriCore architecture.
//!
//! TriCore instructions are either 16 or 32 bits long.
//! The LSB of the first 16-bit word determines the length:
//! - LSB == 0: 16-bit instruction
//! - LSB == 1: 32-bit instruction
//!
//! Instructions are little-endian.
//!
//! IMPORTANT: TriCore's variable-length encoding means almost any byte stream
//! can be parsed as a sequence of TriCore instructions (since LSB determines
//! width, and many major opcodes are valid). To avoid massive false positives
//! against other ISAs, we:
//! 1. Only award points for high-confidence, distinctive instruction patterns
//! 2. Require structural evidence (RETs, CALLs, function patterns)
//! 3. Penalize patterns characteristic of other architectures
//! 4. Apply NO multipliers — raw score only

use std::cmp;

/// Score raw data as TriCore code.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    if data.len() < 4 {
        return 0;
    }

    let mut i = 0;
    let mut ret_count: u32 = 0;
    let mut call_count: u32 = 0;
    let mut valid_insn: u32 = 0;
    let mut invalid_insn: u32 = 0;
    let mut zero_run: u32 = 0;
    let mut sys_insn_count: u32 = 0; // SVLCX, RSLCX, RFE, FRET - very distinctive
    let mut loop_count: u32 = 0; // LOOP/LOOPU instructions

    while i < data.len() - 1 {
        let insn_lo = u16::from_le_bytes([data[i], data[i + 1]]);

        // Handle zero-word runs
        if insn_lo == 0x0000 {
            zero_run += 1;
            if zero_run <= 2 {
                score += 1; // Possible NOP
            } else {
                score -= 3; // Padding, not code
            }
            i += 2;
            continue;
        }
        zero_run = 0;

        // Handle 0xFFFF (erased flash)
        if insn_lo == 0xFFFF {
            score -= 2;
            i += 2;
            continue;
        }

        let is_32bit = (insn_lo & 1) == 1;
        let major_op = (insn_lo & 0xFF) as u8;

        if is_32bit {
            if i + 3 >= data.len() {
                break;
            }
            let insn_hi = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            let insn = ((insn_hi as u32) << 16) | (insn_lo as u32);

            let s = score_32bit(
                insn,
                &mut ret_count,
                &mut call_count,
                &mut sys_insn_count,
                &mut loop_count,
            );
            if s > 0 {
                valid_insn += 1;
            } else if s < 0 {
                invalid_insn += 1;
            }
            score += s;

            i += 4;
        } else {
            // 16-bit instruction
            let s = score_16bit(insn_lo, &mut ret_count, &mut call_count);
            if s > 0 {
                valid_insn += 1;
            } else if s < 0 {
                invalid_insn += 1;
            }
            score += s;

            i += 2;
        }
    }

    // For large inputs (>4KB), require distinctive TriCore patterns
    if data.len() >= 4096 && ret_count == 0 && call_count == 0 {
        return 0;
    }

    // Additional requirement: for large inputs, require more than just
    // ret/call — the invalid ratio should be reasonable
    if data.len() >= 4096 && valid_insn > 0 {
        let total = valid_insn + invalid_insn;
        if total > 50 && (invalid_insn as f64 / total as f64) > 0.7 {
            // More than 70% of instructions are unrecognized — not TriCore
            return 0;
        }
    }

    // Structural bonuses — modest, no multipliers
    if valid_insn > 20 {
        // RET bonus
        if ret_count >= 3 {
            score += (ret_count as i64) * 8;
        }
        // CALL bonus
        if call_count >= 3 {
            score += (call_count as i64) * 5;
        }
        // System instruction bonus — SVLCX/RSLCX/RFE are VERY distinctive
        if sys_insn_count > 0 {
            score += (sys_insn_count as i64) * 15;
        }
        // LOOP instructions — distinctive
        if loop_count > 0 {
            score += (loop_count as i64) * 10;
        }
    }

    // Cross-architecture penalty: detect ARM patterns
    let arm_penalty = detect_arm_cross_penalty(data);
    if arm_penalty < 1.0 {
        score = (score as f64 * arm_penalty) as i64;
    }

    // Cross-architecture penalty: detect MIPS/PPC/SPARC patterns
    // These are 4-byte-aligned big-endian ISAs that TriCore will parse as
    // alternating 16-bit and 32-bit instructions due to random LSB values
    let be_penalty = detect_big_endian_cross_penalty(data);
    if be_penalty < 1.0 {
        score = (score as f64 * be_penalty) as i64;
    }

    cmp::max(0, score)
}

fn score_16bit(insn: u16, ret_count: &mut u32, call_count: &mut u32) -> i64 {
    // 16-bit instructions: LSB == 0
    // Major opcode is the low byte
    let major_op = (insn & 0xFF) as u8;
    let upper = (insn >> 8) as u8;

    // TriCore 16-bit RET: 0x9000 exactly (RET from call, no operands)
    if insn == 0x9000 {
        *ret_count += 1;
        return 15;
    }

    // TriCore 16-bit RFE: 0x8000 exactly
    if insn == 0x8000 {
        return 8;
    }

    // CALL (16-bit SB format): major_op = 0x5C
    // Encoding: 0x5C + 8-bit signed displacement in upper byte
    if major_op == 0x5C {
        *call_count += 1;
        return 12;
    }

    // J (16-bit SB format): major_op = 0x3C
    if major_op == 0x3C {
        return 4;
    }

    // Only score a few very distinctive 16-bit patterns.
    // Most 16-bit TriCore instructions are compact forms that look similar
    // to instructions in many other ISAs, so we keep scores LOW.
    match major_op {
        // SC format (stack cache): used for ADD.A SP, #const4 etc.
        // 0x10: ADD.A A10, #const4 — very common in TriCore (stack adjust)
        0x10 => 2,
        // SR format system: 0x00 with specific upper byte patterns
        0x00 => {
            match upper {
                0x00 => 0,  // NOP — don't reward
                0x90 => 15, // RET (caught above but just in case)
                0x80 => 8,  // RFE
                _ => 0,     // Other SR system — too ambiguous
            }
        }
        // SRR format: register-register operations
        0x32 => 2, // SR ACCU (ADD, SUB, MOV etc with A[15] or D[15])
        // JNZA, JZA (16-bit conditional jumps on address registers) — fairly distinctive
        0x6E => 3, // JNZ.A
        0xEE => 3, // JZ.A
        // JNZ, JZ on data register (16-bit)
        0x76 => 3, // JNZ.T
        0xF6 => 3, // JZ.T
        // LD.A / ST.A (16-bit short forms)
        0xD8 => 2, // LD.A short
        0xD4 => 2, // LD.A another form
        // Don't score other major opcodes — too many collisions with other ISAs
        _ => 0,
    }
}

fn score_32bit(
    insn: u32,
    ret_count: &mut u32,
    call_count: &mut u32,
    sys_count: &mut u32,
    loop_count: &mut u32,
) -> i64 {
    let major_op = (insn & 0xFF) as u8;

    // SYS format: major_op = 0x0D
    if major_op == 0x0D {
        let op2 = (insn >> 22) & 0x3F;
        match op2 {
            0x00 => return 3, // NOP (32-bit) — modest
            0x06 => {
                // RET (32-bit)
                *ret_count += 1;
                return 15;
            }
            0x07 => {
                // RFE — return from exception, VERY distinctive
                *sys_count += 1;
                return 20;
            }
            0x08 => {
                // SVLCX — save lower context, UNIQUE to TriCore
                *sys_count += 1;
                return 25;
            }
            0x09 => {
                // RSLCX — restore lower context, UNIQUE to TriCore
                *sys_count += 1;
                return 25;
            }
            0x03 => {
                // FRET — fast return
                *ret_count += 1;
                return 20;
            }
            0x04 => {
                // DEBUG
                return 5;
            }
            0x0C | 0x0D | 0x0E | 0x0F => return 3, // DISABLE/ENABLE/etc
            _ => return 0,                         // Unknown op2 in SYS — don't score
        }
    }

    // CALL (32-bit absolute/relative)
    match major_op {
        0x6D => {
            *call_count += 1;
            return 12; // CALL disp24
        }
        0xED => {
            *call_count += 1;
            return 12; // CALLA disp24
        }
        _ => {}
    }

    // LOOP instruction — very distinctive TriCore pattern (hardware loop)
    if major_op == 0xFD {
        *loop_count += 1;
        return 15; // LOOP
    }
    if major_op == 0xFC {
        *loop_count += 1;
        return 15; // LOOPU
    }

    // Jumps: only award modest scores
    match major_op {
        0x1D => return 3, // J
        0x9D => return 3, // JA
        0x5D => return 3, // JL
        0xDD => return 3, // JLA
        0x61 => return 3, // FCALL
        0xE1 => return 3, // FCALLA
        _ => {}
    }

    // Conditional branches (BRC, BRN, BRR forms)
    match major_op {
        // These are distinctive TriCore conditional branch forms
        0xDF => return 2, // JNE
        0xFF => return 2, // JNZ.T
        0xBF => return 2, // JZ.T
        0x6F => return 2, // JNZ
        0xEF => return 2, // JZ
        0x5F => return 2, // JEQ
        _ => {}
    }

    // Load/Store: be very conservative — these major opcodes overlap heavily
    // with other ISAs. Only award 1 point each.
    match major_op {
        0x85 | 0x05 | 0x15 | 0x25 | 0x45 | 0x65 | 0xA5 | 0xC5 | 0xE5 => return 1, // LD variants
        0x89 | 0xA9 | 0x09 | 0x29 | 0x49 | 0x69 => return 1,                      // ST variants
        0xB5 => return 1,                                                         // LD.A/ST.A
        _ => {}
    }

    // ALU operations: very conservative
    match major_op {
        0x0B | 0x8B => return 1, // ADD/SUB register forms
        0x8F => return 1,        // Immediate ALU
        0x0F => return 1,        // ABSDIF etc.
        _ => {}
    }

    // Everything else: no score (not penalized either, since TriCore has
    // odd-numbered major ops for 32-bit instructions and even for 16-bit,
    // so many values are legitimately possible)
    0
}

/// Detect ARM instruction patterns that TriCore falsely matches.
fn detect_arm_cross_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    // Check for ARM32 condition-code pattern: in ARM32, bits [31:28] are
    // the condition code. Most instructions use 0xE (AL=always).
    // When read as little-endian, the condition byte is at offset +3.
    // Check if most 4-byte-aligned words have 0xE in the high nibble.
    let mut al_count = 0u32;
    let mut check_count = 0u32;
    let check_len = data.len().min(1024);
    let mut j = 0;
    while j + 3 < check_len {
        let top_nibble = data[j + 3] >> 4;
        if top_nibble == 0xE {
            al_count += 1;
        }
        check_count += 1;
        j += 4;
    }
    if check_count > 10 && (al_count as f64 / check_count as f64) > 0.40 {
        return 0.2; // Strong ARM32 evidence
    }

    // Check for AArch64 patterns: MRS/MSR (0xD53/0xD51 in top 12 bits)
    let mut aarch64_sysreg = 0u32;
    j = 0;
    while j + 3 < check_len {
        let w = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
        let top12 = w >> 20;
        if top12 == 0xD53 || top12 == 0xD51 || top12 == 0xD50 {
            aarch64_sysreg += 1;
        }
        j += 4;
    }
    if aarch64_sysreg >= 3 {
        return 0.15;
    }

    // Check for Thumb-2 patterns: BL instruction = 0xF000xxxx + 0xF8xx
    // Thumb PUSH with LR: 0xB5xx (upper byte B5)
    let mut thumb_count = 0u32;
    j = 0;
    while j + 1 < check_len {
        let hw = u16::from_le_bytes([data[j], data[j + 1]]);
        if hw == 0x4770 {
            thumb_count += 2;
        } // BX LR
        if hw & 0xFF00 == 0xB500 {
            thumb_count += 1;
        } // PUSH {LR, ...}
        if hw & 0xFF00 == 0xBD00 {
            thumb_count += 1;
        } // POP {PC, ...}
        if hw == 0xBF00 {
            thumb_count += 1;
        } // NOP.N
        j += 2;
    }
    if thumb_count >= 8 {
        return 0.25;
    }

    1.0
}

/// Detect big-endian ISA patterns (MIPS, PowerPC, SPARC, s390x).
fn detect_big_endian_cross_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    let check_len = data.len().min(1024);

    // MIPS: NOP=0x00000000, JR $ra=0x03E00008, common lui/addiu patterns
    // PowerPC: BLR=0x4E800020, NOP=0x60000000
    // SPARC: NOP=0x01000000, RET+RESTORE=0x81C7E008
    let mut mips_sig = 0u32;
    let mut ppc_sig = 0u32;
    let mut sparc_sig = 0u32;

    let mut j = 0;
    while j + 3 < check_len {
        let w = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
        // MIPS
        if w == 0x03E00008 {
            mips_sig += 3;
        } // JR $ra
        if (w >> 26) == 0x0F {
            mips_sig += 1;
        } // LUI
        if (w >> 26) == 0x09 {
            mips_sig += 1;
        } // ADDIU
          // PowerPC
        if w == 0x4E800020 {
            ppc_sig += 3;
        } // BLR
        if w == 0x60000000 {
            ppc_sig += 1;
        } // NOP (ori 0,0,0)
        if (w >> 26) == 18 {
            ppc_sig += 1;
        } // B/BL
          // SPARC
        if w == 0x01000000 {
            sparc_sig += 1;
        } // NOP
        if w == 0x81C7E008 {
            sparc_sig += 3;
        } // RET
        if (w >> 30) == 0x01 {
            sparc_sig += 1;
        } // CALL

        j += 4;
    }

    let max_sig = mips_sig.max(ppc_sig).max(sparc_sig);
    if max_sig >= 8 {
        return 0.1;
    }
    if max_sig >= 4 {
        return 0.3;
    }

    // s390x: instructions start with specific opcodes that are very distinctive
    // s390x RET is 0x07FE (BCR 15,14)
    let mut s390_sig = 0u32;
    j = 0;
    while j + 1 < check_len {
        let hw = u16::from_be_bytes([data[j], data[j + 1]]);
        if hw == 0x07FE {
            s390_sig += 2;
        } // BCR 15,14 (return)
        if hw & 0xFF00 == 0x4700 {
            s390_sig += 1;
        } // BC (branch)
        j += 2;
    }
    if s390_sig >= 6 {
        return 0.15;
    }

    1.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tricore_nop_ret() {
        let code = [
            0x00, 0x00, // NOP 16-bit
            0x00, 0x90, // RET 16-bit
            0x0d, 0x00, 0x00, 0x00, // NOP 32-bit (major 0x0d, op2 = 0)
            0x0d, 0x00, 0x80, 0x01, // RET 32-bit (major 0x0d, op2 = 0x06 in bits 22-27)
        ];
        assert!(score(&code) > 0);
    }
}
