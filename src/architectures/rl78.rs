//! Heuristic scoring for the Renesas RL78 instruction set architecture.
//!
//! The RL78 is the modern successor to the NEC 78K family of 8/16-bit
//! microcontrollers. It is widely used in automotive (instrument clusters,
//! body electronics) and industrial applications.
//!
//! Key characteristics for heuristic detection:
//! - **Little-endian** byte ordering
//! - **Variable-length instructions**: 1 to 5 bytes, byte-aligned
//! - **8/16-bit registers**: 8 general-purpose 8-bit registers
//!   (X, A, C, B, E, D, L, H) that can be paired as 16-bit register
//!   pairs (AX, BC, DE, HL)
//! - **20-bit address space** (1MB)
//! - **Stack pointer**: SP (16-bit or 20-bit depending on mode)
//! - **Three instruction prefixes** that extend the opcode map:
//!   - 0x61 prefix: second map (additional ALU, shift, special instructions)
//!   - 0x71 prefix: third map (bit manipulation, conditional branches)
//!   - 0xCE prefix: extended instructions (MOV with [DE+byte], etc.)
//! - **Common opcodes**: RET (0xD7), NOP (0x00), PUSH/POP register pairs
//!   (0xC0-0xC7), CALL !addr16 (0xFD), CALL $addr20 (0xFE),
//!   MOV A,#imm8 (0x51), MOVW rp,#imm16 (0x30/0x32/0x34/0x36)
//!
//! References:
//! - Renesas RL78 Family User's Manual: Software (R01US0015EJ)
//! - Renesas RL78/G14 Hardware Manual
//! - RL78 Instruction Set Summary (R01US0029EJ)

use std::cmp;

/// Score raw data as Renesas RL78 code.
///
/// The scorer walks through data byte-by-byte (variable-length instructions,
/// 1 to 5 bytes), interpreting each position as a potential RL78 instruction.
/// It recognizes page 1 opcodes (single byte), page 2 opcodes (0x61 prefix),
/// page 3 opcodes (0x71 prefix), and extended opcodes (0xCE prefix). It
/// assigns per-instruction scores weighted by distinctiveness and applies
/// structural bonuses for patterns characteristic of real RL78 firmware.
///
/// Returns a non-negative score (clamped at 0).
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 16 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut i: usize = 0;

    // Structural counters
    let mut ret_count: u32 = 0; // RET (0xD7)
    let mut reti_count: u32 = 0; // RETI (0x61 0xFC)
    let mut _nop_count: u32 = 0; // NOP (0x00)
    let mut brk_count: u32 = 0; // BRK (0x61 0xCC)
    let mut halt_count: u32 = 0; // HALT (0x61 0xED)
    let mut call_count: u32 = 0; // CALL instructions (0xFD, 0xFE)
    let mut callt_count: u32 = 0; // CALLT instructions
    let mut br_count: u32 = 0; // Unconditional branches
    let mut bcc_count: u32 = 0; // Conditional branches
    let mut push_pop_count: u32 = 0; // PUSH/POP register pairs
    let mut mov_count: u32 = 0; // MOV/MOVW instructions
    let mut alu_count: u32 = 0; // ALU immediate instructions
    let mut bit_op_count: u32 = 0; // Bit operations (0x71 prefix)
    let mut prefix61_count: u32 = 0; // 0x61 prefix sequences
    let mut prefix71_count: u32 = 0; // 0x71 prefix sequences
    let mut prefixce_count: u32 = 0; // 0xCE prefix sequences
    let mut ei_di_count: u32 = 0; // EI/DI instructions
    let mut valid_insn_count: u32 = 0;
    let mut invalid_count: u32 = 0;
    let mut zero_run: u32 = 0;

    while i < data.len() {
        let opcode = data[i];

        // ─── Handle zero bytes ───
        // 0x00 = NOP on RL78 — valid but used as padding in flash images.
        // Penalize long zero runs to avoid false positives from zero-filled data.
        if opcode == 0x00 {
            zero_run += 1;
            if zero_run <= 2 {
                // First 1-2 NOPs are plausible (alignment padding)
                _nop_count += 1;
                total_score += 1;
            } else if zero_run <= 4 {
                total_score -= 2;
            } else {
                total_score -= 5;
            }
            i += 1;
            continue;
        }
        // 0xFF bytes (erased flash)
        if opcode == 0xFF {
            i += 1;
            continue;
        }
        zero_run = 0;

        let (insn_score, insn_len) = score_instruction(data, i);

        total_score += insn_score;

        if insn_score > 0 {
            valid_insn_count += 1;
        } else if insn_score < -1 {
            invalid_count += 1;
        }

        // ─── Update structural counters ───
        match opcode {
            0xD7 => ret_count += 1,
            // PUSH register pairs
            0xC1 | 0xC5 | 0xC3 | 0xC7 => push_pop_count += 1,
            // POP register pairs
            0xC0 | 0xC4 | 0xC2 | 0xC6 => push_pop_count += 1,
            // CALL !addr16
            0xFD => call_count += 1,
            // CALL $addr20 (relative)
            0xFE => call_count += 1,
            // CALLT [addr5]
            0xC8..=0xCF if (opcode & 0xC0) == 0xC0 => {
                // CALLT encoding: 0b110001xx to 0b11001111 range
                // Actually CALLT is 0x61 0x84-0x9F in some docs,
                // but in the main map it's 0xC8-0xCF range
                callt_count += 1;
            }
            // BR $rel (3-byte unconditional branch)
            0xEF => br_count += 1,
            // BC $rel
            0xDC => bcc_count += 1,
            // BNC $rel
            0xDD => bcc_count += 1,
            // BZ $rel
            0xDE => bcc_count += 1,
            // BNZ $rel
            0xDF => bcc_count += 1,
            // MOV A, #imm8 and MOV reg, #imm8 (0x50-0x57)
            0x50..=0x57 => mov_count += 1,
            // MOVW rp, #imm16 (0x30, 0x32, 0x34, 0x36)
            0x30 | 0x32 | 0x34 | 0x36 => mov_count += 1,
            // MOV A, [HL] / MOV A, [DE]
            0x8B | 0x8A => mov_count += 1,
            // MOV [HL], A / MOV [DE], A
            0x9B | 0x9A => mov_count += 1,
            // MOV saddr, #imm8
            0xCD => mov_count += 1,
            // ALU immediate: ADD/ADDC/SUB/SUBC/CMP/AND/OR/XOR A, #imm8
            0x0D | 0x1D | 0x2D | 0x3D | 0x4D | 0x5D | 0x6D | 0x7D => alu_count += 1,
            // 0x61 prefix — handled in score_instruction, just count
            0x61 => prefix61_count += 1,
            // 0x71 prefix — handled in score_instruction, just count
            0x71 => prefix71_count += 1,
            // 0xCE prefix
            0xCE => prefixce_count += 1,
            // Bit manipulation with 0x31 prefix (BT/BF/BTCLR)
            0x31 => bit_op_count += 1,
            _ => {}
        }

        // Check for RETI, HALT, BRK etc. (0x61 prefix)
        if opcode == 0x61 && i + 1 < data.len() {
            match data[i + 1] {
                0xFC => reti_count += 1,
                0xCC => brk_count += 1,
                0xED => halt_count += 1,
                _ => {}
            }
        }

        // Check for EI/DI (0x71 prefix, 3 bytes)
        if opcode == 0x71 && i + 2 < data.len() {
            if data[i + 2] == 0xFA {
                match data[i + 1] {
                    0x7A => ei_di_count += 1, // EI
                    0x7B => ei_di_count += 1, // DI
                    _ => {}
                }
            }
        }

        i += insn_len;
    }

    // ─── Structural bonuses ───
    let total_insns = valid_insn_count + invalid_count;
    if total_insns > 10 {
        let valid_ratio = valid_insn_count as f64 / total_insns as f64;

        // High valid instruction ratio: only award a small bonus, and require
        // a very high ratio since nearly every byte maps to a valid RL78 opcode.
        if valid_ratio > 0.70 && total_insns > 100 {
            total_score += (valid_insn_count as i64) / 8;
        }

        // RET (0xD7) — function return
        if ret_count > 5 {
            total_score += (ret_count as i64) * 3;
        }

        // RETI (0x61 0xFC) — interrupt return (2-byte sequence, more distinctive)
        if reti_count > 0 {
            total_score += (reti_count as i64) * 8;
        }

        // HALT (0x61 0xED) — 2-byte sequence, distinctive
        if halt_count > 0 {
            total_score += (halt_count as i64) * 6;
        }

        // BRK (0x61 0xCC) — software breakpoint
        if brk_count > 0 {
            total_score += (brk_count as i64) * 5;
        }

        // PUSH/POP register pairs (0xC0-0xC7)
        if push_pop_count > 4 {
            total_score += (push_pop_count as i64) * 2;
        }

        // CALL instructions
        if call_count > 5 {
            total_score += (call_count as i64) * 3;
        }

        // CALLT — table call, highly distinctive for RL78
        if callt_count > 0 {
            total_score += (callt_count as i64) * 8;
        }

        // Conditional branches (BC/BNC/BZ/BNZ)
        if bcc_count > 5 {
            total_score += (bcc_count as i64) * 2;
        }

        // EI/DI — enable/disable interrupts, distinctive 3-byte sequences
        if ei_di_count > 0 {
            total_score += (ei_di_count as i64) * 6;
        }

        // 0x61 prefix sequences — characteristic of RL78's extended opcode map
        if prefix61_count > 5 {
            total_score += (prefix61_count as i64) * 2;
        }

        // 0x71 prefix sequences — bit manipulation map
        if prefix71_count > 3 {
            total_score += (prefix71_count as i64) * 3;
        }

        // Combined structural signature: require more RL78-specific features
        // and give smaller bonuses
        let signature_features = [
            ret_count > 8,                                       // Function returns
            push_pop_count > 5,                                  // Stack operations
            call_count > 8,                                      // Subroutine calls
            bcc_count > 8,                                       // Conditional branches
            mov_count > 15,                                      // Data movement
            prefix61_count > 3 || prefix71_count > 2,            // Prefix usage
            reti_count > 0 || halt_count > 0 || ei_di_count > 0, // System instructions
            callt_count > 0,                                     // Table calls (unique!)
            bit_op_count > 2 || prefix71_count > 3,              // Bit manipulation
        ];
        let feature_count = signature_features.iter().filter(|&&f| f).count();
        if feature_count >= 6 {
            total_score += (valid_insn_count as i64) / 4;
        } else if feature_count >= 4 {
            total_score += (valid_insn_count as i64) / 8;
        }

        // ─── Prologue/epilogue pattern detection ───
        // RL78 function prologues typically start with PUSH rp sequences:
        //   PUSH AX (0xC1), PUSH BC (0xC5), PUSH DE (0xC3), PUSH HL (0xC7)
        // And epilogues end with POP rp sequences followed by RET:
        //   POP HL (0xC6), POP DE (0xC2), POP BC (0xC4), POP AX (0xC0), RET (0xD7)
        if data.len() >= 4 {
            let mut prologue_count: u32 = 0;
            let mut epilogue_count: u32 = 0;

            let mut j = 0;
            while j + 1 < data.len() {
                // Detect PUSH sequence: two or more consecutive PUSH rp
                if is_push_rp(data[j]) && is_push_rp(data[j + 1]) {
                    prologue_count += 1;
                }
                // Detect POP + RET: POP rp followed by RET
                if is_pop_rp(data[j]) && data[j + 1] == 0xD7 {
                    epilogue_count += 1;
                }
                j += 1;
            }

            if prologue_count > 0 {
                total_score += (prologue_count as i64) * 5;
            }
            if epilogue_count > 0 {
                total_score += (epilogue_count as i64) * 8;
            }
        }
    }

    // ─── Structural evidence requirement for larger files ───
    // For files > 512 bytes, require meaningful structural evidence (returns + calls).
    // Byte-oriented ISAs like RL78 match nearly every byte as a valid opcode,
    // so without structural evidence the score is almost certainly a false positive.
    if data.len() > 512 {
        if ret_count == 0 && call_count == 0 && reti_count == 0 {
            return 0;
        }
        // For larger files, require both returns AND calls
        if data.len() > 2048 && (ret_count < 2 || (call_count == 0 && callt_count == 0)) {
            total_score /= 4;
        }
    }

    // ─── Cross-architecture penalties ───
    // RL78 is a byte-oriented ISA where ~80% of byte values score positive.
    // Without cross-arch penalties, it will outscore the correct ISA on
    // virtually any binary. We detect distinctive patterns from major ISAs
    // and apply heavy penalties when found.
    let arm_penalty = detect_arm_cross_arch_penalty(data);
    if arm_penalty < 1.0 {
        total_score = (total_score as f64 * arm_penalty) as i64;
    }

    let be_penalty = detect_big_endian_cross_arch_penalty(data);
    if be_penalty < 1.0 {
        total_score = (total_score as f64 * be_penalty) as i64;
    }

    let x86_penalty = detect_x86_cross_arch_penalty(data);
    if x86_penalty < 1.0 {
        total_score = (total_score as f64 * x86_penalty) as i64;
    }

    let riscv_penalty = detect_riscv_cross_arch_penalty(data);
    if riscv_penalty < 1.0 {
        total_score = (total_score as f64 * riscv_penalty) as i64;
    }

    let hexagon_penalty = detect_hexagon_cross_arch_penalty(data);
    if hexagon_penalty < 1.0 {
        total_score = (total_score as f64 * hexagon_penalty) as i64;
    }

    let loongarch_penalty = detect_loongarch_cross_arch_penalty(data);
    if loongarch_penalty < 1.0 {
        total_score = (total_score as f64 * loongarch_penalty) as i64;
    }

    let tc_penalty = detect_tricore_cross_arch_penalty(data);
    if tc_penalty < 1.0 {
        total_score = (total_score as f64 * tc_penalty) as i64;
    }

    let mips_le_penalty = detect_mips_le_cross_arch_penalty(data);
    if mips_le_penalty < 1.0 {
        total_score = (total_score as f64 * mips_le_penalty) as i64;
    }

    cmp::max(0, total_score)
}

/// Check if a byte is a PUSH register pair opcode.
#[inline]
fn is_push_rp(b: u8) -> bool {
    matches!(b, 0xC1 | 0xC5 | 0xC3 | 0xC7)
}

/// Check if a byte is a POP register pair opcode.
#[inline]
fn is_pop_rp(b: u8) -> bool {
    matches!(b, 0xC0 | 0xC4 | 0xC2 | 0xC6)
}

/// Score a single RL78 instruction at position `i` in `data`.
/// Returns (score, instruction_length_in_bytes).
///
/// This function handles the full RL78 opcode space including:
/// - Page 1: single-byte opcodes (the main map)
/// - Page 2: 0x61 prefix + second byte
/// - Page 3: 0x71 prefix + second byte (+ possible operands)
/// - Extended: 0xCE prefix + second byte (+ operands)
/// - Bit test/branch: 0x31 prefix + second byte (+ operands)
fn score_instruction(data: &[u8], i: usize) -> (i64, usize) {
    let opcode = data[i];

    // ─── Page 2 prefix (0x61) ───
    // The 0x61 prefix extends the opcode map with additional ALU,
    // shift, and system instructions.
    if opcode == 0x61 {
        return score_page2_instruction(data, i);
    }

    // ─── Page 3 prefix (0x71) ───
    // The 0x71 prefix provides bit manipulation instructions:
    // SET1, CLR1, and related bit operations on saddr.
    if opcode == 0x71 {
        return score_page3_instruction(data, i);
    }

    // ─── Extended prefix (0xCE) ───
    // The 0xCE prefix provides extended addressing modes,
    // particularly MOV with [DE+byte] and [HL+byte] offsets.
    if opcode == 0xCE {
        return score_extended_instruction(data, i);
    }

    // ─── Bit test and branch prefix (0x31) ───
    // BT saddr.bit, $rel / BF saddr.bit, $rel / BTCLR saddr.bit, $rel
    if opcode == 0x31 {
        return score_bit_branch_instruction(data, i);
    }

    // ─── RET — return from subroutine (0xD7) ───
    // The single most common instruction in RL78 code; every function
    // ends with it. Moderately scored — must not be too high since 0xD7
    // is a single byte that can appear in any binary.
    if opcode == 0xD7 {
        return (5, 1);
    }

    // ─── PUSH register pairs ───
    // PUSH AX = 0xC1, PUSH DE = 0xC3, PUSH BC = 0xC5, PUSH HL = 0xC7
    match opcode {
        0xC1 => return (3, 1), // PUSH AX
        0xC3 => return (3, 1), // PUSH DE
        0xC5 => return (3, 1), // PUSH BC
        0xC7 => return (3, 1), // PUSH HL
        _ => {}
    }

    // ─── POP register pairs ───
    // POP AX = 0xC0, POP DE = 0xC2, POP BC = 0xC4, POP HL = 0xC6
    match opcode {
        0xC0 => return (3, 1), // POP AX
        0xC2 => return (3, 1), // POP DE
        0xC4 => return (3, 1), // POP BC
        0xC6 => return (3, 1), // POP HL
        _ => {}
    }

    // ─── CALLT [addr5] — table call ───
    // Encoding: 0b110000xx to 0b110011xx range (0xC8-0xCF)
    // CALLT is highly distinctive for RL78: it calls through a table
    // in low memory (0x0080-0x00BF), which is unique to this architecture.
    // Note: 0xCE is the extended prefix, so exclude it.
    if opcode >= 0xC8 && opcode <= 0xCF && opcode != 0xCE {
        return (5, 1);
    }

    // ─── MOV reg, #imm8 (0x50-0x57) ───
    // 0x50 = MOV X, #imm8
    // 0x51 = MOV A, #imm8 — the most common single MOV instruction
    // 0x52 = MOV C, #imm8
    // 0x53 = MOV B, #imm8
    // 0x54 = MOV E, #imm8
    // 0x55 = MOV D, #imm8
    // 0x56 = MOV L, #imm8
    // 0x57 = MOV H, #imm8
    if opcode >= 0x50 && opcode <= 0x57 {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        // MOV A, #imm8 is the most common
        let s = if opcode == 0x51 { 3 } else { 2 };
        return (s, 2);
    }

    // ─── MOVW rp, #imm16 ───
    // 0x30 = MOVW AX, #imm16  (3 bytes)
    // 0x32 = MOVW DE, #imm16  (3 bytes)
    // 0x34 = MOVW BC, #imm16  (3 bytes)
    // 0x36 = MOVW HL, #imm16  (3 bytes)
    match opcode {
        0x30 | 0x32 | 0x34 | 0x36 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        _ => {}
    }

    // ─── MOVW rp, rp (register pair to register pair) ───
    // 0x24 = MOVW AX, BC (but check RL78 manual — various MOVW encodings)
    // Actually these are 0x11nn forms — handled below

    // ─── MOV A, [HL] / MOV A, [DE] / MOV [HL], A / MOV [DE], A ───
    match opcode {
        0x8B => return (3, 1), // MOV A, [HL]
        0x8A => return (3, 1), // MOV A, [DE]
        0x9B => return (3, 1), // MOV [HL], A
        0x9A => return (3, 1), // MOV [DE], A
        _ => {}
    }

    // ─── MOV A, [HL+byte] / MOV [HL+byte], A ───
    match opcode {
        0x89 => {
            // MOV A, [HL+byte] — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x99 => {
            // MOV [HL+byte], A — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        _ => {}
    }

    // ─── MOV saddr, #imm8 (0xCD) — short address direct ───
    // 3 bytes: opcode + saddr + imm8
    if opcode == 0xCD {
        if i + 2 >= data.len() {
            return (-1, 1);
        }
        return (2, 3);
    }

    // ─── MOV A, saddr (0x8D) / MOV saddr, A (0x9D) ───
    match opcode {
        0x8D => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2); // MOV A, saddr
        }
        0x9D => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2); // MOV saddr, A
        }
        _ => {}
    }

    // ─── MOV A, !addr16 (0x8E) / MOV !addr16, A (0x9E) ───
    match opcode {
        0x8E => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (2, 3); // MOV A, !addr16
        }
        0x9E => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (2, 3); // MOV !addr16, A
        }
        _ => {}
    }

    // ─── MOV saddr, saddr (0xCA) ───
    if opcode == 0xCA {
        if i + 2 >= data.len() {
            return (-1, 1);
        }
        return (2, 3); // MOV saddr, saddr — 3 bytes
    }

    // ─── MOVW AX, saddr (0xAD) / MOVW saddr, AX (0xBD) ───
    match opcode {
        0xAD => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0xBD => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        _ => {}
    }

    // ─── MOVW AX, !addr16 (0xAE) / MOVW !addr16, AX (0xBE) ───
    match opcode {
        0xAE => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (2, 3);
        }
        0xBE => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (2, 3);
        }
        _ => {}
    }

    // ─── ALU A, #imm8 instructions ───
    // These all have the pattern 0xnD + imm8 (2 bytes)
    match opcode {
        0x0D => {
            // ADD A, #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x1D => {
            // ADDC A, #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x2D => {
            // SUB A, #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x3D => {
            // SUBC A, #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x4D => {
            // CMP A, #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2); // CMP is very common before branches
        }
        0x5D => {
            // AND A, #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x6D => {
            // OR A, #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x7D => {
            // XOR A, #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        _ => {}
    }

    // ─── ALU A, saddr instructions ───
    // Pattern: 0x0E-0x7E with low nibble 0xE (ADD/ADDC/SUB/SUBC/CMP/AND/OR/XOR)
    // 2 bytes: opcode + saddr
    match opcode {
        0x0E | 0x1E | 0x2E | 0x3E | 0x4E | 0x5E | 0x6E | 0x7E => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (1, 2);
        }
        _ => {}
    }

    // ─── ALU A, !addr16 instructions ───
    // Pattern: 0x08-0x78 with low nibble 0x8 (some are ALU with !addr16)
    // 3 bytes: opcode + addr16
    match opcode {
        0x08 | 0x18 | 0x28 | 0x38 | 0x48 | 0x58 | 0x68 | 0x78 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (1, 3);
        }
        _ => {}
    }

    // ─── ALU A, [HL] / ALU A, [DE] instructions ───
    // Pattern: 0x0B-0x7B / 0x0A-0x7A with specific low nibbles
    match opcode {
        0x0B | 0x1B | 0x2B | 0x3B | 0x4B | 0x5B | 0x6B | 0x7B => {
            // ALU A, [HL] — 1 byte
            return (2, 1);
        }
        0x0A | 0x1A | 0x2A | 0x3A | 0x4A | 0x5A | 0x6A | 0x7A => {
            // ALU A, [DE] — 1 byte (some of these are actually different ops,
            // but in the RL78 map they're generally valid)
            return (1, 1);
        }
        _ => {}
    }

    // ─── ALU saddr, #imm8 instructions ───
    // 3 bytes: opcode + saddr + imm8
    match opcode {
        0x0C | 0x1C | 0x2C | 0x3C | 0x4C | 0x5C | 0x6C | 0x7C => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (1, 3);
        }
        _ => {}
    }

    // ─── Branch instructions ───
    match opcode {
        // BR $addr20 = 0xEF + 2-byte signed relative (3 bytes total)
        0xEF => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        // BR !addr16 = 0xED + 2-byte absolute (3 bytes total)
        0xED => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (2, 3);
        }
        // BC $rel = 0xDC + rel8 (2 bytes)
        0xDC => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        // BNC $rel = 0xDD + rel8 (2 bytes)
        0xDD => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        // BZ $rel = 0xDE + rel8 (2 bytes)
        0xDE => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        // BNZ $rel = 0xDF + rel8 (2 bytes)
        0xDF => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        _ => {}
    }

    // ─── CALL instructions ───
    match opcode {
        // CALL !addr16 = 0xFD + 2-byte address (3 bytes) — near call
        0xFD => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        // CALL $addr20 = 0xFE + 2-byte relative (3 bytes)
        0xFE => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        // CALL !!addr20 = 0xFC + 3-byte address (4 bytes) — far call
        0xFC => {
            if i + 3 >= data.len() {
                return (-1, 1);
            }
            return (4, 4);
        }
        _ => {}
    }

    // ─── INC/DEC register ───
    // INC r (0x40-0x47), DEC r (0x90-0x97 in some encoding)
    // Actually RL78 INC saddr = 0x80, DEC saddr = 0x81
    match opcode {
        0x80 => {
            // INC saddr — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        0x81 => {
            // DEC saddr — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        _ => {}
    }

    // ─── INCW/DECW register pair ───
    // INCW AX = 0xA0, INCW BC = 0xA2, INCW DE = 0xA4, INCW HL = 0xA6
    // DECW AX = 0xB0, DECW BC = 0xB2, DECW DE = 0xB4, DECW HL = 0xB6
    match opcode {
        0xA0 | 0xA2 | 0xA4 | 0xA6 => return (2, 1), // INCW rp
        0xB0 | 0xB2 | 0xB4 | 0xB6 => return (2, 1), // DECW rp
        _ => {}
    }

    // ─── ADDW/SUBW/CMPW instructions (word operations) ───
    match opcode {
        // ADDW AX, #imm16 = 0x04 + word (3 bytes)
        0x04 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (2, 3);
        }
        // SUBW AX, #imm16 = 0x06 + word (3 bytes)
        0x06 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (2, 3);
        }
        // CMPW AX, #imm16 = 0x44 + word (3 bytes)
        0x44 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (2, 3);
        }
        _ => {}
    }

    // ─── MOVW SP, AX / MOVW AX, SP ───
    // These are actually 0x61 prefixed instructions, handled in page2

    // ─── XCH A, r (exchange) ───
    // 0x08..0x0F range (some are XCH, some ALU — check RL78 map carefully)
    // XCH A, X = 0x08 — but 0x08 is also ADD A, !addr16 above
    // Actually XCH is in the 0x61 prefix map

    // ─── MULU X ───
    // 0xD6 = MULU X (unsigned multiply: AX = A * X) — 1 byte
    if opcode == 0xD6 {
        return (3, 1);
    }

    // ─── DIVHU / DIVWU ───
    // These are in the 0x61 prefix map

    // ─── ROL/ROR/ROLC/RORC/SHL/SHR/SAR ───
    // Most shift/rotate instructions are in the 0x61 prefix map

    // ─── MOV ES, #imm8 (0x41) ───
    // The ES (extension segment) register is used for 20-bit addressing.
    // MOV ES, #imm8 = 0x41 + byte (2 bytes)
    if opcode == 0x41 {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        // ES register usage is distinctive for RL78's 20-bit addressing
        return (4, 2);
    }

    // ─── MOV1 CY, saddr.bit / MOV1 saddr.bit, CY ───
    // Various bit-level carry operations — encoded in 0x71 prefix map

    // ─── SET1 / CLR1 in main map ───
    // SET1 saddr.bit / CLR1 saddr.bit — some variants in main map
    // SET1 CY = 0x20 (1 byte), CLR1 CY = 0x21 (1 byte)
    match opcode {
        0x20 => return (4, 1), // SET1 CY
        0x21 => return (4, 1), // CLR1 CY
        _ => {}
    }

    // ─── ONEB/ONEW/CLRB/CLRW shortcuts ───
    match opcode {
        // ONEB A = 0xE4 (MOV A, #1 shortcut)
        0xE4 => return (4, 1),
        // ONEB X = 0xE5
        0xE5 => return (4, 1),
        // ONEB B = 0xE6 — but be careful, 0xE6 might be something else
        // CLRB A = 0xF4 (MOV A, #0 shortcut)
        0xF4 => return (4, 1),
        // ONEW AX = 0xE0
        0xE0 => return (4, 1),
        // ONEW BC = 0xE2
        0xE2 => return (4, 1),
        // CLRW AX = 0xF0
        0xF0 => return (4, 1),
        // CLRW BC = 0xF2
        0xF2 => return (4, 1),
        _ => {}
    }

    // ─── Short direct branch instructions (DBNZ) ───
    // DBNZ saddr, $rel = 0x04 ?? — actually DBNZ B, $rel = 0x82 + rel (2 bytes)
    // DBNZ C, $rel = 0x83 + rel (2 bytes)
    // DBNZ saddr, $rel = 0x84 + saddr + rel (3 bytes)
    match opcode {
        0x82 | 0x83 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2); // DBNZ reg, $rel — loop primitive
        }
        0x84 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3); // DBNZ saddr, $rel
        }
        _ => {}
    }

    // ─── MOVW rp, AX / MOVW AX, rp ───
    // MOVW DE, AX = 0x15, MOVW BC, AX = 0x13, MOVW HL, AX = 0x17
    // MOVW AX, DE = 0x14, MOVW AX, BC = 0x12, MOVW AX, HL = 0x16
    match opcode {
        0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 => {
            return (2, 1); // MOVW register pair operations
        }
        _ => {}
    }

    // ─── XCHW AX, rp ───
    // 0x31..0x37 odd — but 0x31 is the bit-branch prefix, so only some
    // Actually XCHW is also in the main map:
    // XCHW AX, BC = 0x35, XCHW AX, DE = 0x33, XCHW AX, HL = 0x37
    match opcode {
        0x33 | 0x35 | 0x37 => return (2, 1),
        _ => {}
    }

    // ─── MOV A, reg / MOV reg, A (register-to-register) ───
    // MOV A, X = 0x60, MOV A, C = 0x62, MOV A, B = 0x63,
    // MOV A, E = 0x64, MOV A, D = 0x65, MOV A, L = 0x66, MOV A, H = 0x67
    if opcode >= 0x60 && opcode <= 0x67 {
        return (1, 1);
    }
    // MOV X, A = 0x70, MOV C, A = 0x72, MOV B, A = 0x73,
    // MOV E, A = 0x74, MOV D, A = 0x75, MOV L, A = 0x76, MOV H, A = 0x77
    if opcode >= 0x70 && opcode <= 0x77 {
        return (1, 1);
    }

    // ─── MOV A, [HL+C] / MOV A, [HL+B] ───
    match opcode {
        0x8C => return (2, 1), // MOV A, [HL+B]
        0x8F => return (2, 1), // MOV A, [HL+C]
        _ => {}
    }

    // ─── MOVW with SP (in 0x61 prefix map, but some variants here) ───
    // MOVW AX, [SP+byte] variants

    // ─── Catch remaining known valid single-byte opcodes ───
    match opcode {
        // Various 1-byte instructions not matched above
        0x01 => return (3, 1), // NOP variant / ADDW SP, #byte — check context
        0x02 => {
            // ADDW SP, #imm8 — 2 bytes (used in function entry/exit)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        0x03 => {
            // SUBW SP, #imm8 — 2 bytes (used in function entry/exit)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        0x05 => {
            // MOV A, [DE+byte] — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x07 => {
            // MOV [DE+byte], A — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (2, 2);
        }
        0x09 => return (3, 1), // ADDW AX, AX (shift left)
        // Single-byte register operations
        0xD0 => return (3, 1), // (various RL78 1-byte ops)
        0xD1 => return (3, 1),
        0xD4 => return (3, 1),
        0xD5 => return (3, 1),
        _ => {}
    }

    // ─── MOV A, [addr16] ───
    // Various extended addressing forms using 0xF0-0xF7 range
    // (not all of these are MOV — check the RL78 map)
    match opcode {
        0xF5 => {
            // MOV A, ES:[HL+byte] or similar — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        0xF6 => {
            // MOV ES:saddr, A or similar — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        0xF7 => {
            // MOV A, ES:saddr or similar — 2 bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        _ => {}
    }

    // ─── Remaining opcodes not explicitly handled ───
    // The RL78 opcode space has many valid opcodes. Those we haven't
    // explicitly matched may be valid (less common) or may be data
    // mixed with code. Apply a mild penalty.
    (-2, 1)
}

/// Score a page 2 instruction (preceded by 0x61 prefix).
/// The `i` parameter points to the 0x61 byte.
///
/// Page 2 includes: additional MOV/XCH variants, shift/rotate instructions,
/// system instructions (HALT, STOP, BRK, RETI, RETB), stack operations
/// (PUSH PSW, POP PSW), multiply/divide, and extended register operations.
fn score_page2_instruction(data: &[u8], i: usize) -> (i64, usize) {
    if i + 1 >= data.len() {
        return (-1, 1);
    }

    let page2_op = data[i + 1];

    match page2_op {
        // ─── System instructions (distinctive when in 2-byte sequence) ───
        0xFC => return (8, 2), // RETI — return from interrupt
        0xFD => return (6, 2), // STOP — stop processor
        0xED => return (6, 2), // HALT — halt processor
        0xCC => return (5, 2), // BRK — software breakpoint
        0xFE => return (5, 2), // RETB — return from break

        // ─── PUSH PSW ───
        0xDD => return (4, 2), // PUSH PSW

        // ─── MOVW AX, SP / MOVW SP, AX ───
        0xA8 => return (4, 2), // MOVW AX, SP — reading stack pointer
        0xA9 => return (4, 2), // MOVW SP, AX — setting stack pointer

        // ─── Shift/Rotate instructions (all 2 bytes with 0x61 prefix) ───
        // SHL A, cnt / SHR A, cnt / SAR A, cnt
        // ROL A, cnt / ROR A, cnt / ROLC A, cnt / RORC A, cnt
        0xC0..=0xCB if page2_op != 0xCC => {
            // Various shift/rotate encodings in the 0xC0-0xCB range
            return (4, 2);
        }

        // ─── MUL / DIVHU / DIVWU ───
        0xD8 => return (3, 2), // MULHU — unsigned multiply (RL78/G14)
        0xD9 => return (3, 2), // MULH — signed multiply
        0xDE => return (3, 2), // DIVHU — unsigned divide
        0xDF => return (3, 2), // DIVWU — unsigned word divide

        // ─── Extended ALU operations ───
        // ADD/ADDC/SUB/SUBC/AND/OR/XOR/CMP with additional addressing modes
        0x00..=0x7F => {
            // Many valid page 2 ALU and MOV operations
            // Apply moderate positive score
            return (3, 2);
        }

        // ─── XCH A, reg variants ───
        0x80..=0x8F => return (4, 2), // Various XCH operations

        // ─── MULU / other extended operations ───
        0x90..=0xBF => return (3, 2),

        // ─── Conditional branches with extended conditions ───
        // BH $rel = 0x61 0xC3 + byte (3 bytes)
        // BNH $rel = 0x61 0xD3 + byte (3 bytes)
        0xC3 => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (6, 3); // BH $rel
        }
        0xD3 => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (6, 3); // BNH $rel
        }

        // ─── Remaining page 2 opcodes ───
        _ => return (2, 2), // Unknown but plausible page 2 op
    }
}

/// Score a page 3 instruction (preceded by 0x71 prefix).
/// The `i` parameter points to the 0x71 byte.
///
/// Page 3 is the bit manipulation map:
/// - SET1 saddr.bit = 0x71 0x0n + saddr (3 bytes, n=bit*2)
/// - CLR1 saddr.bit = 0x71 0x8n + saddr (3 bytes, n=bit*2)
/// - SET1 A.bit / CLR1 A.bit (2 bytes)
/// - MOV1 CY, saddr.bit / MOV1 saddr.bit, CY
/// - AND1 CY, saddr.bit / OR1 CY, saddr.bit / XOR1 CY, saddr.bit
/// - EI/DI: 0x71 0x7A 0xFA / 0x71 0x7B 0xFA (3 bytes)
fn score_page3_instruction(data: &[u8], i: usize) -> (i64, usize) {
    if i + 1 >= data.len() {
        return (-1, 1);
    }

    let page3_op = data[i + 1];

    // ─── EI / DI — enable/disable interrupts ───
    // These are 3-byte sequences and very distinctive for RL78.
    // EI = 0x71 0x7A 0xFA
    // DI = 0x71 0x7B 0xFA
    if i + 2 < data.len() && data[i + 2] == 0xFA {
        match page3_op {
            0x7A => return (8, 3), // EI — enable interrupts (3-byte distinctive)
            0x7B => return (8, 3), // DI — disable interrupts (3-byte distinctive)
            _ => {}
        }
    }

    // ─── SET1 / CLR1 on saddr ───
    // SET1 saddr.bit: page3_op in 0x00-0x0E even (bit 0-7)
    // CLR1 saddr.bit: page3_op in 0x80-0x8E even (bit 0-7)
    let lo_nib = page3_op & 0x0F;
    let hi_nib = page3_op >> 4;

    // SET1 saddr.bit — upper nibble 0x0, lower nibble 0x00-0x0E even
    if hi_nib == 0x0 && (lo_nib & 0x01) == 0 {
        if i + 2 >= data.len() {
            return (3, 2);
        }
        return (8, 3); // SET1 saddr.bit — 3 bytes, very distinctive
    }

    // CLR1 saddr.bit — upper nibble 0x8, lower nibble 0x00-0x0E even
    if hi_nib == 0x8 && (lo_nib & 0x01) == 0 {
        if i + 2 >= data.len() {
            return (3, 2);
        }
        return (8, 3); // CLR1 saddr.bit — 3 bytes
    }

    // SET1 A.bit — upper nibble 0x0, lower nibble odd (0x01-0x0F)
    if hi_nib == 0x0 && (lo_nib & 0x01) == 1 {
        return (6, 2); // SET1 A.bit — 2 bytes
    }

    // CLR1 A.bit — upper nibble 0x8, lower nibble odd (0x81-0x8F)
    if hi_nib == 0x8 && (lo_nib & 0x01) == 1 {
        return (6, 2); // CLR1 A.bit — 2 bytes
    }

    // ─── MOV1 CY, saddr.bit / MOV1 saddr.bit, CY ───
    // MOV1 CY, saddr.bit: hi_nib = 0x0-0x7, certain patterns
    // MOV1 saddr.bit, CY: hi_nib = 0x0-0x7, certain patterns
    if hi_nib >= 0x0 && hi_nib <= 0x7 {
        if i + 2 >= data.len() {
            return (3, 2);
        }
        return (6, 3); // MOV1/AND1/OR1/XOR1 with carry
    }

    // ─── NOT1 CY ───
    if page3_op == 0xC0 {
        return (5, 2);
    }

    // ─── Remaining page 3 opcodes ───
    // All page 3 opcodes are valid bit operations
    if i + 2 < data.len() {
        return (4, 3); // Most page 3 ops are 3 bytes
    }
    (2, 2)
}

/// Score an extended instruction (preceded by 0xCE prefix).
/// The `i` parameter points to the 0xCE byte.
///
/// The 0xCE prefix provides extended addressing modes, particularly
/// MOV with [DE+byte] and [HL+byte] base+displacement addressing.
fn score_extended_instruction(data: &[u8], i: usize) -> (i64, usize) {
    if i + 1 >= data.len() {
        return (-1, 1);
    }

    let ext_op = data[i + 1];

    // Most 0xCE prefix instructions are 3-4 bytes:
    // 0xCE + subopcode + operand(s)
    match ext_op {
        // MOV A, [DE+byte] / MOV [DE+byte], A variants
        0x00..=0x0F => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3); // MOV with base+displacement
        }
        // MOV A, [HL+byte] / MOV [HL+byte], A variants
        0x10..=0x1F => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        // ALU A, [HL+byte] — extended ALU with base+displacement
        0x80..=0xBF => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (4, 3);
        }
        // Various extended MOV/ALU operations
        _ => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (3, 3);
        }
    }
}

/// Score a bit test and branch instruction (preceded by 0x31 prefix).
/// The `i` parameter points to the 0x31 byte.
///
/// These instructions test a bit in a short-address byte and conditionally
/// branch:
/// - BT saddr.bit, $rel — branch if bit is set
/// - BF saddr.bit, $rel — branch if bit is clear
/// - BTCLR saddr.bit, $rel — branch if bit is set, then clear it
///
/// These are highly distinctive for the RL78 architecture.
fn score_bit_branch_instruction(data: &[u8], i: usize) -> (i64, usize) {
    if i + 1 >= data.len() {
        return (-1, 1);
    }

    let sub_op = data[i + 1];

    // BT saddr.bit, $rel: sub_op high nibble 0x8n (bit test, branch if set)
    // BF saddr.bit, $rel: sub_op high nibble 0x0n (bit test, branch if clear)
    // BTCLR saddr.bit, $rel: another encoding variant
    //
    // All of these are 4 bytes: 0x31 + sub_op + saddr + rel
    let hi_nib = sub_op >> 4;

    match hi_nib {
        0x8 | 0x9 | 0xA | 0xB | 0xC | 0xD | 0xE | 0xF => {
            // BT variants — branch if bit set
            if i + 3 >= data.len() {
                return (3, 2);
            }
            return (8, 4); // BT saddr.bit, $rel — 4 bytes, very distinctive
        }
        0x0 | 0x1 | 0x2 | 0x3 | 0x4 | 0x5 | 0x6 | 0x7 => {
            // BF / BTCLR variants — branch if bit clear
            if i + 3 >= data.len() {
                return (3, 2);
            }
            return (8, 4); // BF saddr.bit, $rel — 4 bytes
        }
        _ => {
            // Should not reach here given exhaustive nibble coverage
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (5, 4);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: pad a byte vector to at least 16 bytes with RET (0xD7)
    /// instructions so the scorer's minimum length check passes.
    fn pad16(mut v: Vec<u8>) -> Vec<u8> {
        while v.len() < 16 {
            v.push(0xD7); // RET — valid filler
        }
        v
    }

    #[test]
    fn test_rl78_ret() {
        // RET (0xD7) repeated — every function ends with RET
        let code = vec![0xD7; 20];
        let s = score(&code);
        assert!(s > 0, "RET stream should score positively, got {}", s);
    }

    #[test]
    fn test_rl78_push_pop_ret() {
        // Typical function prologue/epilogue:
        // PUSH AX, PUSH BC, ... work ... POP BC, POP AX, RET
        let code = pad16(vec![
            0xC1, // PUSH AX
            0xC5, // PUSH BC
            0xC3, // PUSH DE
            0x51, 0x42, // MOV A, #0x42
            0x4D, 0x00, // CMP A, #0x00
            0xDE, 0x03, // BZ $+3
            0xFD, 0x00, 0x10, // CALL !0x1000
            0xC2, // POP DE
            0xC4, // POP BC
            0xC0, // POP AX
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 30,
            "Push/pop/call/ret pattern should score well, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_call() {
        // CALL !addr16 (0xFD + 2 bytes)
        let code = pad16(vec![
            0xFD, 0x00, 0x10, // CALL !0x1000
            0xFD, 0x50, 0x20, // CALL !0x2050
            0xFD, 0x00, 0x30, // CALL !0x3000
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(s > 20, "CALL stream should score well, got {}", s);
    }

    #[test]
    fn test_rl78_mov_immediate() {
        // MOV reg, #imm8 instructions
        let code = pad16(vec![
            0x51, 0x00, // MOV A, #0x00
            0x50, 0xFF, // MOV X, #0xFF
            0x52, 0x55, // MOV C, #0x55
            0x53, 0xAA, // MOV B, #0xAA
            0x56, 0x10, // MOV L, #0x10
            0x57, 0x20, // MOV H, #0x20
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 20,
            "MOV immediate stream should score positively, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_movw_immediate() {
        // MOVW rp, #imm16 instructions (3 bytes each)
        let code = pad16(vec![
            0x30, 0x00, 0x10, // MOVW AX, #0x1000
            0x36, 0x00, 0x20, // MOVW HL, #0x2000
            0x34, 0xFF, 0x00, // MOVW BC, #0x00FF
            0x32, 0x50, 0x30, // MOVW DE, #0x3050
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 20,
            "MOVW immediate stream should score positively, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_alu_immediate() {
        // ALU A, #imm8 instructions
        let code = pad16(vec![
            0x0D, 0x01, // ADD A, #0x01
            0x2D, 0x02, // SUB A, #0x02
            0x4D, 0x00, // CMP A, #0x00
            0x5D, 0x0F, // AND A, #0x0F
            0x6D, 0xF0, // OR A, #0xF0
            0x7D, 0xFF, // XOR A, #0xFF
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 20,
            "ALU immediate stream should score positively, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_conditional_branches() {
        // Conditional branch instructions
        let code = pad16(vec![
            0x4D, 0x00, // CMP A, #0x00
            0xDE, 0x05, // BZ $+5
            0x4D, 0xFF, // CMP A, #0xFF
            0xDF, 0x03, // BNZ $+3
            0xDC, 0x02, // BC $+2
            0xDD, 0x01, // BNC $+1
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 20,
            "Conditional branch stream should score positively, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_page2_instructions() {
        // Page 2 (0x61 prefix) instructions
        let code = pad16(vec![
            0x61, 0xFC, // RETI
            0x61, 0xED, // HALT
            0x61, 0xA8, // MOVW AX, SP
            0x61, 0xDD, // PUSH PSW
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(s > 20, "Page 2 instructions should score well, got {}", s);
    }

    #[test]
    fn test_rl78_page3_bit_ops() {
        // Page 3 (0x71 prefix) bit operations
        let code = pad16(vec![
            0x71, 0x00, 0x20, // SET1 0x20.0
            0x71, 0x80, 0x20, // CLR1 0x20.0
            0x71, 0x02, 0x21, // SET1 0x21.1
            0x71, 0x82, 0x21, // CLR1 0x21.1
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(s > 20, "Page 3 bit operations should score well, got {}", s);
    }

    #[test]
    fn test_rl78_ei_di() {
        // EI/DI — enable/disable interrupts (3 bytes each)
        let code = pad16(vec![
            0x71, 0x7B, 0xFA, // DI
            0x51, 0x00, // MOV A, #0x00
            0x9D, 0x20, // MOV saddr, A
            0x71, 0x7A, 0xFA, // EI
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(s > 20, "EI/DI pattern should score well, got {}", s);
    }

    #[test]
    fn test_rl78_bit_branch() {
        // Bit test and branch (0x31 prefix, 4 bytes)
        let code = pad16(vec![
            0x31, 0x80, 0x20, 0x05, // BT saddr.0, $+5
            0x31, 0x00, 0x20, 0x03, // BF saddr.0, $+3
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 10,
            "Bit test and branch should score positively, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_mov_memory() {
        // MOV A, [HL] / MOV [HL], A / MOV A, [DE] etc.
        let code = pad16(vec![
            0x8B, // MOV A, [HL]
            0x9B, // MOV [HL], A
            0x8A, // MOV A, [DE]
            0x9A, // MOV [DE], A
            0x8D, 0x20, // MOV A, saddr
            0x9D, 0x20, // MOV saddr, A
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(s > 20, "MOV memory operations should score well, got {}", s);
    }

    #[test]
    fn test_rl78_incw_decw() {
        // INCW/DECW register pair
        let code = pad16(vec![
            0xA6, // INCW HL
            0xA6, // INCW HL
            0xA6, // INCW HL
            0xB6, // DECW HL
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(s > 0, "INCW/DECW should score positively, got {}", s);
    }

    #[test]
    fn test_rl78_zero_padding_penalty() {
        // Long run of zeros should be penalized
        let code = vec![0x00; 64];
        let s = score(&code);
        assert!(s == 0, "Long zero run should score 0 (clamped), got {}", s);
    }

    #[test]
    fn test_rl78_ff_padding_penalty() {
        // Long run of 0xFF (erased flash) should be penalized
        let code = vec![0xFF; 64];
        let s = score(&code);
        assert!(s == 0, "Long 0xFF run should score 0 (clamped), got {}", s);
    }

    #[test]
    fn test_rl78_realistic_function() {
        // A realistic RL78 function:
        // void set_port(uint8_t val) {
        //   DI();
        //   P1 = val;
        //   EI();
        //   return;
        // }
        let code = pad16(vec![
            0xC1, // PUSH AX
            0x71, 0x7B, 0xFA, // DI
            0x9D, 0x01, // MOV 0xFF01, A  (port P1)
            0x71, 0x7A, 0xFA, // EI
            0xC0, // POP AX
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 30,
            "Realistic RL78 function should score well, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_callt() {
        // CALLT table calls — distinctive for RL78
        let code = pad16(vec![
            0xC8, // CALLT [0x0080]
            0xC9, // CALLT [0x0082]
            0xCA, // CALLT [addr]  — note 0xCA is MOV saddr,saddr in main map
            0xCB, // CALLT [addr]
            0xCF, // CALLT [addr]
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(s > 0, "CALLT stream should score positively, got {}", s);
    }

    #[test]
    fn test_rl78_subw_sp() {
        // SUBW SP, #imm8 / ADDW SP, #imm8 — stack frame manipulation
        let code = pad16(vec![
            0x03, 0x04, // SUBW SP, #4
            0x51, 0x00, // MOV A, #0
            0x02, 0x04, // ADDW SP, #4
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 10,
            "Stack frame manipulation should score positively, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_extended_prefix() {
        // 0xCE prefix (extended addressing)
        let code = pad16(vec![
            0xCE, 0x00, 0x10, // MOV A, [DE+0x10] via extended prefix
            0xCE, 0x10, 0x20, // MOV A, [HL+0x20] via extended prefix
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 5,
            "Extended prefix instructions should score positively, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_dbnz_loop() {
        // DBNZ — decrement and branch if not zero (loop primitive)
        let code = pad16(vec![
            0x53, 0x0A, // MOV B, #10
            // loop:
            0x9B, // MOV [HL], A
            0xA6, // INCW HL
            0x82, 0xFC, // DBNZ B, loop  (rel = -4)
            0xD7, // RET
        ]);
        let s = score(&code);
        assert!(
            s > 10,
            "DBNZ loop pattern should score positively, got {}",
            s
        );
    }

    #[test]
    fn test_rl78_not_random() {
        // Random-ish data should not score well
        let code: Vec<u8> = (0..64).map(|i| ((i * 37 + 13) % 256) as u8).collect();
        let s = score(&code);
        // Random data may get some incidental hits but should be modest
        // Just verify it doesn't explode — exact threshold is hard to predict
        assert!(
            s < 200,
            "Random data should not score excessively, got {}",
            s
        );
    }
}

fn detect_tricore_cross_arch_penalty(data: &[u8]) -> f64 {
    let mut tricore_ret = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        if data[i] == 0x00 && (data[i + 1] & 0xF0) == 0x90 {
            tricore_ret += 1;
        }
        i += 2;
    }
    if tricore_ret > 50 && data.len() >= 4096 {
        return 0.05;
    }
    1.0
}

/// Detect ARM32/Thumb/AArch64 firmware and penalize RL78 score.
///
/// ARM32: condition codes in bits 31:28 (0xE = always), BX LR (0xE12FFF1E),
/// common prologue PUSH {fp,lr} / STMFD sp!, {...}.
/// AArch64: fixed-width 32-bit LE instructions, RET = 0xD65F03C0,
/// BL = 0x94xxxxxx, B = 0x14xxxxxx/0x17xxxxxx.
fn detect_arm_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    let mut arm_evidence: u32 = 0;

    // Scan for 32-bit ARM/AArch64 patterns at 4-byte alignment
    let mut arm32_cond_e: u32 = 0;
    let mut aarch64_ret: u32 = 0;
    let mut aarch64_bl: u32 = 0;
    let mut arm_bx_lr: u32 = 0;

    let check_len = data.len().min(8192);
    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // ARM32: condition code 0xE (always) in bits 31:28
        if (w >> 28) == 0xE {
            arm32_cond_e += 1;
        }

        // ARM32 BX LR = 0xE12FFF1E
        if w == 0xE12FFF1E {
            arm_bx_lr += 1;
        }

        // AArch64 RET = 0xD65F03C0
        if w == 0xD65F03C0 {
            aarch64_ret += 1;
        }

        // AArch64 BL = 0x94xxxxxx
        if (w >> 26) == 0b100101 {
            aarch64_bl += 1;
        }

        // AArch64 B = 0x14xxxxxx or 0x17xxxxxx
        if (w >> 26) == 0b000101 {
            aarch64_bl += 1;
        }

        i += 4;
    }

    let total_words = (check_len / 4) as f64;

    // ARM32: high density of condition code 0xE
    if arm32_cond_e as f64 / total_words > 0.25 {
        arm_evidence += 3;
    } else if arm32_cond_e as f64 / total_words > 0.15 {
        arm_evidence += 2;
    }

    // ARM32 BX LR
    if arm_bx_lr >= 3 {
        arm_evidence += 2;
    } else if arm_bx_lr >= 1 {
        arm_evidence += 1;
    }

    // AArch64 RET
    if aarch64_ret >= 3 {
        arm_evidence += 3;
    } else if aarch64_ret >= 1 {
        arm_evidence += 2;
    }

    // AArch64 BL density
    if aarch64_bl >= 10 {
        arm_evidence += 2;
    } else if aarch64_bl >= 3 {
        arm_evidence += 1;
    }

    if arm_evidence >= 4 {
        0.05
    } else if arm_evidence >= 3 {
        0.10
    } else if arm_evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect big-endian RISC architectures (MIPS, PPC, SPARC, s390x) and penalize RL78.
///
/// MIPS: JR $ra = 0x03E00008, LUI = 0x3Cxxxxxx, NOP = 0x00000000 after branch.
/// PPC: BLR = 0x4E800020, NOP = 0x60000000, B = 0x48xxxxxx.
/// SPARC: RET = 0x81C7E008, NOP = 0x01000000, SAVE = 0x9DExxxxx.
/// s390x: BCR 15,14 = 0x07FE, BALR = 0x05xx.
fn detect_big_endian_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    let mut be_evidence: u32 = 0;
    let check_len = data.len().min(8192);

    let mut mips_jr_ra: u32 = 0;
    let mut mips_lui: u32 = 0;
    let mut ppc_blr: u32 = 0;
    let mut ppc_nop: u32 = 0;
    let mut sparc_ret: u32 = 0;
    let mut sparc_save: u32 = 0;
    let mut s390_bcr: u32 = 0;

    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // MIPS JR $ra = 0x03E00008
        if w == 0x03E00008 {
            mips_jr_ra += 1;
        }
        // MIPS LUI rt, imm = 0x3Cxxxxxx (opcode field = 0x0F)
        if (w >> 26) == 0x0F {
            mips_lui += 1;
        }
        // PPC BLR = 0x4E800020
        if w == 0x4E800020 {
            ppc_blr += 1;
        }
        // PPC NOP = 0x60000000
        if w == 0x60000000 {
            ppc_nop += 1;
        }
        // SPARC RET = 0x81C7E008
        if w == 0x81C7E008 {
            sparc_ret += 1;
        }
        // SPARC SAVE = 0x9DExxxxx (bits 31:25 = 0b1001110 1)
        if (w >> 22) == 0x277 {
            sparc_save += 1;
        }

        // s390x: 2-byte instructions — check halfwords
        if i + 1 < check_len {
            let hw = u16::from_be_bytes([data[i], data[i + 1]]);
            // BCR 15,14 = 0x07FE
            if hw == 0x07FE {
                s390_bcr += 1;
            }
        }

        i += 4;
    }

    // MIPS evidence
    if mips_jr_ra >= 3 {
        be_evidence += 3;
    } else if mips_jr_ra >= 1 {
        be_evidence += 2;
    }
    if mips_lui >= 10 {
        be_evidence += 2;
    } else if mips_lui >= 3 {
        be_evidence += 1;
    }

    // PPC evidence
    if ppc_blr >= 3 {
        be_evidence += 3;
    } else if ppc_blr >= 1 {
        be_evidence += 2;
    }
    if ppc_nop >= 5 {
        be_evidence += 1;
    }

    // SPARC evidence
    if sparc_ret >= 2 {
        be_evidence += 3;
    } else if sparc_ret >= 1 {
        be_evidence += 2;
    }
    if sparc_save >= 2 {
        be_evidence += 1;
    }

    // s390x evidence
    if s390_bcr >= 5 {
        be_evidence += 3;
    } else if s390_bcr >= 2 {
        be_evidence += 2;
    }

    if be_evidence >= 4 {
        0.05
    } else if be_evidence >= 3 {
        0.10
    } else if be_evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect x86/x86_64 code and penalize RL78.
///
/// x86: RET = 0xC3, PUSH EBP = 0x55, MOV ESP,EBP = 0x89E5,
/// CALL rel32 = 0xE8xxxxxxxx, INT3 = 0xCC, REX prefixes (0x40-0x4F in x64).
fn detect_x86_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    let check_len = data.len().min(8192);
    let mut x86_ret: u32 = 0;
    let mut x86_push_ebp: u32 = 0;
    let mut x86_call_rel32: u32 = 0;
    let mut x86_mov_rsp: u32 = 0; // 0x4889E5 (REX.W MOV RBP, RSP) or 0x89E5

    let mut i = 0;
    while i < check_len {
        let b = data[i];
        match b {
            0xC3 => x86_ret += 1,
            0x55 => x86_push_ebp += 1,
            0xE8 => x86_call_rel32 += 1,
            0x89 if i + 1 < check_len && data[i + 1] == 0xE5 => x86_mov_rsp += 1,
            0x48 if i + 2 < check_len && data[i + 1] == 0x89 && data[i + 2] == 0xE5 => {
                x86_mov_rsp += 1;
            }
            _ => {}
        }
        i += 1;
    }

    let byte_count = check_len as f64;
    let mut x86_evidence: u32 = 0;

    // x86 RET density (in real x86 code: ~0.5-2%)
    let ret_density = x86_ret as f64 / byte_count;
    if ret_density > 0.005 && x86_ret >= 3 {
        x86_evidence += 2;
    } else if x86_ret >= 2 {
        x86_evidence += 1;
    }

    // PUSH EBP + MOV RBP,RSP pattern (function prologues)
    if x86_push_ebp >= 3 && x86_mov_rsp >= 2 {
        x86_evidence += 3;
    } else if x86_push_ebp >= 2 && x86_mov_rsp >= 1 {
        x86_evidence += 2;
    }

    // CALL rel32 density
    let call_density = x86_call_rel32 as f64 / byte_count;
    if call_density > 0.005 && x86_call_rel32 >= 5 {
        x86_evidence += 2;
    } else if x86_call_rel32 >= 3 {
        x86_evidence += 1;
    }

    if x86_evidence >= 4 {
        0.05
    } else if x86_evidence >= 3 {
        0.10
    } else if x86_evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect RISC-V code and penalize RL78.
///
/// RISC-V: RET = JALR x0,x1,0 = 0x00008067, AUIPC = upper bits 0x17,
/// C.JR/C.JALR in compressed form, LUI = upper bits 0x37.
fn detect_riscv_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    let check_len = data.len().min(8192);
    let mut riscv_ret: u32 = 0;
    let mut riscv_auipc: u32 = 0;
    let mut riscv_lui: u32 = 0;

    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // RISC-V RET = 0x00008067
        if w == 0x00008067 {
            riscv_ret += 1;
        }
        // AUIPC: opcode bits 6:0 = 0x17
        if (w & 0x7F) == 0x17 {
            riscv_auipc += 1;
        }
        // LUI: opcode bits 6:0 = 0x37
        if (w & 0x7F) == 0x37 {
            riscv_lui += 1;
        }

        i += 4;
    }

    let total_words = (check_len / 4) as f64;
    let mut rv_evidence: u32 = 0;

    if riscv_ret >= 3 {
        rv_evidence += 3;
    } else if riscv_ret >= 1 {
        rv_evidence += 2;
    }

    let auipc_density = riscv_auipc as f64 / total_words;
    if auipc_density > 0.03 && riscv_auipc >= 5 {
        rv_evidence += 2;
    } else if riscv_auipc >= 3 {
        rv_evidence += 1;
    }

    let lui_density = riscv_lui as f64 / total_words;
    if lui_density > 0.03 && riscv_lui >= 5 {
        rv_evidence += 1;
    }

    if rv_evidence >= 4 {
        0.05
    } else if rv_evidence >= 3 {
        0.10
    } else if rv_evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect Hexagon (QDSP6) code and penalize RL78.
///
/// Hexagon uses 32-bit LE instructions in packets of 1-4. Packet end markers
/// are in bits 15:14 of each word. The most distinctive patterns:
/// - Bits 15:14 = 0b11 marks end-of-packet (very common ~25% of insns)
/// - JUMPR LR = 0x529CC000 or similar JR patterns
/// - ALLOCFRAME = 0xA09DC000 range
fn detect_hexagon_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 128 {
        return 1.0;
    }

    let check_len = data.len().min(8192);
    let mut end_of_packet: u32 = 0;
    let mut jumpr_lr: u32 = 0;

    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // End-of-packet marker: bits 15:14 = 0b11
        if (w >> 14) & 3 == 3 {
            end_of_packet += 1;
        }

        // JUMPR R31 (return): various encodings, but common pattern is
        // opcode with R31 in source field. Look for specific known encodings.
        // 0x529CC000 is one common form, but let's be broader:
        // Hexagon DEALLOC_RETURN = 0x961EC01E or similar
        if (w & 0xFFFFE01F) == 0x529CC000 {
            jumpr_lr += 1;
        }
        // DEALLOC_RETURN variants
        if (w >> 21) == 0x4B0 {
            jumpr_lr += 1;
        }

        i += 4;
    }

    let total_words = (check_len / 4) as f64;
    let mut hex_evidence: u32 = 0;

    // End-of-packet density: in real Hexagon code, ~20-35% of words have EOP
    let eop_density = end_of_packet as f64 / total_words;
    if eop_density > 0.15 && eop_density < 0.45 {
        hex_evidence += 3;
    } else if eop_density > 0.10 {
        hex_evidence += 1;
    }

    if jumpr_lr >= 2 {
        hex_evidence += 2;
    }

    if hex_evidence >= 4 {
        0.05
    } else if hex_evidence >= 3 {
        0.10
    } else if hex_evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect LoongArch code and penalize RL78.
///
/// LoongArch: 32-bit LE fixed-width, JIRL r0,r1,0 (return) = 0x4C000020,
/// BL = 0x54xxxxxx, LU12I.W = 0x14xxxxxx.
fn detect_loongarch_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    let check_len = data.len().min(8192);
    let mut la_ret: u32 = 0;
    let mut la_bl: u32 = 0;
    let mut la_lu12i: u32 = 0;

    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // JIRL r0, r1, 0 = 0x4C000020
        if w == 0x4C000020 {
            la_ret += 1;
        }
        // BL = opcode 0x54 in bits 31:26
        if (w >> 26) == 0x15 {
            la_bl += 1;
        }
        // LU12I.W = opcode 0x14 in bits 31:25
        if (w >> 25) == 0x0A {
            la_lu12i += 1;
        }

        i += 4;
    }

    let mut la_evidence: u32 = 0;

    if la_ret >= 3 {
        la_evidence += 3;
    } else if la_ret >= 1 {
        la_evidence += 2;
    }

    if la_bl >= 5 {
        la_evidence += 2;
    } else if la_bl >= 2 {
        la_evidence += 1;
    }

    if la_lu12i >= 5 {
        la_evidence += 1;
    }

    if la_evidence >= 4 {
        0.05
    } else if la_evidence >= 3 {
        0.10
    } else if la_evidence >= 2 {
        0.25
    } else {
        1.0
    }
}

/// Detect MIPS little-endian code patterns.
///
/// MIPS LE uses fixed 32-bit instructions stored in little-endian byte order.
/// When read byte-by-byte (as RL78 does), MIPS LE instructions produce many
/// bytes that match RL78 opcodes since RL78 covers ~80% of the byte space.
/// This function scans for common MIPS LE instruction patterns at 32-bit
/// alignment.
fn detect_mips_le_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 32 {
        return 1.0;
    }

    let mut mips_evidence = 0u32;
    let mut jr_ra = 0u32; // JR $ra = 0x03E00008
    let mut lui = 0u32; // LUI rt, imm: opcode 0x0F (bits 31:26)
    let mut addiu = 0u32; // ADDIU: opcode 0x09
    let mut lw = 0u32; // LW: opcode 0x23
    let mut sw = 0u32; // SW: opcode 0x2B
    let mut beq_bne = 0u32; // BEQ=0x04, BNE=0x05
    let mut jal = 0u32; // JAL: opcode 0x03
    let mut nop = 0u32; // NOP = 0x00000000

    let mut j = 0;
    while j + 3 < data.len() {
        let w = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
        let opcode = w >> 26;

        if w == 0x03E00008 {
            jr_ra += 1;
        } else if w == 0x00000000 {
            nop += 1;
        } else {
            match opcode {
                0x0F => {
                    lui += 1;
                }
                0x09 => {
                    addiu += 1;
                }
                0x23 => {
                    lw += 1;
                }
                0x2B => {
                    sw += 1;
                }
                0x04 | 0x05 => {
                    beq_bne += 1;
                }
                0x03 => {
                    jal += 1;
                }
                _ => {}
            }
        }
        j += 4;
    }

    // Build evidence from pattern counts
    if jr_ra >= 1 {
        mips_evidence += 3;
    }
    if lui >= 3 {
        mips_evidence += 2;
    } else if lui >= 1 {
        mips_evidence += 1;
    }
    if addiu >= 3 {
        mips_evidence += 2;
    } else if addiu >= 1 {
        mips_evidence += 1;
    }
    if lw >= 3 {
        mips_evidence += 1;
    }
    if sw >= 3 {
        mips_evidence += 1;
    }
    if beq_bne >= 2 {
        mips_evidence += 1;
    }
    if jal >= 1 {
        mips_evidence += 1;
    }

    // Also check overall fraction of decoded MIPS instructions
    let total_words = (data.len() / 4).max(1);
    let mips_total = jr_ra + lui + addiu + lw + sw + beq_bne + jal + nop;
    let mips_fraction = mips_total as f64 / total_words as f64;
    if mips_fraction > 0.3 {
        mips_evidence += 2;
    }

    if mips_evidence >= 6 {
        0.05
    } else if mips_evidence >= 4 {
        0.10
    } else if mips_evidence >= 3 {
        0.25
    } else {
        1.0
    }
}
