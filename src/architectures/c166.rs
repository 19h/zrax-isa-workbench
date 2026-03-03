//! Heuristic scoring for Infineon/Siemens C166 (C16x/ST10) architecture.
//!
//! The C166 is a 16-bit **little-endian** microcontroller family developed by
//! Siemens (later Infineon), widely used in automotive ECUs (Bosch ME7, Simos 3,
//! EDC15, etc.). STMicroelectronics second-sourced the family as the ST10.
//!
//! Key characteristics for heuristic detection:
//! - **Little-endian** byte ordering
//! - **Fixed instruction widths**: exactly 2 or 4 bytes (never 1 or 3)
//! - **Opcode in first byte**: the first byte of every instruction is the opcode
//! - **16-bit general-purpose registers**: R0–R15 (with byte halves RL0-RL7, RH0-RH7)
//! - **Segmented memory model**: DPP (Data Page Pointer) registers, EXTS/EXTR for
//!   extended segment access — unique to C166, no other ISA has these
//! - **Distinctive opcodes**: RET=0xCB, RETS=0xDB, NOP=0xCC, PUSH=0xEC, POP=0xFC,
//!   CALLR=0xBB, CALLI=0xCA, CALLS=0xDA, JMPA=0xEA, JMPS=0xFA, EXTS=0xD7, EXTR=0xD1
//! - **JMPR/CALLR encoding**: lower nibble 0xD or 0xB with condition code in upper nibble
//! - **Bit operations**: BSET=0x_F, BCLR=0x_E, JB=0x8A, JNB=0x9A, BFLDL=0x0A, BFLDH=0x1A
//! - **SFR (Special Function Register) area**: addresses 0xFE00-0xFFFF, with I/O ports at
//!   0xFFC0+ matching exact C167 datasheet addresses
//!
//! References:
//! - Infineon C167CR/CS User Manual (C166S V2 Core)
//! - Keil A166 Macro Assembler documentation
//! - ST10 Flash Family Reference Manual (STMicroelectronics)
//! - C167BootTool project (verified .a66 source ↔ .bin binary correspondence)

use std::cmp;

/// Score raw data as C166/C167/ST10 code.
///
/// The scorer walks through data in 2-byte steps (C166 instructions are always
/// 2 or 4 bytes), reading the opcode from the first byte and the operand/register
/// selector from the second byte. It classifies each opcode, assigns per-instruction
/// scores weighted by distinctiveness, and applies structural bonuses for patterns
/// characteristic of real C166 firmware.
///
/// Returns a non-negative score (clamped at 0).
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 16 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut i: usize = 0;

    // Structural counters
    let mut ret_count: u32 = 0; // RET (0xCB)
    let mut rets_count: u32 = 0; // RETS (0xDB) — segmented return
    let mut callr_count: u32 = 0; // CALLR (0xBB)
    let mut calli_count: u32 = 0; // CALLI (0xCA)
    let mut calls_count: u32 = 0; // CALLS (0xDA) — segmented call
    let mut jmpr_count: u32 = 0; // JMPR cc, rel (0x_D)
    let mut jmpa_count: u32 = 0; // JMPA (0xEA)
    let mut jmps_count: u32 = 0; // JMPS (0xFA) — segmented jump
    let mut push_count: u32 = 0; // PUSH (0xEC)
    let mut pop_count: u32 = 0; // POP (0xFC)
    let mut exts_count: u32 = 0; // EXTS (0xD7) — unique to C166
    let mut extr_count: u32 = 0; // EXTR (0xD1) — unique to C166
    let mut bset_count: u32 = 0; // BSET (0x_F)
    let mut bclr_count: u32 = 0; // BCLR (0x_E where bit ops)
    let mut bfld_count: u32 = 0; // BFLDL/BFLDH (0x0A/0x1A)
    let mut jb_jnb_count: u32 = 0; // JB/JNB (0x8A/0x9A)
    let mut nop_count: u32 = 0; // NOP (0xCC)
    let mut mov_count: u32 = 0; // MOV variants
    let mut cmp_count: u32 = 0; // CMP variants
    let mut add_sub_count: u32 = 0; // ADD/SUB/ADDB/SUBB
    let mut logic_count: u32 = 0; // AND/OR/XOR
    let mut shift_count: u32 = 0; // SHL/SHR/ROL/ROR
    let mut sfr_ref_count: u32 = 0; // References to SFR area (0xFExx/0xFFxx)
    let mut valid_insn_count: u32 = 0;
    let mut invalid_count: u32 = 0;
    let mut zero_word_count: u32 = 0;
    let mut ff_word_count: u32 = 0;

    while i + 1 < data.len() {
        let opcode = data[i];
        let operand = data[i + 1];

        // Handle zero words — not a valid C166 instruction (0x0000 = ADD R0, R0,
        // which is valid but semantically a NOP. In practice, zero-filled regions
        // are padding, not code.)
        if opcode == 0x00 && operand == 0x00 {
            zero_word_count += 1;
            if zero_word_count <= 2 {
                total_score -= 1;
            } else {
                total_score -= 3;
            }
            i += 2;
            continue;
        }
        // Handle 0xFFFF words (erased flash)
        if opcode == 0xFF && operand == 0xFF {
            ff_word_count += 1;
            if ff_word_count <= 2 {
                total_score -= 1;
            } else {
                total_score -= 3;
            }
            i += 2;
            continue;
        }
        zero_word_count = 0;
        ff_word_count = 0;

        let (insn_score, insn_len) = score_c166_instruction(opcode, operand, data, i);
        total_score += insn_score;

        if insn_score > 0 {
            valid_insn_count += 1;
        } else if insn_score < -1 {
            invalid_count += 1;
        }

        // Update structural counters
        match opcode {
            0xCB => ret_count += 1,
            0xDB => rets_count += 1,
            0xBB => callr_count += 1,
            0xCA => calli_count += 1,
            0xDA => calls_count += 1,
            0xEA => jmpa_count += 1,
            0xFA => jmps_count += 1,
            0xD7 => exts_count += 1,
            0xD1 => extr_count += 1,
            0xEC => push_count += 1,
            0xFC => pop_count += 1,
            0xCC => nop_count += 1,
            0x0A => bfld_count += 1,   // BFLDL
            0x1A => bfld_count += 1,   // BFLDH
            0x8A => jb_jnb_count += 1, // JB
            0x9A => jb_jnb_count += 1, // JNB
            _ => {
                let lo_nib = opcode & 0x0F;
                match lo_nib {
                    0x0D => jmpr_count += 1,                   // JMPR cc, rel
                    0x0F if opcode >= 0x0F => bset_count += 1, // BSET bitaddr
                    0x0E if opcode >= 0x0E && (opcode >> 4) <= 0x0F => bclr_count += 1, // BCLR bitaddr
                    _ => {}
                }
            }
        }

        // Track MOV variants
        match opcode {
            0xF0 | 0xF2 | 0xF4 | 0xF6 | 0xE0 | 0xE6 | 0xE7 | 0xA0 | 0xA8 | 0xB8 | 0x88 | 0x98
            | 0xC8 | 0xD0 | 0xB0 | 0xC0 => mov_count += 1,
            _ => {}
        }

        // Track CMP variants
        match opcode {
            0x40 | 0x41 | 0x42 | 0x44 | 0x46 | 0x48 | 0x49 => cmp_count += 1,
            0x80 | 0x90 | 0xA0 => {} // CMPI/CMPD counted separately
            _ => {}
        }

        // Track ADD/SUB
        match opcode {
            0x00 | 0x02 | 0x04 | 0x06 | 0x08 => add_sub_count += 1, // ADD variants
            0x10 | 0x12 | 0x14 | 0x16 | 0x18 => add_sub_count += 1, // ADDB variants
            0x20 | 0x22 | 0x24 | 0x26 | 0x28 => add_sub_count += 1, // SUB variants
            0x30 | 0x32 | 0x34 | 0x36 | 0x38 => add_sub_count += 1, // SUBB variants
            _ => {}
        }

        // Track logic
        match opcode {
            0x60 | 0x62 | 0x64 | 0x66 | 0x68 => logic_count += 1, // AND
            0x70 | 0x72 | 0x74 | 0x76 | 0x78 => logic_count += 1, // OR
            0x50 | 0x52 | 0x54 | 0x56 | 0x58 => logic_count += 1, // XOR
            _ => {}
        }

        // Track shifts
        match opcode {
            0x5C | 0x7C | 0x6C | 0x4C | 0xAC | 0xBC => shift_count += 1,
            _ => {}
        }

        // Check for SFR references in 4-byte instructions with imm16
        // SFR area is 0xFE00-0xFFFF, appearing as the 16-bit operand in
        // bytes [i+2..i+4] of 4-byte instructions (little-endian)
        if insn_len == 4 && i + 3 < data.len() {
            let imm16 = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            if imm16 >= 0xFE00 {
                sfr_ref_count += 1;
            }
        }

        i += insn_len;
    }

    // ─── Structural bonuses ───
    let total_insns = valid_insn_count + invalid_count;
    if total_insns > 10 {
        let valid_ratio = valid_insn_count as f64 / total_insns as f64;

        // High valid instruction ratio — tightened threshold
        if valid_ratio > 0.70 && total_insns > 100 {
            total_score += (valid_insn_count as i64) / 8;
        }

        // RET (0xCB) — near return
        if ret_count > 4 {
            total_score += (ret_count as i64) * 3;
        }

        // RETS (0xDB) — segmented return, distinctive of C166
        if rets_count > 0 {
            total_score += (rets_count as i64) * 5;
        }

        // CALLR (0xBB) — relative call
        if callr_count > 4 {
            total_score += (callr_count as i64) * 3;
        }

        // CALLS (0xDA) — segmented call
        if calls_count > 0 {
            total_score += (calls_count as i64) * 4;
        }

        // CALLI (0xCA) — indirect call
        if calli_count > 0 {
            total_score += (calli_count as i64) * 3;
        }

        // JMPR (0x_D) — conditional relative jump
        if jmpr_count > 5 {
            total_score += (jmpr_count as i64) * 2;
        }

        // EXTS/EXTR (0xD7/0xD1) — unique to C166
        if exts_count > 0 {
            total_score += (exts_count as i64) * 5;
        }
        if extr_count > 0 {
            total_score += (extr_count as i64) * 5;
        }

        // PUSH/POP (0xEC/0xFC)
        if push_count > 2 {
            total_score += (push_count as i64) * 2;
        }
        if pop_count > 2 {
            total_score += (pop_count as i64) * 2;
        }

        // BSET/BCLR — bit operations
        if bset_count + bclr_count > 2 {
            total_score += ((bset_count + bclr_count) as i64) * 2;
        }

        // BFLDL/BFLDH — bit field operations
        if bfld_count > 0 {
            total_score += (bfld_count as i64) * 3;
        }

        // JB/JNB — bit test and jump
        if jb_jnb_count > 0 {
            total_score += (jb_jnb_count as i64) * 3;
        }

        // SFR references
        if sfr_ref_count > 3 {
            total_score += (sfr_ref_count as i64) * 4;
        }

        // MOV instructions — raised threshold
        if mov_count > 8 {
            total_score += (mov_count as i64) * 1;
        }

        // Combined structural signature — require more features
        let signature_features = [
            ret_count > 3,                                      // Function returns
            callr_count > 3 || calls_count > 0,                 // Subroutine calls
            jmpr_count > 5,                                     // Conditional branches
            push_count > 2 && pop_count > 2,                    // Stack operations
            mov_count > 8,                                      // Data movement
            exts_count > 0 || extr_count > 0,                   // Segmented operations (unique!)
            sfr_ref_count > 3,                                  // Hardware register access
            bset_count > 0 || bclr_count > 0 || bfld_count > 0, // Bit operations
            rets_count > 0 || calls_count > 0,                  // Segmented call/return
        ];
        let feature_count = signature_features.iter().filter(|&&f| f).count();
        if feature_count >= 7 {
            total_score += (valid_insn_count as i64) / 4;
        } else if feature_count >= 5 {
            total_score += (valid_insn_count as i64) / 6;
        } else if feature_count >= 4 {
            total_score += (valid_insn_count as i64) / 8;
        }

        // ─── RET;NOP pattern detection ───
        if data.len() >= 4 {
            let mut ret_nop_count: u32 = 0;
            let mut j = 0;
            while j + 3 < data.len() {
                if data[j] == 0xCB
                    && data[j + 1] == 0x00
                    && data[j + 2] == 0xCC
                    && data[j + 3] == 0x00
                {
                    ret_nop_count += 1;
                }
                if data[j] == 0xDB
                    && data[j + 1] == 0x00
                    && data[j + 2] == 0xCC
                    && data[j + 3] == 0x00
                {
                    ret_nop_count += 1;
                }
                j += 2;
            }
            if ret_nop_count > 0 {
                total_score += (ret_nop_count as i64) * 5;
            }
        }
    }

    // ─── Cross-architecture penalty: SuperH firmware detection ───
    //
    // C166 (little-endian 16-bit) reads SH (big-endian 16-bit) firmware as
    // quasi-random 2-byte sequences. Many of the common SH instruction byte
    // values (0x00-0x09 range, 0x60-0x6F range, etc.) coincidentally map to
    // valid C166 opcodes, causing false-positive accumulation. We detect SH
    // firmware by its distinctive vector table structures and apply a heavy
    // penalty.
    let tc_penalty = detect_tricore_cross_arch_penalty(data);
    if tc_penalty < 1.0 {
        total_score = (total_score as f64 * tc_penalty) as i64;
    }
    let sh_penalty = detect_sh_cross_arch_penalty(data);
    if sh_penalty > 0.0 && sh_penalty < 1.0 {
        total_score = (total_score as f64 * sh_penalty) as i64;
    }

    // ─── Structural evidence requirement ───
    let call_total = callr_count + calls_count + calli_count;
    let ret_total = ret_count + rets_count;
    if data.len() > 2048 {
        if ret_total < 2 || call_total < 2 {
            return 0;
        }
    } else if data.len() > 512 {
        if ret_total == 0 || call_total == 0 {
            return 0;
        }
    }

    // ─── Cross-architecture penalties ───
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
    let avr_penalty = detect_avr_cross_arch_penalty(data);
    if avr_penalty < 1.0 {
        total_score = (total_score as f64 * avr_penalty) as i64;
    }
    let hex_penalty = detect_hexagon_cross_arch_penalty(data);
    if hex_penalty < 1.0 {
        total_score = (total_score as f64 * hex_penalty) as i64;
    }

    cmp::max(0, total_score)
}

/// Detect SuperH firmware structural signatures and return a multiplier
/// penalty for the C166 score. Returns 1.0 (no penalty) if no SH evidence
/// is found, or a value < 1.0 if SH patterns are detected.
fn detect_sh_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    // ─── Check 1: SH7058 sparse vector table (16-byte stride) ───
    // Pattern: [4-byte 0xFF00xxxx address][12 bytes 0xFF] repeated 4 times
    if data.len() >= 0x80 {
        let mut sparse_valid = 0u32;
        let mut sparse_ff_padding = 0u32;

        for entry_idx in 0..4 {
            let off = entry_idx * 16;
            if off + 16 > data.len() {
                break;
            }
            let addr = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            let padding_all_ff = data[off + 4..off + 16].iter().all(|&b| b == 0xFF);

            if is_sh_vector_addr(addr) {
                sparse_valid += 1;
            }
            if padding_all_ff {
                sparse_ff_padding += 1;
            }
        }

        if sparse_valid >= 2 && sparse_ff_padding >= 3 {
            return 0.08; // Definitely SH7058 firmware
        }
    }

    // ─── Check 2: Standard (packed) SH vector table at offset 0 ───
    if data.len() >= 32 {
        let mut packed_valid = 0u32;
        let check_count = (data.len().min(256) / 4).min(16);

        for v in 0..check_count {
            let off = v * 4;
            let addr = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            if is_sh_vector_addr(addr) && (addr & 1) == 0 {
                packed_valid += 1;
            }
        }

        if packed_valid >= check_count as u32 * 3 / 4 && packed_valid >= 6 {
            return 0.15; // Strong SH vector table
        }
    }

    // ─── Check 3: SH compound delay-slot patterns ───
    // RTS;NOP = 0x000B 0x0009 as big-endian bytes
    if data.len() >= 1024 {
        let mut sh_compounds = 0u32;
        let end = data.len() - 3;
        let mut j = 2usize;
        while j < end {
            if data[j] == 0x00 && data[j + 1] == 0x09 {
                // Check preceding halfword for SH control-flow instruction
                let prev_hi = data[j - 2];
                let prev_lo = data[j - 1];
                let is_rts_nop = prev_hi == 0x00 && prev_lo == 0x0B;
                let is_rte_nop = prev_hi == 0x00 && prev_lo == 0x2B;
                let is_jmp_nop = (prev_hi & 0xF0) == 0x40 && prev_lo == 0x2B;
                let is_jsr_nop = (prev_hi & 0xF0) == 0x40 && prev_lo == 0x0B;
                let is_bra_nop = (prev_hi & 0xF0) == 0xA0;
                let is_bsr_nop = (prev_hi & 0xF0) == 0xB0;

                if is_rts_nop || is_rte_nop || is_jmp_nop || is_jsr_nop || is_bra_nop || is_bsr_nop
                {
                    sh_compounds += 1;
                }
            }
            j += 2;
        }

        let density = sh_compounds as f64 / (data.len() as f64 / 4.0);
        if sh_compounds >= 20 && density > 0.0005 {
            return 0.15; // Strong SH delay-slot evidence
        } else if sh_compounds >= 8 {
            return 0.40; // Moderate SH evidence
        }
    }

    1.0 // No SH evidence
}

/// Check if a 32-bit address is a valid SuperH vector table entry.
#[inline]
fn is_sh_vector_addr(addr: u32) -> bool {
    if addr == 0x00000000 || addr == 0xFFFFFFFF {
        return false;
    }
    let is_rom = addr >= 0x00000040 && addr < 0x01000000;
    let is_rom_alias = addr >= 0xFF000000 && addr < 0xFF100000;
    let is_ram = addr >= 0xFFF80000 && addr < 0xFFFFFF00;
    is_rom || is_rom_alias || is_ram
}

/// Score a single C166 instruction at position `i` in `data`.
///
/// C166 instructions are either 2 bytes or 4 bytes. The opcode is always
/// the first byte. The second byte encodes register selectors, addressing
/// modes, or condition codes. For 4-byte instructions, bytes 3-4 are a
/// 16-bit immediate or memory address (little-endian).
///
/// Returns `(score, instruction_length_in_bytes)`.
fn score_c166_instruction(opcode: u8, operand: u8, data: &[u8], i: usize) -> (i64, usize) {
    // ─── Highly distinctive inherent (2-byte) instructions ───
    match opcode {
        // RET — near return. Second byte should be 0x00.
        0xCB => {
            if operand == 0x00 {
                return (5, 2);
            }
            return (1, 2);
        }
        // RETS — segmented return (far return). Distinctive.
        0xDB => {
            if operand == 0x00 {
                return (6, 2);
            }
            return (2, 2);
        }
        // NOP — 0xCC 0x00
        0xCC => {
            if operand == 0x00 {
                return (2, 2);
            }
            return (1, 2);
        }
        // PUSH reg
        0xEC => {
            if (operand & 0xF0) == 0xF0 {
                return (3, 2);
            }
            return (1, 2);
        }
        // POP reg
        0xFC => {
            if (operand & 0xF0) == 0xF0 {
                return (3, 2);
            }
            return (1, 2);
        }
        // CALLR — relative call
        0xBB => {
            return (3, 2);
        }
        _ => {}
    }

    // ─── JMPR cc, rel — conditional relative jump ───
    // Encoding: upper nibble = condition code (0-F), lower nibble = 0xD
    // The second byte is a signed 8-bit relative offset.
    if (opcode & 0x0F) == 0x0D {
        let cc = opcode >> 4;
        // All 16 condition codes are valid (0=cc_UC to F=cc_NV)
        // cc_UC (unconditional) and common conditions score higher
        let cc_score = match cc {
            0x00 => 3,        // cc_UC (unconditional jump)
            0x02 | 0x03 => 3, // cc_Z / cc_NZ (equal/not equal)
            0x06 | 0x07 => 2, // cc_C / cc_NC (carry/no carry)
            0x04 | 0x05 => 2, // cc_V / cc_NV
            _ => 2,
        };
        return (cc_score, 2);
    }

    // ─── BSET bitaddr.q / BCLR bitaddr.q ───
    // BSET: upper nibble = bit number (q), lower nibble = 0xF
    // BCLR: upper nibble = bit number (q), lower nibble = 0xE
    // Second byte encodes the bit-addressable SFR/register byte address
    if (opcode & 0x0F) == 0x0F && opcode >= 0x0F {
        // BSET
        return (3, 2);
    }
    if (opcode & 0x0F) == 0x0E && opcode >= 0x0E {
        // BCLR
        return (3, 2);
    }

    // ─── EXTS — extended segment override (UNIQUE to C166!) ───
    // 0xD7 with various second bytes for different forms
    if opcode == 0xD7 {
        // EXTS #seg, #pag_cnt — 4-byte form
        if i + 3 < data.len() {
            return (8, 4);
        }
        return (4, 2);
    }

    // ─── EXTR — extended register bank (UNIQUE to C166!) ───
    if opcode == 0xD1 {
        return (8, 2);
    }

    // ─── 4-byte instructions with immediate/memory operands ───

    // MOV Rn, #imm16 (0xE6)
    if opcode == 0xE6 {
        if i + 3 < data.len() {
            return (2, 4);
        }
        return (-1, 2);
    }

    // MOVB RLn, #imm8 (0xE7)
    if opcode == 0xE7 {
        return (2, 2);
    }

    // MOV Rn, #imm4 (0xE0)
    if opcode == 0xE0 {
        return (2, 2);
    }

    // MOV Rn, Rm (0xF0)
    if opcode == 0xF0 {
        return (2, 2);
    }

    // MOV Rn, [mem] (0xF2)
    if opcode == 0xF2 {
        if i + 3 < data.len() {
            return (2, 4);
        }
        return (-1, 2);
    }

    // MOVB Rn, Rm (0xF4)
    if opcode == 0xF4 {
        return (2, 2);
    }

    // MOV [mem], Rn (0xF6)
    if opcode == 0xF6 {
        if i + 3 < data.len() {
            return (2, 4);
        }
        return (-1, 2);
    }

    // MOVB [mem], Rn (0xF7)
    if opcode == 0xF7 {
        if i + 3 < data.len() {
            return (2, 4);
        }
        return (-1, 2);
    }

    // ─── CALLI/CALLS/JMPA/JMPS — 4-byte control flow ───
    match opcode {
        0xCA => {
            // CALLI cc, [Rn] — indirect call with condition
            return (4, 2);
        }
        0xDA => {
            // CALLS seg, addr — segmented call (4 bytes)
            if i + 3 < data.len() {
                return (5, 4);
            }
            return (-1, 2);
        }
        0xEA => {
            // JMPA cc, addr — absolute jump with condition (4 bytes)
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        0xFA => {
            // JMPS seg, addr — segmented jump (4 bytes)
            if i + 3 < data.len() {
                return (4, 4);
            }
            return (-1, 2);
        }
        _ => {}
    }

    // ─── JB/JNB/JBC/JNBS — bit test and jump (4 bytes) ───
    match opcode {
        0x8A => {
            // JB bitaddr.q, rel — jump if bit set
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        0x9A => {
            // JNB bitaddr.q, rel — jump if bit not set
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        0xAA => {
            // JBC bitaddr.q, rel — jump if bit set and clear it
            if i + 3 < data.len() {
                return (4, 4);
            }
            return (-1, 2);
        }
        0xBA => {
            // JNBS bitaddr.q, rel — jump if bit not set and set it
            if i + 3 < data.len() {
                return (4, 4);
            }
            return (-1, 2);
        }
        _ => {}
    }

    // ─── BFLDL/BFLDH — bit field operations (4 bytes, distinctive) ───
    if opcode == 0x0A {
        // BFLDL bitoff, #mask, #data
        if i + 3 < data.len() {
            return (4, 4);
        }
        return (-1, 2);
    }
    if opcode == 0x1A {
        // BFLDH bitoff, #mask, #data
        if i + 3 < data.len() {
            return (4, 4);
        }
        return (-1, 2);
    }

    // ─── ALU operations (2-byte register-register forms) ───
    // Pattern: opcode encodes operation, operand encodes Rn/Rm
    // High nibble of operand = destination reg, low nibble = source reg
    match opcode {
        // ADD Rn, Rm
        0x00 => return (1, 2),
        // ADDB RLn, RLm
        0x10 => return (1, 2),
        // SUB Rn, Rm
        0x20 => return (1, 2),
        // SUBB RLn, RLm
        0x30 => return (1, 2),
        // CMP Rn, Rm
        0x40 => return (2, 2),
        // CMPB RLn, RLm
        0x41 => return (1, 2),
        // XOR Rn, Rm
        0x50 => return (1, 2),
        // AND Rn, Rm
        0x60 => return (1, 2),
        // OR Rn, Rm
        0x70 => return (1, 2),
        _ => {}
    }

    // ─── ALU operations with register indirect ───
    match opcode {
        // ADD Rn, [Rm] / ADD Rn, [Rm+]
        0x08 | 0x09 => return (2, 2),
        // ADDB
        0x18 | 0x19 => return (1, 2),
        // SUB
        0x28 | 0x29 => return (2, 2),
        // SUBB
        0x38 | 0x39 => return (1, 2),
        // CMP
        0x48 | 0x49 => return (2, 2),
        // XOR
        0x58 | 0x59 => return (1, 2),
        // AND
        0x68 | 0x69 => return (1, 2),
        // OR
        0x78 | 0x79 => return (1, 2),
        _ => {}
    }

    // ─── ALU with immediate 16 (4-byte forms) ───
    // Pattern: base_op + 0x06 for word, base_op + 0x07 for byte
    match opcode {
        0x06 | 0x16 | 0x26 | 0x36 | 0x46 | 0x56 | 0x66 | 0x76 => {
            // ADD/ADDB/SUB/SUBB/CMP/XOR/AND/OR Rn, #imm16
            if i + 3 < data.len() {
                return (2, 4);
            }
            return (-1, 2);
        }
        0x07 | 0x17 | 0x27 | 0x37 | 0x47 | 0x57 | 0x67 | 0x77 => {
            // Byte immediate forms
            return (1, 2);
        }
        _ => {}
    }

    // ─── ALU with memory operand (4-byte forms) ───
    match opcode {
        0x02 | 0x04 | 0x12 | 0x14 | 0x22 | 0x24 | 0x32 | 0x34 | 0x42 | 0x44 | 0x52 | 0x54
        | 0x62 | 0x64 | 0x72 | 0x74 => {
            if i + 3 < data.len() {
                return (2, 4);
            }
            return (-1, 2);
        }
        _ => {}
    }

    // ─── MOV indirect forms ───
    match opcode {
        // MOV [Rn], Rm
        0x88 => return (2, 2),
        // MOV Rn, [Rm+]
        0x98 => return (2, 2),
        // MOV [-Rn], Rm
        0xA8 => return (2, 2),
        // MOV Rn, [Rm]
        0xB8 => return (2, 2),
        // MOV [Rm], Rn (alternate encoding)
        0xC8 => return (2, 2),
        // MOVB indirect forms
        0x89 | 0x99 | 0xA9 | 0xB9 | 0xC9 => return (1, 2),
        _ => {}
    }

    // ─── MOVBZ / MOVBS (zero/sign extend) ───
    match opcode {
        0xB0 | 0xB5 => return (2, 2), // MOVBZ
        0xC0 | 0xC5 => return (2, 2), // MOVBS
        0xD0 => return (2, 2),        // MOV byte indirect variants
        _ => {}
    }

    // ─── Shift/rotate operations ───
    match opcode {
        0x5C => return (2, 2), // SHL Rn, #cnt
        0x7C => return (2, 2), // SHR Rn, #cnt
        0x6C => return (2, 2), // ROL Rn, #cnt
        0x4C => return (2, 2), // ROR Rn, #cnt
        0xAC => return (2, 2), // ASHR Rn, #cnt
        0xBC => return (2, 2), // PRIOR — find first bit
        _ => {}
    }

    // ─── CMPI/CMPD — compare and increment/decrement (unique to C166!) ───
    match opcode {
        0x80 => return (3, 2), // CMPI1 Rn, #imm4
        0x82 => {
            // CMPI1 Rn, #imm16
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        0x84 => {
            // CMPI2 Rn, #imm16
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        0x90 => return (3, 2), // CMPD1 Rn, #imm4
        0x92 => {
            // CMPD1 Rn, #imm16
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        0x94 => {
            // CMPD2 Rn, #imm16
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        _ => {}
    }

    // ─── MUL/DIV ───
    match opcode {
        0x0B => return (2, 2), // MUL Rn, Rm
        0x1B => return (2, 2), // MULU Rn, Rm
        0x4B => return (2, 2), // DIV Rwn
        0x5B => return (2, 2), // DIVU Rwn
        0x6B => return (2, 2), // DIVL Rwn
        0x7B => return (2, 2), // DIVLU Rwn
        _ => {}
    }

    // ─── Miscellaneous ───
    match opcode {
        // NEG Rn
        0x81 => return (1, 2),
        // CPL Rn (complement)
        0x91 => return (1, 2),
        // NEGB
        0xA1 => return (1, 2),
        // CPLB
        0xB1 => return (1, 2),
        // TRAP — software interrupt
        0x9B => return (2, 2),
        // RETI — return from interrupt
        0xFB => return (4, 2),
        // IDLE — enter idle mode
        0x87 => {
            if operand == 0x78 {
                return (3, 2);
            }
            return (1, 2);
        }
        // SRST — software reset
        0xB7 => {
            if operand == 0x48 {
                return (3, 2);
            }
            return (1, 2);
        }
        // SRVWDT — service watchdog timer
        0xA7 => {
            if operand == 0x58 {
                return (3, 2);
            }
            return (1, 2);
        }
        // DISWDT — disable watchdog timer
        0xA5 => {
            if operand == 0x5A {
                return (4, 2);
            }
            return (1, 2);
        }
        // EINIT — end of initialization
        0xB5 => {
            if operand == 0x4A {
                return (4, 2);
            }
            return (1, 2);
        }
        // ATOMIC/EXTS prefix sequences
        0xD4 => return (2, 2), // ATOMIC
        // SCXT — switch context
        0xC6 => {
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        // PCALL — push and call
        0xE2 => {
            if i + 3 < data.len() {
                return (3, 4);
            }
            return (-1, 2);
        }
        _ => {}
    }

    // ─── MOV with memory address (4-byte forms, 0x_2 and 0x_4 patterns) ───
    match opcode {
        0xA2 | 0xA4 | 0xB2 | 0xB4 | 0xC2 | 0xC4 | 0xD2 | 0xD4 | 0xE2 | 0xE4 => {
            if i + 3 < data.len() {
                return (2, 4);
            }
            return (-1, 2);
        }
        _ => {}
    }

    // ─── Remaining even opcodes: DO NOT award points ───
    // Previously this catch-all gave +2/+3 to any opcode with low nibble
    // 0x02, 0x04, 0x06, 0x0A. This matches ~25% of all possible opcodes
    // and causes massive false positives. The specific C166 instructions
    // with these low nibbles have already been matched above.
    let lo = opcode & 0x0F;
    if lo == 0x02 || lo == 0x04 || lo == 0x06 {
        if i + 3 < data.len() {
            return (0, 4); // Neutral: possibly valid but not distinctive
        }
        return (0, 2);
    }

    if lo == 0x0A {
        if i + 3 < data.len() {
            return (0, 4); // Neutral
        }
        return (0, 2);
    }

    // ─── Everything else: default 2-byte instruction with ZERO score ───
    // C166 has many valid 2-byte opcodes, so most bytes are technically valid.
    // However, giving +1 for all "common" opcode ranges causes massive false
    // positives on non-C166 data (SH, HCS12, etc.) because almost any byte
    // value falls in the "valid" range. Only specifically-matched instruction
    // patterns above should contribute positive scores.
    //
    // Uncommon/reserved byte patterns get a small penalty.
    match opcode {
        // Known invalid or very rare C166 opcodes
        0x0C | 0x1C | 0x2C | 0x3C => (-2, 2), // Undefined in C166
        0xDD | 0xDE | 0xDF => (-2, 2),        // Reserved
        0xFD | 0xFE | 0xFF => (-2, 2),        // Reserved / erased flash
        // Everything else: neutral (0 score)
        _ => (0, 2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c166_ret() {
        // RET (0xCB 0x00) repeated
        let code = [
            0xCB, 0x00, // RET
            0xCB, 0x00, // RET
            0xCB, 0x00, // RET
            0xCB, 0x00, // RET
            0xCB, 0x00, // RET
            0xCB, 0x00, // RET
            0xCB, 0x00, // RET
            0xCB, 0x00, // RET
        ];
        let s = score(&code);
        assert!(s > 0, "RET stream should score positively, got {}", s);
    }

    #[test]
    fn test_c166_bset_bclr_ret() {
        // From gremlindriver.bin: BSET DP6.3, RET, BCLR DP6.3, RET
        let code = [
            0x3F, 0xE7, // BSET DP6.3
            0xCB, 0x00, // RET
            0x3E, 0xE7, // BCLR DP6.3
            0xCB, 0x00, // RET
            0x3E, 0xE6, // BCLR P6.3
            0xCB, 0x00, // RET
            0x3F, 0xE6, // BSET P6.3
            0xCB, 0x00, // RET
        ];
        let s = score(&code);
        assert!(s > 10, "BSET/BCLR/RET should score well, got {}", s);
    }

    #[test]
    fn test_c166_push_pop() {
        // PUSH R3, PUSH R4, ... work ... POP R4, POP R3, RET
        let code = [
            0xEC, 0xF3, // PUSH R3
            0xEC, 0xF4, // PUSH R4
            0xE6, 0xF5, 0x42, 0x00, // MOV R5, #0042h
            0xBB, 0x10, // CALLR +16
            0xFC, 0xF4, // POP R4
            0xFC, 0xF3, // POP R3
            0xCB, 0x00, // RET
            0xCC, 0x00, // NOP
        ];
        let s = score(&code);
        assert!(s > 10, "Push/pop/call pattern should score well, got {}", s);
    }

    #[test]
    fn test_c166_exts() {
        // EXTS is unique to C166 — very strong signal
        let code = [
            0xD7, 0x00, 0x01, 0x00, // EXTS #seg, #1
            0xF2, 0xF0, 0x00, 0x80, // MOV R0, [8000h]
            0xD7, 0x00, 0x01, 0x00, // EXTS #seg, #1
            0xF6, 0xF0, 0x02, 0x80, // MOV [8002h], R0
            0xCB, 0x00, // RET
            0xCC, 0x00, // NOP
        ];
        let s = score(&code);
        assert!(s > 20, "EXTS usage should score very well, got {}", s);
    }

    #[test]
    fn test_c166_calls_rets() {
        // Segmented call/return
        let code = [
            0xDA, 0x00, 0x00, 0x80, // CALLS seg, 8000h
            0xDA, 0x00, 0x00, 0x90, // CALLS seg, 9000h
            0xDB, 0x00, // RETS
            0xCC, 0x00, // NOP
            0xDA, 0x00, 0x00, 0xA0, // CALLS seg, A000h
            0xDB, 0x00, // RETS
        ];
        let s = score(&code);
        assert!(s > 20, "CALLS/RETS should score very well, got {}", s);
    }

    #[test]
    fn test_c166_jmpr() {
        // JMPR with various condition codes
        let code = [
            0x0D, 0x08, // JMPR cc_UC, +8  (unconditional)
            0x2D, 0x04, // JMPR cc_Z, +4   (if zero)
            0x3D, 0x02, // JMPR cc_NZ, +2  (if not zero)
            0xED, 0x10, // JMPR cc_ULT, +16
            0xCB, 0x00, // RET
            0xCC, 0x00, // NOP
            0xCC, 0x00, // NOP
            0xCC, 0x00, // NOP
        ];
        let s = score(&code);
        assert!(s > 10, "JMPR patterns should score well, got {}", s);
    }

    #[test]
    fn test_c166_not_hcs12() {
        // Make sure the Solano HCS12 first bytes don't score well as C166
        // HCS12 code: CLR, JSR ext, etc. (big-endian)
        let code: Vec<u8> = vec![
            0x79, 0x5E, 0x5B, 0x16, 0xBA, 0x86, 0x18, 0x04, 0x5E, 0x84, 0x5E, 0x57, 0xC6, 0x11,
            0x16, 0xCF,
        ];
        let s = score(&code);
        // HC12 code may get some incidental C166 hits but should be modest.
        // On 16 bytes, scores up to ~50 are acceptable (a real C166 binary
        // of comparable size would score much higher).
        assert!(
            s < 60,
            "HCS12 code should not score highly as C166, got {}",
            s
        );
    }

    #[test]
    fn test_c166_real_gremlin_bytes() {
        // First 32 bytes of gremlindriver.bin
        let code = vec![
            0x3F, 0xE7, // BSET DP6.3
            0xCB, 0x00, // RET
            0x3E, 0xE7, // BCLR DP6.3
            0xCB, 0x00, // RET
            0x3E, 0xE6, // BCLR P6.3
            0xCB, 0x00, // RET
            0x3F, 0xE6, // BSET P6.3
            0xCB, 0x00, // RET
            0x00, 0x00, // (padding)
            0x00, 0x00, // (padding)
            0x00, 0x00, // (padding)
            0x00, 0x00, // (padding)
            0x00, 0x00, // (padding)
            0x00, 0x00, // (padding)
            0x00, 0x00, // (padding)
            0x00, 0x00, // (padding)
        ];
        let s = score(&code);
        assert!(s > 10, "Real gremlin driver should score well, got {}", s);
    }

    #[test]
    fn test_c166_real_24c0x_bytes() {
        // First 16 bytes of 24C0xDriver.bin
        let code = vec![
            0xF2, 0xF6, 0xC0, 0xFF, // MOV R6, [FFC0h] (= P2)
            0x66, 0xF6, 0x00, 0x01, // AND R6, #0100h
            0x7C, 0x86, // SHR R6, #8
            0xCB, 0x00, // RET
            0xE0, 0x06, // MOV R6, #0
            0xCB, 0x00, // RET
        ];
        let s = score(&code);
        assert!(s > 10, "Real 24C0x driver should score well, got {}", s);
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
        return 0.05; // 95% penalty
    }
    1.0
}

/// Detect ARM32/Thumb patterns in data.
fn detect_arm_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(2048);

    // ARM32: condition code 0xE (always) in bits [31:28] = byte[3] >> 4
    let mut al_count = 0u32;
    let mut check_count = 0u32;
    let mut j = 0usize;
    while j + 3 < check_len {
        if data[j + 3] >> 4 == 0xE {
            al_count += 1;
        }
        check_count += 1;
        j += 4;
    }
    if check_count > 10 && (al_count as f64 / check_count as f64) > 0.40 {
        return 0.15;
    }

    // Thumb: BX LR (0x4770), PUSH {LR} (0xB5xx), POP {PC} (0xBDxx)
    let mut thumb_sig = 0u32;
    j = 0;
    while j + 1 < check_len {
        let hw = u16::from_le_bytes([data[j], data[j + 1]]);
        if hw == 0x4770 {
            thumb_sig += 3;
        }
        if hw & 0xFF00 == 0xB500 {
            thumb_sig += 2;
        }
        if hw & 0xFF00 == 0xBD00 {
            thumb_sig += 2;
        }
        if hw == 0xBF00 {
            thumb_sig += 1;
        }
        j += 2;
    }
    if thumb_sig >= 8 {
        return 0.15;
    }

    // AArch64: MRS/MSR patterns
    let mut aarch64_sig = 0u32;
    j = 0;
    while j + 3 < check_len {
        let w = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
        let top12 = w >> 20;
        if top12 == 0xD53 || top12 == 0xD51 {
            aarch64_sig += 1;
        }
        // AArch64 RET (0xD65F03C0)
        if w == 0xD65F03C0 {
            aarch64_sig += 3;
        }
        j += 4;
    }
    if aarch64_sig >= 3 {
        return 0.12;
    }

    1.0
}

/// Detect big-endian ISA patterns (MIPS, PowerPC, SPARC, s390x, Hexagon).
fn detect_big_endian_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(2048);
    let mut mips_sig = 0u32;
    let mut ppc_sig = 0u32;
    let mut sparc_sig = 0u32;

    let mut j = 0usize;
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
          // MIPS LE (check both endianness)
        let wle = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
        if wle == 0x03E00008 {
            mips_sig += 3;
        }
        if (wle >> 26) == 0x0F {
            mips_sig += 1;
        }
        // PowerPC
        if w == 0x4E800020 {
            ppc_sig += 3;
        } // BLR
        if w == 0x60000000 {
            ppc_sig += 1;
        } // NOP
        if (w >> 26) == 18 {
            ppc_sig += 1;
        } // B/BL
          // PPC LE
        if wle == 0x4E800020 {
            ppc_sig += 3;
        }
        // SPARC
        if w == 0x81C7E008 {
            sparc_sig += 3;
        } // RET
        if w == 0x01000000 {
            sparc_sig += 1;
        } // NOP
        j += 4;
    }

    let max_sig = mips_sig.max(ppc_sig).max(sparc_sig);
    if max_sig >= 8 {
        return 0.1;
    }
    if max_sig >= 4 {
        return 0.3;
    }

    // s390x
    let mut s390_sig = 0u32;
    j = 0;
    while j + 1 < check_len {
        let hw = u16::from_be_bytes([data[j], data[j + 1]]);
        if hw == 0x07FE {
            s390_sig += 2;
        } // BCR 15,14 (return)
        j += 2;
    }
    if s390_sig >= 6 {
        return 0.15;
    }

    1.0
}

/// Detect x86/x86-64 patterns.
fn detect_x86_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(2048);
    let mut x86_sig = 0u32;

    for j in 0..check_len {
        match data[j] {
            0xC3 => x86_sig += 2, // RET
            0xCC => {
                // C166 NOP is also 0xCC, but in x86 this is INT3
                // Check if this looks like x86 context (preceded by RET or followed by push)
                if j > 0 && data[j - 1] == 0xC3 {
                    x86_sig += 1; // INT3 after RET = common x86 padding
                }
            }
            0x55 => {
                // PUSH EBP — extremely common x86 function prologue
                if j + 2 < check_len && data[j + 1] == 0x89 && data[j + 2] == 0xE5 {
                    x86_sig += 3; // PUSH EBP; MOV EBP, ESP
                }
            }
            0xE8 => x86_sig += 1, // CALL rel32
            _ => {}
        }
    }

    // REX prefixes (0x40-0x4F) followed by common opcodes indicate x86-64
    let mut rex_count = 0u32;
    for j in 0..check_len.saturating_sub(1) {
        if data[j] >= 0x40 && data[j] <= 0x4F {
            let next = data[j + 1];
            if next == 0x89
                || next == 0x8B
                || next == 0x83
                || next == 0x01
                || next == 0x29
                || next == 0x53
                || next == 0x55
                || next == 0x56
                || next == 0x57
            {
                rex_count += 1;
            }
        }
    }
    x86_sig += rex_count;

    if x86_sig >= 10 {
        return 0.12;
    }
    if x86_sig >= 5 {
        return 0.3;
    }

    1.0
}

/// Detect RISC-V patterns.
fn detect_riscv_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(2048);
    let mut riscv_sig = 0u32;

    let mut j = 0usize;
    while j + 3 < check_len {
        let w = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
        // RISC-V JALR x0, x1, 0 (ret) = 0x00008067
        if w == 0x00008067 {
            riscv_sig += 3;
        }
        // RISC-V JAL (opcode = 0x6F)
        if (w & 0x7F) == 0x6F {
            riscv_sig += 1;
        }
        // RISC-V AUIPC (opcode = 0x17)
        if (w & 0x7F) == 0x17 {
            riscv_sig += 1;
        }
        j += 4;
    }

    // Compressed RISC-V: C.JALR, C.JR (16-bit instructions)
    j = 0;
    while j + 1 < check_len {
        let hw = u16::from_le_bytes([data[j], data[j + 1]]);
        // C.JR rs1: [15:12]=1000, [11:7]=rs1, [6:2]=00000, [1:0]=10
        if (hw & 0xF07F) == 0x8002 {
            riscv_sig += 1;
        }
        // C.JALR rs1: [15:12]=1001, [11:7]=rs1, [6:2]=00000, [1:0]=10
        if (hw & 0xF07F) == 0x9002 {
            riscv_sig += 1;
        }
        j += 2;
    }

    if riscv_sig >= 8 {
        return 0.12;
    }
    if riscv_sig >= 4 {
        return 0.3;
    }

    1.0
}

/// Detect AVR code and penalize C166.
fn detect_avr_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }
    let check_len = data.len().min(8192);
    let mut avr_ret: u32 = 0;
    let mut avr_reti: u32 = 0;
    let mut avr_rcall: u32 = 0;
    let mut i = 0;
    while i + 1 < check_len {
        let hw = u16::from_le_bytes([data[i], data[i + 1]]);
        if hw == 0x9508 {
            avr_ret += 1;
        }
        if hw == 0x9518 {
            avr_reti += 1;
        }
        if (hw >> 12) == 0xD {
            avr_rcall += 1;
        }
        i += 2;
    }
    let mut evidence: u32 = 0;
    if avr_ret >= 3 {
        evidence += 3;
    } else if avr_ret >= 1 {
        evidence += 2;
    }
    if avr_reti >= 1 {
        evidence += 1;
    }
    let total_halfwords = (check_len / 2) as f64;
    let rcall_density = avr_rcall as f64 / total_halfwords;
    if rcall_density > 0.02 && avr_rcall >= 5 {
        evidence += 2;
    } else if avr_rcall >= 3 {
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

/// Detect Hexagon (QDSP6) code and penalize C166.
fn detect_hexagon_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 128 {
        return 1.0;
    }
    let check_len = data.len().min(8192);
    let mut eop: u32 = 0;
    let mut i = 0;
    while i + 3 < check_len {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if (w >> 14) & 3 == 3 {
            eop += 1;
        }
        i += 4;
    }
    let total_words = (check_len / 4) as f64;
    let eop_density = eop as f64 / total_words;
    if eop_density > 0.15 && eop_density < 0.45 {
        0.10
    } else {
        1.0
    }
}
