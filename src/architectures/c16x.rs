//! Heuristic scoring for Infineon/Siemens C16x architecture (C161, C164, C165, C166, C167).
//!
//! The C16x family is a 16-bit microcontroller widely used in automotive ECUs
//! (Bosch, Continental, Siemens VDO). Instructions are 2 or 4 bytes long,
//! little-endian, with the first byte being the opcode. Certain opcodes
//! indicate 4-byte instructions (those that carry immediate16 or address16
//! operands).
//!
//! Key characteristics for heuristic detection:
//! - Opcode byte is always the first byte of the instruction
//! - 2-byte instructions: NOP (0xCC), RET (0xCB 0x00), RETS (0xDB 0x00),
//!   MOV Rwn,Rwm (0xF0), CALLR (0xBB), JMPR (low nibble 0xD), etc.
//! - 4-byte instructions: MOV reg,#imm16 (0xE6), MOV mem,reg (0xF6),
//!   JMPA/CALLA (0xEA), CALLS (0xDA), etc.
//! - Bit manipulation: BSET (0x0F), BCLR (0x0E) — very characteristic
//! - DPP (Data Page Pointer) segment register setup is highly distinctive

use std::cmp;

/// Opcodes that always indicate a 4-byte instruction.
/// These carry an immediate16 or address16 in bytes 2-3.
const FOUR_BYTE_OPCODES: [u8; 30] = [
    0xE6, // MOV reg, #data16
    0xE7, // MOV reg, #data16 (variant)
    0xF6, // MOV [mem], reg
    0xF7, // MOV [mem], reg (variant)
    0xF2, // MOV reg, [mem]
    0xF3, // MOV reg, [mem] (variant)
    0xEA, // JMPA / CALLA cc, caddr
    0xDA, // CALLS seg, caddr
    0xCA, // CALLI cc, [Rwn] - actually 2-byte, but CALLA is 4
    0xE4, // MOVB reg, #data8 (but padded to 4 bytes)
    0xE5, // MOVB reg, #data8 (variant)
    0xF4, // MOVB reg, [mem]
    0xF5, // MOVB [mem], reg
    0xD4, // MOV [Rwn+], mem (4 bytes)
    0xD5, // MOVB [Rwn+], mem (4 bytes)
    0xC4, // MOV [-Rwn], mem (4 bytes)
    0xC5, // MOVB [-Rwn], mem (4 bytes)
    0xD6, // ADD/SUB/AND/OR/XOR/CMP reg, mem (various 4-byte ALU)
    0xD7, // ADD/SUB/AND/OR/XOR/CMP mem, reg (various 4-byte ALU)
    0xE0, // MOV/MOVB with various addressing
    0xE2, // MOV [Rwm+#data16], Rwn (4 bytes)
    0xE3, // MOVB [Rwm+#data16], Rbn (4 bytes)
    0x86, // BMOV/BMOVN/BAND/BOR/BXOR (4-byte bit operations)
    0x87, // BCMP (4-byte)
    0x8A, // JMPI cc, [Rwn] - 2 byte, but JMPS is 0xFA
    0xFA, // JMPS seg, caddr (4 bytes, segment jump)
    0x84, // MOV [-Rwn], Rwm (4 bytes)
    0x94, // MOV [Rwn+], Rwm (4 bytes)
    0xA4, // MOV [Rwn], mem (4 bytes)
    0xB4, // MOVB [Rwn], mem (4 bytes)
];

/// Check if an opcode indicates a 4-byte instruction.
#[inline]
fn is_four_byte_opcode(op: u8) -> bool {
    // The 4-byte opcodes have several patterns. For speed, check the lookup table
    // plus the known pattern rules.
    FOUR_BYTE_OPCODES.contains(&op)
}

/// Score raw data as C16x code.
///
/// Walks through the data byte-by-byte at 2-byte alignment, interpreting
/// each position as a potential C16x instruction. The first byte is the opcode;
/// based on the opcode, the instruction is either 2 or 4 bytes.
///
/// Returns a non-negative score (clamped at 0).
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 8 {
        return 0;
    }

    // Skip leading zero/0xFF padding — common in automotive firmware flash images
    let start = skip_padding(data);
    let data = &data[start..];

    if data.len() < 8 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut i = 0;

    // Counters for structural analysis (used for bonus/penalty at the end)
    let mut nop_count: u32 = 0;
    let mut ret_count: u32 = 0;
    let mut rets_count: u32 = 0;
    let mut mov_reg_imm_count: u32 = 0;
    let mut mov_mem_count: u32 = 0; // F2/F3/F6/F7 — memory load/store operations
    let mut jmpr_count: u32 = 0;
    let mut call_count: u32 = 0;
    let mut bset_bclr_count: u32 = 0;
    let mut dpp_setup_count: u32 = 0;
    let mut valid_insn_count: u32 = 0;
    let mut invalid_count: u32 = 0;
    let mut zero_run: u32 = 0;

    while i + 1 < data.len() {
        let opcode = data[i];
        let operand = data[i + 1];

        // Handle zero words (padding within code region)
        if opcode == 0x00 && operand == 0x00 {
            zero_run += 1;
            if zero_run <= 4 {
                // Mild penalty for short zero runs (alignment padding)
                total_score -= 1;
            } else {
                // Heavier penalty for long zero runs
                total_score -= 3;
            }
            i += 2;
            continue;
        }
        zero_run = 0;

        // Determine instruction length and score
        let (insn_score, insn_len) = score_instruction(opcode, operand, data, i);

        total_score += insn_score;

        if insn_score > 0 {
            valid_insn_count += 1;
        } else if insn_score < -1 {
            invalid_count += 1;
        }

        // Update structural counters
        match opcode {
            0xCC => nop_count += 1,
            0xCB if operand == 0x00 => ret_count += 1,
            0xDB if operand == 0x00 => rets_count += 1,
            0xE6 | 0xE7 => mov_reg_imm_count += 1,
            0xF6 | 0xF7 | 0xF2 | 0xF3 => mov_mem_count += 1,
            0xBB => call_count += 1,
            0xDA | 0xEA => call_count += 1,
            0x0E | 0x1E | 0x2E | 0x3E | 0x4E | 0x5E | 0x6E | 0x7E => bset_bclr_count += 1,
            0x0F | 0x1F | 0x2F | 0x3F | 0x4F | 0x5F | 0x6F | 0x7F => bset_bclr_count += 1,
            _ => {
                // JMPR: low nibble 0xD (0x0D, 0x1D, 0x2D, ..., 0xFD)
                if (opcode & 0x0F) == 0x0D {
                    jmpr_count += 1;
                }
            }
        }

        // DPP setup detection: MOV DPPx, #seg
        // DPP registers are at addresses 0xFE00-0xFE06 (DPP0-DPP3)
        // Typically: 0xE6 Rx imm16 where Rx encodes a DPP register
        if opcode == 0xE6 && i + 3 < data.len() {
            // The second byte encodes the register number.
            // DPP0=R0 at FE00, DPP1=R1 at FE02, DPP2=R2 at FE04, DPP3=R3 at FE06
            // In many ECU firmwares, early code sets up DPP registers with segment numbers.
            // The register field (bits 4-7 of operand byte) being 0-3 for DPPx
            let reg = (operand >> 4) & 0x0F;
            if reg <= 3 {
                // Immediate value (bytes 2-3) should be a small segment number (0-15 typically)
                let imm16 = u16::from_le_bytes([data[i + 2], data[i + 3]]);
                if imm16 <= 15 {
                    dpp_setup_count += 1;
                }
            }
        }

        i += insn_len;
    }

    // Structural bonuses: patterns that are very characteristic of C16x firmware.
    //
    // Rationale: x86 scoring is inherently aggressive because its variable-length
    // byte-aligned encoding means random data often incidentally matches x86
    // prefixes and opcodes. C16x needs strong structural bonuses to overcome
    // this bias, since C16x patterns (JMPR, BSET/BCLR, CALLS/JMPS, DPP setup)
    // are architecturally specific and would not appear in random data or x86 code.
    let total_insns = valid_insn_count + invalid_count;
    if total_insns > 0 {
        let valid_ratio = valid_insn_count as f64 / total_insns as f64;

        // High valid instruction ratio is a strong signal
        if valid_ratio > 0.6 && total_insns > 50 {
            total_score += (valid_insn_count as i64) / 3;
        }

        // C16x firmware almost always has JMPR instructions (conditional branches).
        // JMPR uses the low nibble 0xD pattern — this is structurally distinctive.
        // In 229 KB of C167 firmware we expect ~4000 JMPRs.
        if jmpr_count > 10 {
            total_score += (jmpr_count as i64) * 3;
        }

        // BSET/BCLR are extremely distinctive to C16x — bit manipulation on SFRs.
        // No other common architecture uses opcodes 0x0E-0x7E and 0x0F-0x7F in
        // this specific low-nibble pattern. This is a near-unique C16x fingerprint.
        if bset_bclr_count > 3 {
            total_score += (bset_bclr_count as i64) * 5;
        }

        // MOV reg, #imm16 (0xE6) is extremely common in C16x code.
        // In firmware, we expect hundreds of these.
        if mov_reg_imm_count > 10 {
            total_score += (mov_reg_imm_count as i64) * 2;
        }

        // MOV [mem], reg (0xF6) and MOV reg, [mem] (0xF2) — memory operations
        if mov_mem_count > 10 {
            total_score += (mov_mem_count as i64) * 2;
        }

        // DPP setup is almost unique to C16x — segment register initialization.
        // Even a single DPP setup is a very strong signal.
        if dpp_setup_count > 0 {
            total_score += (dpp_setup_count as i64) * 50;
        }

        // RET (0xCB 0x00) and RETS (0xDB 0x00) presence.
        // RETS is especially distinctive — segment return is unique to C16x.
        if ret_count > 0 || rets_count > 0 {
            total_score += (ret_count as i64) * 8;
            total_score += (rets_count as i64) * 15;
        }

        // NOP density: C16x firmware often has NOP sleds for alignment
        if nop_count > 10 && nop_count < total_insns / 2 {
            total_score += (nop_count as i64);
        }

        // Calls are a strong sign of real code — CALLR, CALLS, CALLA
        if call_count > 5 {
            total_score += (call_count as i64) * 4;
        }

        // Combined structural signature: if we have multiple C16x-specific
        // features present together, it's overwhelmingly C16x.
        // (JMPR + BSET/BCLR + CALLS/JMPS + MOV reg,#imm16)
        let signature_features = [
            jmpr_count > 20,
            bset_bclr_count > 5,
            call_count > 5,
            mov_reg_imm_count > 20,
            ret_count + rets_count > 2,
            nop_count > 20,
        ];
        let feature_count = signature_features.iter().filter(|&&f| f).count();
        if feature_count >= 4 {
            // Strong multi-feature signature — this is definitely C16x.
            // Apply a substantial bonus proportional to code size.
            total_score += (valid_insn_count as i64) / 2;
        } else if feature_count >= 3 {
            total_score += (valid_insn_count as i64) / 4;
        }
    }

    cmp::max(0, total_score)
}

/// Score a single C16x instruction at position `i` in `data`.
/// Returns (score, instruction_length_in_bytes).
fn score_instruction(opcode: u8, operand: u8, data: &[u8], i: usize) -> (i64, usize) {
    // === 2-byte instructions (high confidence) ===

    // NOP: 0xCC 0x00
    if opcode == 0xCC {
        if operand == 0x00 {
            return (8, 2);
        }
        // 0xCC with non-zero operand is still NOP variant
        return (4, 2);
    }

    // RET: 0xCB 0x00
    if opcode == 0xCB && operand == 0x00 {
        return (15, 2);
    }

    // RETS: 0xDB 0x00
    if opcode == 0xDB && operand == 0x00 {
        return (20, 2); // Very distinctive — segment return
    }

    // RETI: 0xFB 0x88
    if opcode == 0xFB && operand == 0x88 {
        return (20, 2); // Return from interrupt — very distinctive
    }

    // MOV Rwn, Rwm: 0xF0 xx (register-to-register move)
    if opcode == 0xF0 {
        return (5, 2);
    }

    // MOVB Rbn, Rbm: 0xF1 xx (byte register-to-register move)
    if opcode == 0xF1 {
        return (4, 2);
    }

    // CALLR rel: 0xBB xx (relative call — very common in C16x code)
    if opcode == 0xBB {
        return (8, 2);
    }

    // PUSH/POP: 0xEC (PUSH), 0xFC (POP)
    if opcode == 0xEC || opcode == 0xFC {
        return (6, 2);
    }

    // JMPR cc, rel: low nibble 0xD → opcodes 0x0D, 0x1D, ..., 0xFD
    // The high nibble encodes the condition code.
    if (opcode & 0x0F) == 0x0D {
        // Validate condition code (high nibble 0-F are all valid conditions)
        return (6, 2);
    }

    // BSET bitaddr: 0xXF where X = bit position (0-7)
    // High nibble 0-7 with low nibble 0xF
    if (opcode & 0x0F) == 0x0F && (opcode >> 4) <= 7 {
        return (8, 2);
    }

    // BCLR bitaddr: 0xXE where X = bit position (0-7)
    // High nibble 0-7 with low nibble 0xE
    if (opcode & 0x0F) == 0x0E && (opcode >> 4) <= 7 {
        return (8, 2);
    }

    // ADD Rwn, Rwm: 0x00 xx (but 0x00 0x00 is handled as zero above)
    if opcode == 0x00 && operand != 0x00 {
        return (3, 2);
    }

    // ADD Rwn, #data4: 0x08 xx
    if opcode == 0x08 {
        return (3, 2);
    }

    // ADDB Rbn, Rbm: 0x01
    if opcode == 0x01 {
        return (2, 2);
    }

    // SUB Rwn, Rwm: 0x20
    if opcode == 0x20 {
        return (3, 2);
    }

    // SUB Rwn, #data4: 0x28
    if opcode == 0x28 {
        return (3, 2);
    }

    // CMP Rwn, Rwm: 0x40
    if opcode == 0x40 {
        return (4, 2);
    }

    // CMP Rwn, #data4: 0x48
    if opcode == 0x48 {
        return (4, 2);
    }

    // AND Rwn, Rwm: 0x60
    if opcode == 0x60 {
        return (3, 2);
    }

    // OR Rwn, Rwm: 0x70
    if opcode == 0x70 {
        return (3, 2);
    }

    // XOR Rwn, Rwm: 0x50
    if opcode == 0x50 {
        return (3, 2);
    }

    // SHL/SHR/ROL/ROR (shift/rotate): various 2-byte
    if opcode == 0x4C || opcode == 0x5C || opcode == 0x6C || opcode == 0x7C {
        return (4, 2);
    }

    // MUL/MULU: 0x0B (2-byte form)
    if opcode == 0x0B {
        return (3, 2);
    }

    // DIV/DIVU: 0x4B (2-byte form)
    if opcode == 0x4B {
        return (3, 2);
    }

    // NEG Rwn: 0x81 (2-byte)
    if opcode == 0x81 {
        return (3, 2);
    }

    // CPL Rwn: 0x91 (complement, 2-byte)
    if opcode == 0x91 {
        return (3, 2);
    }

    // MOVBS / MOVBZ (sign/zero extend byte to word): 0xD0, 0xC0
    if opcode == 0xD0 || opcode == 0xC0 {
        return (4, 2);
    }

    // === 4-byte instructions ===

    // Check if we have enough data for a 4-byte instruction
    if is_four_byte_opcode(opcode) {
        if i + 3 >= data.len() {
            // Not enough data; skip as 2-byte with small penalty
            return (-1, 2);
        }

        match opcode {
            // MOV reg, #data16: 0xE6 Rx lo hi
            0xE6 => return (6, 4),

            // MOV reg, #data16 variant: 0xE7
            0xE7 => return (5, 4),

            // MOV [mem], reg: 0xF6 Rx addr_lo addr_hi
            0xF6 => return (6, 4),

            // MOV [mem], reg variant: 0xF7
            0xF7 => return (5, 4),

            // MOV reg, [mem]: 0xF2 Rx addr_lo addr_hi
            0xF2 => return (6, 4),

            // MOV reg, [mem] variant: 0xF3
            0xF3 => return (5, 4),

            // JMPA / CALLA cc, caddr: 0xEA cc addr_lo addr_hi
            0xEA => {
                // The condition code is in bits 4-7 of the second byte
                // cc=0 means unconditional (JMPA cc_UC)
                let cc = (operand >> 4) & 0x0F;
                if cc == 0 {
                    return (8, 4); // Unconditional jump/call — very common
                }
                return (6, 4);
            }

            // CALLS seg, caddr: 0xDA seg addr_lo addr_hi
            0xDA => return (10, 4), // Segment call — very distinctive

            // JMPS seg, caddr: 0xFA seg addr_lo addr_hi
            0xFA => return (10, 4), // Segment jump — very distinctive

            // MOVB reg, #data8: 0xE4 (padded to 4 bytes)
            0xE4 | 0xE5 => return (4, 4),

            // MOV/MOVB with memory addressing: 0xF4, 0xF5
            0xF4 | 0xF5 => return (5, 4),

            // Various 4-byte ALU with memory operands
            0xD4 | 0xD5 | 0xC4 | 0xC5 | 0xD6 | 0xD7 => return (4, 4),

            // MOV with indexed addressing
            0xE0 | 0xE2 | 0xE3 => return (4, 4),

            // Bit manipulation 4-byte forms
            0x86 | 0x87 => return (5, 4),

            // Other known 4-byte opcodes
            0x84 | 0x94 | 0xA4 | 0xB4 | 0x8A | 0xCA => return (3, 4),

            _ => return (2, 4),
        }
    }

    // === Other known 2-byte opcodes ===

    // Various 2-byte ALU with immediate data4
    match opcode {
        0x06 | 0x07 | 0x16 | 0x17 | 0x26 | 0x27 | 0x36 | 0x37 => return (2, 2), // ADD/ADDB/SUB/SUBB with #data4
        0x46 | 0x47 | 0x56 | 0x57 | 0x66 | 0x67 | 0x76 | 0x77 => return (2, 2), // CMP/XOR/AND/OR with #data4
        0x02 | 0x03 | 0x12 | 0x13 | 0x22 | 0x23 | 0x32 | 0x33 => return (2, 2), // ADD/SUB indirect
        0x42 | 0x43 | 0x52 | 0x53 | 0x62 | 0x63 | 0x72 | 0x73 => return (2, 2), // CMP/XOR/AND/OR indirect

        // MOV indirect addressing 2-byte forms
        0x80 | 0x88 | 0x90 | 0x98 | 0xA0 | 0xA8 | 0xB0 | 0xB8 => return (2, 2),

        // JMPI cc, [Rwn]: conditional indirect jump
        0x9C => return (5, 2),

        // PCALL (push and call): 0xE2 is 4-byte, but 0xE8/0xC8 are 2-byte forms
        0xE8 | 0xC8 => return (3, 2),

        // SCXT (switch context): 0xC6 4-byte, 0xD6 4-byte, but 0x86 series handled above
        0xC6 => {
            if i + 3 < data.len() {
                return (5, 4); // SCXT — context switch, very C16x specific
            }
            return (1, 2);
        }

        // TRAP: 0x9B xx
        0x9B => return (5, 2),

        // IDLE/PWRDN/SRST: system instructions
        0x87 if operand == 0x78 => return (10, 4), // IDLE
        0xB7 if operand == 0x68 => return (10, 2), // PWRDN

        // DISWDT (disable watchdog): 0xA5 with specific operand
        0xA5 => return (5, 2),

        // EINIT / SRVWDT — system init
        0xB5 => return (5, 2),

        _ => {}
    }

    // If we reach here, the opcode is not recognized.
    // Apply a mild penalty — not too harsh since C16x has a dense opcode space.
    (-2, 2)
}

/// Skip leading padding (all-zero or all-0xFF regions).
/// Returns the offset of the first non-padding byte, aligned to 2 bytes.
fn skip_padding(data: &[u8]) -> usize {
    let mut i = 0;
    let chunk_size = 64;

    while i + chunk_size <= data.len() {
        let chunk = &data[i..i + chunk_size];
        let all_zero = chunk.iter().all(|&b| b == 0x00);
        let all_ff = chunk.iter().all(|&b| b == 0xFF);

        if !all_zero && !all_ff {
            break;
        }
        i += chunk_size;
    }

    // Align to 2 bytes
    i & !1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c16x_nop() {
        // NOP = 0xCC 0x00
        let code = [0xCC, 0x00, 0xCC, 0x00, 0xCC, 0x00, 0xCC, 0x00];
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_c16x_ret() {
        // RET = 0xCB 0x00
        let code = [0xCC, 0x00, 0xCB, 0x00, 0xCC, 0x00, 0xCC, 0x00];
        let s = score(&code);
        assert!(s > 0);
    }

    #[test]
    fn test_c16x_rets() {
        // RETS = 0xDB 0x00
        let code = [0xCC, 0x00, 0xDB, 0x00, 0xCC, 0x00, 0xCC, 0x00];
        let s = score(&code);
        assert!(s > 0);
    }

    #[test]
    fn test_c16x_mov_reg_imm16() {
        // MOV R4, #0x1234 → 0xE6 0x40 0x34 0x12
        let code = [
            0xE6, 0x40, 0x34, 0x12, // MOV R4, #0x1234
            0xE6, 0x50, 0x00, 0x01, // MOV R5, #0x0100
        ];
        let s = score(&code);
        assert!(s > 0);
    }

    #[test]
    fn test_c16x_jmpr() {
        // JMPR cc_UC, rel → 0x0D rel (unconditional relative jump)
        // JMPR cc_Z, rel → 0x2D rel (jump if zero)
        let code = [
            0x0D, 0x05, // JMPR cc_UC, +5
            0x2D, 0xFE, // JMPR cc_Z, -2
            0x3D, 0x03, // JMPR cc_NZ, +3
            0xCC, 0x00, // NOP
        ];
        let s = score(&code);
        assert!(s > 0);
    }

    #[test]
    fn test_c16x_bset_bclr() {
        // BSET: 0x0F-0x7F (low nibble F, high nibble 0-7)
        // BCLR: 0x0E-0x7E (low nibble E, high nibble 0-7)
        let code = [
            0x0F, 0x40, // BSET bit0
            0x1F, 0x40, // BSET bit1
            0x0E, 0x40, // BCLR bit0
            0x1E, 0x40, // BCLR bit1
        ];
        let s = score(&code);
        assert!(s > 0);
    }

    #[test]
    fn test_c16x_calls_jmps() {
        // CALLS seg, caddr → 0xDA seg lo hi
        // JMPS seg, caddr → 0xFA seg lo hi
        let code = [
            0xDA, 0x00, 0x00, 0x80, // CALLS 0, 0x8000
            0xFA, 0x01, 0x00, 0x40, // JMPS 1, 0x4000
        ];
        let s = score(&code);
        assert!(s > 0);
    }

    #[test]
    fn test_c16x_callr() {
        // CALLR rel → 0xBB rel
        let code = [
            0xBB, 0x10, // CALLR +16
            0xBB, 0x20, // CALLR +32
            0xCC, 0x00, // NOP
            0xCB, 0x00, // RET
        ];
        let s = score(&code);
        assert!(s > 0);
    }

    #[test]
    fn test_c16x_typical_function() {
        // Typical C16x function: push, mov, work, ret
        let code = [
            0xEC, 0x04, // PUSH R4
            0xEC, 0x05, // PUSH R5
            0xE6, 0x40, 0x00, 0x01, // MOV R4, #0x0100
            0xF6, 0x40, 0x00, 0xFE, // MOV [0xFE00], R4 (write to SFR)
            0x0F, 0x40, // BSET
            0xF0, 0x54, // MOV R5, R4
            0x0D, 0x03, // JMPR cc_UC, +3
            0xFC, 0x05, // POP R5
            0xFC, 0x04, // POP R4
            0xCB, 0x00, // RET
        ];
        let s = score(&code);
        assert!(
            s > 20,
            "Expected high score for typical C16x function, got {}",
            s
        );
    }

    #[test]
    fn test_c16x_with_leading_zeros() {
        // Simulate firmware with leading zero padding
        let mut data = vec![0x00u8; 256];
        // Append actual code
        data.extend_from_slice(&[
            0xCC, 0x00, // NOP
            0xE6, 0x40, 0x34, 0x12, // MOV R4, #0x1234
            0xF0, 0x54, // MOV R5, R4
            0xBB, 0x10, // CALLR
            0x0D, 0x05, // JMPR
            0xCB, 0x00, // RET
        ]);
        let s = score(&data);
        assert!(s > 0, "Should handle leading zero padding, got score {}", s);
    }

    #[test]
    fn test_c16x_not_x86() {
        // x86 prologue should not score well as C16x
        let x86_code = [
            0x55, // push ebp
            0x89, 0xE5, // mov ebp, esp
            0x83, 0xEC, 0x10, // sub esp, 0x10
            0x89, 0x45, 0xFC, // mov [ebp-4], eax
            0xC9, // leave
            0xC3, // ret
        ];
        let s = score(&x86_code);
        // x86 code should not score highly as C16x
        // It may get some incidental hits but should be low
        assert!(
            s < 30,
            "x86 code should not score highly as C16x, got {}",
            s
        );
    }

    #[test]
    fn test_c16x_dpp_setup() {
        // DPP register setup: MOV DPP0, #3 → 0xE6 0x00 0x03 0x00
        // MOV DPP1, #4 → 0xE6 0x10 0x04 0x00
        let code = [
            0xE6, 0x00, 0x03, 0x00, // MOV DPP0, #3
            0xE6, 0x10, 0x04, 0x00, // MOV DPP1, #4
            0xE6, 0x20, 0x05, 0x00, // MOV DPP2, #5
            0xE6, 0x30, 0x06, 0x00, // MOV DPP3, #6
        ];
        let s = score(&code);
        assert!(s > 50, "DPP setup should score very highly, got {}", s);
    }

    #[test]
    fn test_skip_padding() {
        // 128 bytes of zeros followed by code
        let mut data = vec![0x00u8; 128];
        data.extend_from_slice(&[0xCC, 0x00]); // NOP
        let offset = skip_padding(&data);
        assert_eq!(offset, 128);
    }

    #[test]
    fn test_skip_ff_padding() {
        // 64 bytes of 0xFF followed by code
        let mut data = vec![0xFFu8; 64];
        data.extend_from_slice(&[0xCC, 0x00]); // NOP
        let offset = skip_padding(&data);
        assert_eq!(offset, 64);
    }
}
