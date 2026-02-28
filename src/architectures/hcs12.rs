//! Heuristic scoring for Freescale/NXP HCS12/HCS12X (MC68HC12 / CPU12).
//!
//! The HC12/HCS12X is a 16-bit big-endian Motorola-lineage microcontroller
//! widely used in automotive ECUs (Bosch, Continental, Delphi). The MCU family
//! includes MC9S12XEP768, MC9S12XDP512, and many others.
//!
//! Key characteristics for heuristic detection:
//! - **Big-endian** (Motorola byte order): addresses stored MSB first
//! - **Variable-length instructions**: 1 to 8 bytes, length determined by opcode
//! - **Byte-aligned**: no alignment requirement
//! - **Page 2 prefix**: opcode 0x18 extends opcode space (LBRA, ABA, TAB, MOVW, etc.)
//! - **Interrupt vector table** at the end of flash (0xFF80–0xFFFE for HC12,
//!   0xFF10–0xFFFE for HCS12X), with the reset vector at 0xFFFE
//! - **Common opcodes**: RTS (0x3D), BRA (0x20), BSR (0x07), JSR (0x16),
//!   LDAA (0x86/96/A6/B6), LDD (0xCC/DC/EC/FC), etc.
//! - **0x00 = BGND** (background debug), NOT NOP. NOP is 0xA7.
//!
//! References:
//! - Freescale S12XCPU Reference Manual (S12XCPUV2)
//! - Capstone M680X / CPU12 disassembler source
//! - cstool cpu12 verification against known HCS12X firmware

use std::cmp;

/// Score raw data as HC12/HCS12X code.
///
/// The scorer walks through the data byte-by-byte, interpreting each
/// position as a potential HC12 instruction. It recognizes page 1 opcodes
/// (single-byte prefix) and page 2 opcodes (0x18 prefix), assigns
/// per-instruction scores, and applies structural bonuses for patterns
/// that are highly characteristic of HC12 firmware.
///
/// Returns a non-negative score (clamped at 0).
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 16 {
        return 0;
    }

    // Skip leading zero/0xFF padding — common in automotive firmware flash images
    let start = skip_padding(data);
    let working = &data[start..];

    if working.len() < 16 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut i = 0;

    // Structural counters
    let mut rts_count: u32 = 0;
    let mut rtc_count: u32 = 0;
    let mut rti_count: u32 = 0;
    let mut bra_count: u32 = 0; // unconditional branches
    let mut bcc_count: u32 = 0; // conditional branches
    let mut bsr_count: u32 = 0;
    let mut jsr_count: u32 = 0;
    let mut jmp_count: u32 = 0;
    let mut call_count: u32 = 0; // CALL instruction (banked subroutine)
    let mut load_count: u32 = 0; // LDAA/LDAB/LDD/LDX/LDY
    let mut store_count: u32 = 0; // STAA/STAB/STD/STX/STY
    let mut push_pull_count: u32 = 0;
    let mut nop_count: u32 = 0;
    let mut page2_count: u32 = 0; // 0x18 prefix sequences
    let mut clr_tst_count: u32 = 0; // CLR/CLRA/CLRB/TSTA/TSTB
    let mut valid_insn_count: u32 = 0;
    let mut invalid_count: u32 = 0;
    let mut zero_run: u32 = 0;

    while i < working.len() {
        let opcode = working[i];

        // Handle zero bytes — 0x00 = BGND (debug breakpoint), not normal code
        if opcode == 0x00 {
            zero_run += 1;
            if zero_run <= 2 {
                total_score -= 2;
            } else {
                total_score -= 5;
            }
            i += 1;
            continue;
        }
        // 0xFF bytes (erased flash)
        if opcode == 0xFF {
            zero_run += 1;
            if zero_run <= 2 {
                total_score -= 1;
            } else {
                total_score -= 4;
            }
            i += 1;
            continue;
        }
        zero_run = 0;

        let (insn_score, insn_len) = score_instruction(opcode, working, i);

        total_score += insn_score;

        if insn_score > 0 {
            valid_insn_count += 1;
        } else if insn_score < -1 {
            invalid_count += 1;
        }

        // Update structural counters based on opcode
        match opcode {
            0x3D => rts_count += 1,
            0x0A => rtc_count += 1,
            0x0B => rti_count += 1,
            0xA7 => nop_count += 1,
            0x20 => bra_count += 1,
            0x22..=0x2F => bcc_count += 1,
            0x21 => {} // BRN — branch never (2-byte NOP), counted separately
            0x07 => bsr_count += 1,
            0x15 | 0x16 | 0x17 => jsr_count += 1,
            0x05 | 0x06 => jmp_count += 1,
            0x4A | 0x4B => call_count += 1,
            0x86 | 0x96 | 0xA6 | 0xB6 => load_count += 1, // LDAA variants
            0xC6 | 0xD6 | 0xE6 | 0xF6 => load_count += 1, // LDAB variants
            0xCC | 0xDC | 0xEC | 0xFC => load_count += 1, // LDD variants
            0xCE | 0xDE | 0xEE | 0xFE => load_count += 1, // LDX variants
            0xCD | 0xDD | 0xED | 0xFD => load_count += 1, // LDY variants
            0x5A | 0x6A | 0x7A => store_count += 1,       // STAA dir/idx/ext
            0x5B | 0x6B | 0x7B => store_count += 1,       // STAB dir/idx/ext
            0x5C | 0x6C | 0x7C => store_count += 1,       // STD dir/idx/ext
            0x5D | 0x6D | 0x7D => store_count += 1,       // STY dir/idx/ext
            0x5E | 0x6E | 0x7E => store_count += 1,       // STX dir/idx/ext
            0x30..=0x3B if opcode != 0x3D => push_pull_count += 1, // PUL*/PSH* (excluding RTS at 0x3D)
            0x87 | 0xC7 | 0x97 | 0xD7 => clr_tst_count += 1,       // CLRA/CLRB/TSTA/TSTB
            0x69 | 0x79 => clr_tst_count += 1,                     // CLR idx/ext
            0x18 => page2_count += 1,
            _ => {}
        }

        i += insn_len;
    }

    // ─── Structural bonuses ───
    let total_insns = valid_insn_count + invalid_count;
    if total_insns > 20 {
        let valid_ratio = valid_insn_count as f64 / total_insns as f64;

        // High valid instruction ratio is a strong signal
        if valid_ratio > 0.55 && total_insns > 100 {
            total_score += (valid_insn_count as i64) / 4;
        }

        // RTS (0x3D) is the function return — every function ends with it.
        // This is the most common single-byte instruction in HC12 code.
        if rts_count > 5 {
            total_score += (rts_count as i64) * 6;
        }

        // RTC (0x0A) — banked return — distinctive for HCS12X
        if rtc_count > 0 {
            total_score += (rtc_count as i64) * 12;
        }

        // RTI (0x0B) — interrupt return — limited count, but very specific
        if rti_count > 0 {
            total_score += (rti_count as i64) * 10;
        }

        // Branch instructions (0x20-0x2F) are extremely common.
        // BNE (0x26) and BEQ (0x27) are the most frequent.
        if bcc_count > 10 {
            total_score += (bcc_count as i64) * 3;
        }

        // BSR (0x07) — relative subroutine call
        if bsr_count > 2 {
            total_score += (bsr_count as i64) * 5;
        }

        // JSR (0x15-0x17) — absolute subroutine call, very common
        if jsr_count > 5 {
            total_score += (jsr_count as i64) * 5;
        }

        // CALL (0x4A/0x4B) — banked call, distinctive for HCS12X
        if call_count > 0 {
            total_score += (call_count as i64) * 10;
        }

        // Load instructions are extremely common in firmware
        if load_count > 20 {
            total_score += (load_count as i64) * 2;
        }

        // Store instructions
        if store_count > 10 {
            total_score += (store_count as i64) * 2;
        }

        // PUSH/PULL (function prologue/epilogue)
        if push_pull_count > 5 {
            total_score += (push_pull_count as i64) * 3;
        }

        // Page 2 prefix (0x18) — highly characteristic of HC12.
        // This byte as a prefix followed by specific opcodes is a strong signature.
        if page2_count > 5 {
            total_score += (page2_count as i64) * 4;
        }

        // CLR/TST instructions (common for flag/register initialization)
        if clr_tst_count > 5 {
            total_score += (clr_tst_count as i64) * 2;
        }

        // Combined structural signature: multiple HC12-specific features present
        let signature_features = [
            rts_count > 10,                  // Function returns
            bcc_count > 20,                  // Conditional branches
            jsr_count > 10,                  // Subroutine calls
            load_count > 30,                 // Load instructions
            store_count > 15,                // Store instructions
            page2_count > 3,                 // Page 2 prefix usage
            rtc_count > 0 || call_count > 0, // Banked calls/returns (HCS12X specific)
            push_pull_count > 5,             // Stack operations
        ];
        let feature_count = signature_features.iter().filter(|&&f| f).count();
        if feature_count >= 5 {
            total_score += (valid_insn_count as i64) / 2;
        } else if feature_count >= 4 {
            total_score += (valid_insn_count as i64) / 4;
        } else if feature_count >= 3 {
            total_score += (valid_insn_count as i64) / 6;
        }
    }

    // ─── Interrupt vector table detection ───
    // HC12/HCS12X firmware has an interrupt vector table at the end of flash.
    // For a 768KB image, the IVT is at the very end. The reset vector is at
    // offset (size - 2), and vectors fill up to 128 bytes before that.
    // Each vector is a big-endian 16-bit address pointing into the code space.
    total_score += score_vector_table(data);

    // ─── Cross-architecture penalty: SuperH firmware detection ───
    //
    // HC12 is a byte-level scorer where nearly every byte value maps to a
    // valid opcode. When scanning SuperH (SH7052/SH7058) firmware byte-by-byte,
    // HC12 accumulates massive false-positive scores because SH instruction
    // bytes happen to be valid HC12 opcodes (e.g., SH RTS low byte 0x0B =
    // HC12 RTI, SH BRA byte 0x20 = HC12 BRA, etc.).
    //
    // We detect SH firmware by its distinctive structural signatures:
    // 1. SH7058 sparse vector table: 16-byte stride with 0xFF00xxxx addresses
    //    and 12 bytes of 0xFF padding — unmistakable Renesas SH format.
    // 2. Standard SH vector table: packed 32-bit BE addresses at offset 0 in
    //    the 0x00000040–0x00FFFFFF range (ROM) or 0xFFF80000+ (RAM/SP).
    // 3. SH compound delay-slot patterns: RTS;NOP (0x000B0009), JSR;NOP, etc.
    //
    // When strong SH evidence is found, we apply a heavy multiplier penalty
    // to prevent HC12 from outscoring the SH scorer on SH firmware.
    let sh_penalty = detect_sh_cross_arch_penalty(data);
    if sh_penalty > 0.0 && sh_penalty < 1.0 {
        total_score = (total_score as f64 * sh_penalty) as i64;
    }

    // ─── Cross-architecture penalty: C166 firmware detection ───
    //
    // C166 (Infineon/Siemens C16x/ST10) and HC12 are both 16-bit MCUs used
    // in automotive ECUs. HC12's byte-level scoring matches many C166 opcodes
    // because both have dense opcode maps. We detect C166 by its distinctive
    // instruction patterns:
    // - RET = 0xCB 0x00 (HC12 has no 0xCB opcode)
    // - RETS = 0xDB 0x00 (segmented return — unique to C166)
    // - PUSH reg = 0xEC 0xFn / POP reg = 0xFC 0xFn
    // - EXTS = 0xD7 (extended segment — unique to C166, no other ISA has this)
    // - CALLR = 0xBB nn (relative call)
    // - CALLS = 0xDA (segmented call, 4-byte)
    let c166_penalty = detect_c166_cross_arch_penalty(data);
    if c166_penalty > 0.0 && c166_penalty < 1.0 {
        total_score = (total_score as f64 * c166_penalty) as i64;
    }

    cmp::max(0, total_score)
}

/// Score a single HC12 instruction at position `i` in `data`.
/// Returns (score, instruction_length_in_bytes).
fn score_instruction(opcode: u8, data: &[u8], i: usize) -> (i64, usize) {
    // ─── Page 2 prefix (0x18) ───
    // When 0x18 appears, the next byte is the actual opcode from page 2.
    if opcode == 0x18 {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        let page2_op = data[i + 1];
        return score_page2_instruction(page2_op, data, i);
    }

    // ─── Inherent (1-byte) instructions ───
    match opcode {
        0x3D => return (12, 1), // RTS — function return, extremely common
        0x0A => return (15, 1), // RTC — banked return (HCS12X specific)
        0x0B => return (15, 1), // RTI — interrupt return
        0xA7 => return (6, 1),  // NOP
        0x87 => return (5, 1),  // CLRA
        0xC7 => return (5, 1),  // CLRB
        0x97 => return (4, 1),  // TSTA
        0xD7 => return (4, 1),  // TSTB
        0x42 => return (4, 1),  // INCA
        0x43 => return (4, 1),  // DECA
        0x52 => return (4, 1),  // INCB
        0x53 => return (4, 1),  // DECB
        0x08 => return (3, 1),  // INX
        0x09 => return (3, 1),  // DEX
        0x02 => return (3, 1),  // INY
        0x03 => return (3, 1),  // DEY
        0x04 => {
            // DBEQ/DBNE/IBEQ/IBNE/TBEQ/TBNE — loop primitives (3 bytes total)
            if i + 2 < data.len() {
                return (8, 3);
            }
            return (2, 1);
        }
        0x12 => return (5, 1), // MUL (A × B → D)
        0x10 => return (4, 1), // IDIV (D / X → X, rem D)
        0x11 => return (5, 1), // EDIV (Y:D / X → Y, rem D)
        0x14 => return (4, 1), // EDIVS
        0x41 => return (4, 1), // COMA
        0x51 => return (4, 1), // COMB
        0x40 => return (4, 1), // NEGA
        0x50 => return (4, 1), // NEGB
        0x44 => return (3, 1), // LSRA
        0x54 => return (3, 1), // LSRB
        0x45 => return (3, 1), // ROLA
        0x55 => return (3, 1), // ROLB
        0x46 => return (3, 1), // RORA
        0x56 => return (3, 1), // RORB
        0x47 => return (3, 1), // ASRA
        0x57 => return (3, 1), // ASRB
        0x48 => return (3, 1), // ASLA/LSLA
        0x58 => return (3, 1), // ASLB/LSLB
        0x01 => return (3, 1), // MEM (fuzzy logic membership function)
        0x0C => return (3, 1), // BSET/BCLR (indexed with mask, multi-byte)
        _ => {}
    }

    // ─── 2-byte relative branch instructions ───
    // 0x20-0x2F: BRA, BRN, BHI, BLS, BCC, BCS, BNE, BEQ, BVC, BVS, BPL, BMI, BGE, BLT, BGT, BLE
    if opcode >= 0x20 && opcode <= 0x2F {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        let rel = data[i + 1] as i8;
        // Branch target should be reasonable (within ~127 bytes)
        // All branch offsets are valid, but very extreme values are less common
        if opcode == 0x20 {
            return (6, 2); // BRA — unconditional branch
        }
        if opcode == 0x21 {
            return (3, 2); // BRN — branch never (effective 2-byte NOP)
        }
        // Conditional branches: BNE (0x26) and BEQ (0x27) are extremely common
        if opcode == 0x26 || opcode == 0x27 {
            return (6, 2);
        }
        // BCC (0x24) / BCS (0x25) — carry condition
        if opcode == 0x24 || opcode == 0x25 {
            return (5, 2);
        }
        // All other conditional branches
        return (4, 2);
    }

    // ─── BSR rel8 (0x07) — branch to subroutine ───
    if opcode == 0x07 {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        return (8, 2);
    }

    // ─── JMP/JSR instructions ───
    match opcode {
        0x05 => {
            // JMP indexed — 2+ bytes (opcode + index postbyte)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x06 => {
            // JMP extended — 3 bytes (opcode + 16-bit addr)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (6, 3);
        }
        0x15 => {
            // JSR indexed — 2+ bytes
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (7, 1 + plen);
        }
        0x16 => {
            // JSR extended — 3 bytes (opcode + 16-bit addr)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            // Validate that the target address looks reasonable
            let addr = u16::from_be_bytes([data[i + 1], data[i + 2]]);
            if addr >= 0x0800 {
                return (8, 3); // Reasonable code address
            }
            return (5, 3);
        }
        0x17 => {
            // JSR direct — 2 bytes (opcode + 8-bit addr)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (6, 2);
        }
        _ => {}
    }

    // ─── CALL instruction (banked subroutine) ───
    match opcode {
        0x4A => {
            // CALL extended — 4 bytes (opcode + 16-bit addr + page)
            if i + 3 >= data.len() {
                return (-1, 1);
            }
            return (10, 4);
        }
        0x4B => {
            // CALL indexed — 2+ bytes (opcode + index postbyte + page)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (9, 1 + plen + 1); // +1 for page byte
        }
        _ => {}
    }

    // ─── SWI — software interrupt ───
    if opcode == 0x3F {
        return (6, 1);
    }

    // ─── PUSH/PULL instructions (0x30-0x3B, excluding 0x3D=RTS, 0x3F=SWI) ───
    match opcode {
        0x30 => return (5, 1), // PULX
        0x31 => return (5, 1), // PULY
        0x32 => return (5, 1), // PULA
        0x33 => return (5, 1), // PULB
        0x34 => return (5, 1), // PSHX
        0x35 => return (5, 1), // PSHY
        0x36 => return (5, 1), // PSHA
        0x37 => return (5, 1), // PSHB
        0x38 => return (5, 1), // PULC (pull CCR)
        0x39 => return (5, 1), // PSHC (push CCR)
        0x3A => return (5, 1), // PULD
        0x3B => return (5, 1), // PSHD
        0x3C => return (3, 1), // unused/reserved in some variants
        0x3E => return (4, 1), // STOP / WAI depending on variant
        _ => {}
    }

    // ─── Load/Store accumulator A (8-bit) ───
    match opcode {
        0x86 => {
            // LDAA #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0x96 => {
            // LDAA direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xA6 => {
            // LDAA indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0xB6 => {
            // LDAA extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x5A => {
            // STAA direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0x6A => {
            // STAA indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x7A => {
            // STAA extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        _ => {}
    }

    // ─── Load/Store accumulator B (8-bit) ───
    match opcode {
        0xC6 => {
            // LDAB #imm8
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xD6 => {
            // LDAB direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xE6 => {
            // LDAB indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0xF6 => {
            // LDAB extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x5B => {
            // STAB direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0x6B => {
            // STAB indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x7B => {
            // STAB extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        _ => {}
    }

    // ─── Load/Store D register (16-bit) ───
    match opcode {
        0xCC => {
            // LDD #imm16
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (6, 3);
        }
        0xDC => {
            // LDD direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xEC => {
            // LDD indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0xFC => {
            // LDD extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x5C => {
            // STD direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0x6C => {
            // STD indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x7C => {
            // STD extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        _ => {}
    }

    // ─── Load/Store X register (16-bit) ───
    match opcode {
        0xCE => {
            // LDX #imm16
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0xDE => {
            // LDX direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xEE => {
            // LDX indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0xFE => {
            // LDX extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x5E => {
            // STX direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0x6E => {
            // STX indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x7E => {
            // STX extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        _ => {}
    }

    // ─── Load/Store Y register (16-bit) ───
    match opcode {
        0xCD => {
            // LDY #imm16
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0xDD => {
            // LDY direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xED => {
            // LDY indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0xFD => {
            // LDY extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x5D => {
            // STY direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0x6D => {
            // STY indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x7D => {
            // STY extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        _ => {}
    }

    // ─── Load/Store SP (16-bit) ───
    match opcode {
        0xCF => {
            // LDS #imm16
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0xDF => {
            // LDS direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xEF => {
            // LDS indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0xFF => {
            // LDS extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x5F => {
            // STS direct
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0x6F => {
            // STS indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x7F => {
            // STS extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        _ => {}
    }

    // ─── ALU operations on A (8-bit): ADD/ADC/SUB/SBC/AND/ORA/EOR/CMP/BIT ───
    // Pattern: 0x8x=imm, 0x9x=dir, 0xAx=idx, 0xBx=ext
    // Each row: ADDA=0x8B, ADCA=0x89, SUBA=0x80, SBCA=0x82, ANDA=0x84,
    //           ORAA=0x8A, EORA=0x88, CMPA=0x81, BITA=0x85
    if (opcode >= 0x80 && opcode <= 0x8F)
        || (opcode >= 0x90 && opcode <= 0x9F)
        || (opcode >= 0xA0 && opcode <= 0xAF)
        || (opcode >= 0xB0 && opcode <= 0xBF)
    {
        // These are all valid HC12 page-1 opcodes in the 0x80-0xBF range
        // (some are inherent, most take operands)
        let row = (opcode >> 4) & 0x0F;
        match row {
            0x8 => {
                // Immediate mode: 2 bytes for 8-bit ops, 3 bytes for 16-bit
                if i + 1 >= data.len() {
                    return (-1, 1);
                }
                return (3, 2);
            }
            0x9 => {
                // Direct mode: 2 bytes
                if i + 1 >= data.len() {
                    return (-1, 1);
                }
                return (4, 2);
            }
            0xA => {
                // Indexed mode: 2+ bytes
                if i + 1 >= data.len() {
                    return (-1, 1);
                }
                let (_, plen) = decode_index_postbyte(data, i + 1);
                return (3, 1 + plen);
            }
            0xB => {
                // Extended mode: 3 bytes
                if i + 2 >= data.len() {
                    return (-1, 1);
                }
                return (4, 3);
            }
            _ => {}
        }
    }

    // ─── ALU operations on B (8-bit) and D (16-bit): 0xCx-0xFx ───
    // Handled above for LD/ST, but there are also:
    // ADDB, ADCB, SUBB, SBCB, ANDB, ORAB, EORB, CMPB, BITB
    // ADDD, SUBD, CPD, CPX, CPY
    // Some of these overlap with LD/ST, but the ones not yet handled:
    if (opcode >= 0xC0 && opcode <= 0xCF)
        || (opcode >= 0xD0 && opcode <= 0xDF)
        || (opcode >= 0xE0 && opcode <= 0xEF)
        || (opcode >= 0xF0 && opcode <= 0xFF)
    {
        // Already handled specific LD/ST cases above; if we get here,
        // this is an ALU operation
        let row = (opcode >> 4) & 0x0F;
        match row {
            0xC => {
                if i + 1 >= data.len() {
                    return (-1, 1);
                }
                // Some are 2-byte (imm8), some are 3-byte (imm16)
                return (3, 2);
            }
            0xD => {
                if i + 1 >= data.len() {
                    return (-1, 1);
                }
                return (4, 2);
            }
            0xE => {
                if i + 1 >= data.len() {
                    return (-1, 1);
                }
                let (_, plen) = decode_index_postbyte(data, i + 1);
                return (3, 1 + plen);
            }
            0xF => {
                if i + 2 >= data.len() {
                    return (-1, 1);
                }
                return (4, 3);
            }
            _ => {}
        }
    }

    // ─── TFR/EXG (transfer/exchange registers): 0xB7 ───
    if opcode == 0xB7 {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        return (5, 2); // postbyte selects source/dest registers
    }

    // ─── SEX (sign extend): 0xB7 is TFR, but SEX is a special case ───
    // Actually SEX is encoded as TFR with specific register pair

    // ─── LEAS/LEAX/LEAY (load effective address): 0x1B, 0x1A, 0x19 ───
    match opcode {
        0x1B => {
            // LEAS — 2+ bytes (opcode + index postbyte)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x1A => {
            // LEAX
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        0x19 => {
            // LEAY
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (5, 1 + plen);
        }
        _ => {}
    }

    // ─── CLR/INC/DEC/TST/COM/NEG with memory operand ───
    match opcode {
        0x69 => {
            // CLR indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (4, 1 + plen);
        }
        0x79 => {
            // CLR extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0x62 => {
            // INC indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (4, 1 + plen);
        }
        0x72 => {
            // INC extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0x63 => {
            // DEC indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (4, 1 + plen);
        }
        0x73 => {
            // DEC extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0xE7 => {
            // TST indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (4, 1 + plen);
        }
        0xF7 => {
            // TST extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0x61 => {
            // COM indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (4, 1 + plen);
        }
        0x71 => {
            // COM extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0x60 => {
            // NEG indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (4, 1 + plen);
        }
        0x70 => {
            // NEG extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        _ => {}
    }

    // ─── Shift/Rotate memory: ASL/ASR/LSL/LSR/ROL/ROR ───
    match opcode {
        0x64 => {
            // LSR indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (3, 1 + plen);
        }
        0x74 => {
            // LSR extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        0x65 => {
            // ROL indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (3, 1 + plen);
        }
        0x75 => {
            // ROL extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        0x66 => {
            // ROR indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (3, 1 + plen);
        }
        0x76 => {
            // ROR extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        0x67 => {
            // ASR indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (3, 1 + plen);
        }
        0x77 => {
            // ASR extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        0x68 => {
            // ASL/LSL indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            let (_, plen) = decode_index_postbyte(data, i + 1);
            return (3, 1 + plen);
        }
        0x78 => {
            // ASL/LSL extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        _ => {}
    }

    // ─── Bit manipulation: BSET/BCLR/BRSET/BRCLR ───
    match opcode {
        0x0C => {
            // BSET (direct page) — 3 bytes: opcode, addr, mask
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x0D => {
            // BCLR (direct page) — 3 bytes: opcode, addr, mask
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x0E => {
            // BRSET (direct page) — 4 bytes: opcode, addr, mask, rel
            if i + 3 >= data.len() {
                return (-1, 1);
            }
            return (6, 4);
        }
        0x0F => {
            // BRCLR (direct page) — 4 bytes: opcode, addr, mask, rel
            if i + 3 >= data.len() {
                return (-1, 1);
            }
            return (6, 4);
        }
        _ => {}
    }

    // ─── Miscellaneous ───
    match opcode {
        0x13 => return (4, 1), // EMACS — extended multiply & accumulate (5 bytes total)
        0x1C | 0x1D | 0x1E | 0x1F => {
            // BSET/BCLR/BRSET/BRCLR indexed variants — multi-byte
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        _ => {}
    }

    // ─── Remaining opcodes not explicitly handled ───
    // The HC12 opcode space is fairly dense. Opcodes we haven't matched
    // might be valid (less common) or might be data mixed with code.
    // Apply a mild penalty.
    (-2, 1)
}

/// Score a page 2 instruction (preceded by 0x18 prefix).
/// The `i` parameter points to the 0x18 byte.
fn score_page2_instruction(page2_op: u8, data: &[u8], i: usize) -> (i64, usize) {
    match page2_op {
        // ─── Long branches (0x18 0x20-0x2F + 16-bit rel) — 4 bytes total ───
        0x20..=0x2F => {
            if i + 3 >= data.len() {
                return (2, 2);
            }
            if page2_op == 0x20 {
                return (8, 4); // LBRA — long unconditional branch
            }
            if page2_op == 0x21 {
                return (3, 4); // LBRN — long branch never
            }
            // Long conditional branches (LBNE, LBEQ, etc.)
            return (7, 4);
        }
        // ─── Inter-register operations (2 bytes total) ───
        0x06 => return (6, 2), // ABA (A + B → A)
        0x07 => return (5, 2), // DAA (decimal adjust A)
        0x0E => return (6, 2), // TAB (A → B)
        0x0F => return (6, 2), // TBA (B → A)
        0x10 => return (5, 2), // IDIVS
        0x11 => return (5, 2), // FDIV
        0x12 => return (5, 2), // EMULS
        0x13 => return (5, 2), // EMUL
        0x14 => return (5, 2), // EDIVS
        0x16 => return (6, 2), // SBA (A - B → A)
        0x17 => return (5, 2), // CBA (compare A with B)
        // ─── MOVB/MOVW — memory-to-memory moves ───
        // These are highly distinctive: firmware often uses MOVW to init I/O ports.
        0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 => {
            // MOVB/MOVW variants — 4-6 bytes total depending on addressing modes
            if i + 3 >= data.len() {
                return (3, 2);
            }
            // Simplified: most MOVB/MOVW are 4-6 bytes total including the 0x18 prefix
            return (8, 5); // Conservative estimate
        }
        // ─── MAXA/MINA/MAXD/MIND/MAXM/MINM ───
        0x18 | 0x19 | 0x1C | 0x1D | 0x1E | 0x1F => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        // ─── Fuzzy logic: REV, REVW, WAV, TBL, ETBL ───
        0x3A => return (6, 2), // REV
        0x3B => return (6, 2), // REVW
        0x3C => return (6, 2), // WAV
        // ─── STOP, WAI ───
        0x3E => return (4, 2), // WAI
        // ─── EMACS ───
        0x12 => {
            if i + 5 >= data.len() {
                return (2, 2);
            }
            return (5, 6); // EMACS — 6 bytes total
        }
        // ─── Other page 2 opcodes ───
        _ => {
            // Unknown page 2 opcode — mild penalty
            return (0, 2);
        }
    }
}

/// Decode an HC12 indexed addressing mode postbyte and return
/// (is_valid, total_bytes_consumed_including_postbyte).
///
/// The HC12 indexed mode is complex:
/// - 5-bit offset: postbyte only (1 byte total)
/// - 9-bit offset: postbyte + 1 byte (2 bytes total)
/// - 16-bit offset: postbyte + 2 bytes (3 bytes total)
/// - Accumulator offset: postbyte only (1 byte)
/// - Auto inc/dec: postbyte only (1 byte)
/// - Indirect: postbyte + 2 bytes (3 bytes total)
fn decode_index_postbyte(data: &[u8], pos: usize) -> (bool, usize) {
    if pos >= data.len() {
        return (false, 1);
    }

    let pb = data[pos];

    // Check bit 7
    if pb & 0x80 == 0 {
        // 5-bit constant offset from X, Y, SP, or PC
        // Format: 0rr0nnnn or 0rr1nnnn (rr = register, nnnnn = 5-bit offset)
        return (true, 1);
    }

    // Bit 7 is set — check bits 6:5 for the sub-mode
    let mode = (pb >> 5) & 0x03;

    match mode {
        // 0b10x: 9-bit or 16-bit constant offset
        0b10 | 0b11 => {
            // Check bit 1 (in the lower bits) for size
            if pb & 0x02 == 0 {
                // 9-bit offset: 1 additional byte
                if pos + 1 >= data.len() {
                    return (false, 1);
                }
                return (true, 2);
            } else {
                // 16-bit offset: 2 additional bytes
                if pos + 2 >= data.len() {
                    return (false, 1);
                }
                return (true, 3);
            }
        }
        _ => {}
    }

    // Check for specific patterns in bits 4:0
    let low5 = pb & 0x1F;

    // Accumulator offset (A, B, or D)
    if pb & 0xE4 == 0xE4 {
        return (true, 1);
    }

    // Auto increment/decrement
    if pb & 0xE0 == 0x20 || pb & 0xE0 == 0x60 {
        return (true, 1);
    }

    // Indirect modes
    if pb & 0xEF == 0xE3 || pb & 0xEF == 0xEF {
        if pos + 2 >= data.len() {
            return (false, 1);
        }
        return (true, 3);
    }

    // Default: treat as 1-byte postbyte
    (true, 1)
}

/// Detect HC12 interrupt vector table at the end of the data.
///
/// HC12 IVT: 64 vectors (128 bytes) at offsets 0xFF80–0xFFFE relative
/// to the logical address space. In a raw flash image, this maps to
/// the last 128 bytes of the image (or the last 128 bytes before any
/// trailing padding).
///
/// Each vector is a 16-bit big-endian address. Valid vectors typically
/// point to addresses in the range 0x4000–0xFFFF (within banked or
/// fixed flash).
///
/// The reset vector at 0xFFFE is always the last 2 bytes.
fn score_vector_table(data: &[u8]) -> i64 {
    if data.len() < 256 {
        return 0;
    }

    // Try the last 128 bytes as the IVT
    let ivt_start = data.len() - 128;
    let ivt = &data[ivt_start..];

    let mut valid_vectors = 0u32;
    let mut total_vectors = 0u32;
    let mut vector_values: Vec<u16> = Vec::with_capacity(64);

    for j in (0..128).step_by(2) {
        let addr = u16::from_be_bytes([ivt[j], ivt[j + 1]]);
        total_vectors += 1;

        // A valid HC12 vector points to code space (typically 0x0800–0xFFFF).
        // Vectors of 0x0000 or 0xFFFF are unprogrammed/unused.
        if addr >= 0x0800 && addr < 0xFFF0 {
            valid_vectors += 1;
            vector_values.push(addr);
        }
    }

    // Need a significant number of valid-looking vectors
    if valid_vectors < 15 {
        return 0;
    }

    let mut score: i64 = 0;

    // Check the reset vector (last 2 bytes of file)
    let reset_vec = u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]);
    if reset_vec >= 0x4000 && reset_vec < 0xFFF0 {
        score += 200; // Very strong signal
    }

    // Check if vectors point to a cluster of addresses (common in real IVTs
    // where most handlers are near each other in the same flash page)
    if vector_values.len() >= 10 {
        // Find the most common high byte (page)
        let mut page_counts = [0u32; 256];
        for &v in &vector_values {
            page_counts[(v >> 8) as usize] += 1;
        }
        let max_page_count = page_counts.iter().max().copied().unwrap_or(0);

        // If many vectors share the same high byte, it's a strong IVT signal
        if max_page_count >= 10 {
            score += 150;
        } else if max_page_count >= 5 {
            score += 80;
        }
    }

    // General bonus for having many valid vectors
    score += (valid_vectors as i64) * 5;

    // Penalty if too many vectors are the same value (could be a fill pattern)
    if vector_values.len() > 5 {
        let mut sorted = vector_values.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() < vector_values.len() / 4 {
            // Too few unique values — likely a fill pattern, not a real IVT
            score /= 3;
        }
    }

    score
}

/// Skip leading padding (all-zero or all-0xFF regions).
/// Returns the offset of the first non-padding byte.
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

    i
}

/// Detect SuperH firmware structural signatures and return a multiplier
/// penalty for the HC12 score. Returns 1.0 (no penalty) if no SH evidence
/// is found, or a value < 1.0 if SH patterns are detected.
///
/// This prevents HC12's byte-level scoring from dominating on SH firmware,
/// where nearly every byte coincidentally maps to a valid HC12 opcode.
fn detect_sh_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    let mut sh_evidence: u32 = 0;

    // ─── Check 1: SH7058 sparse vector table (16-byte stride) ───
    // Pattern: [4-byte 0xFF00xxxx address][12 bytes 0xFF] repeated 4 times
    // at the very start of the file. This is an extremely distinctive
    // structural pattern unique to Renesas SH7058 Mitsubishi ECU firmware.
    if data.len() >= 0x80 {
        let mut sparse_valid = 0u32;
        let mut sparse_ff_padding = 0u32;

        for entry_idx in 0..4 {
            let off = entry_idx * 16;
            if off + 16 > data.len() {
                break;
            }
            let addr = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);

            // Check the 12-byte padding after the address
            let padding_all_ff = data[off + 4..off + 16].iter().all(|&b| b == 0xFF);

            // SH7058 addresses: ROM alias 0xFF000000-0xFF0FFFFF,
            // RAM 0xFFF80000-0xFFFFBFFF, low ROM 0x00000040-0x00FFFFFF
            if is_sh_vector_addr(addr) {
                sparse_valid += 1;
            }
            if padding_all_ff {
                sparse_ff_padding += 1;
            }
        }

        // Two or more valid SH addresses + three or more 0xFF-padded slots
        // is an extremely strong SH7058 sparse vector table signal.
        if sparse_valid >= 2 && sparse_ff_padding >= 3 {
            sh_evidence += 3; // Strong evidence
        }
    }

    // ─── Check 2: Standard (packed) SH vector table at offset 0 ───
    // SH7052 and similar: packed 32-bit BE vectors at offset 0.
    // First entry = Reset PC, second = Reset SP.
    if sh_evidence == 0 && data.len() >= 32 {
        let mut packed_valid = 0u32;
        let check_count = (data.len().min(256) / 4).min(16);

        for v in 0..check_count {
            let off = v * 4;
            let addr = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            if is_sh_vector_addr(addr) && (addr & 1) == 0 {
                packed_valid += 1;
            }
        }

        // Need most entries to be valid SH vectors
        if packed_valid >= check_count as u32 * 3 / 4 && packed_valid >= 6 {
            sh_evidence += 2;
        }
    }

    // ─── Check 3: SH delay-slot compound patterns ───
    // SuperH instructions are 16-bit, and many control-flow instructions use
    // a delay slot (the instruction after the branch always executes). The
    // canonical pattern is RTS;NOP which is 0x000B 0x0009 as big-endian bytes.
    // These 4-byte sequences are highly characteristic of SH code.
    if data.len() >= 1024 {
        let sh_compounds = count_sh_compound_patterns(data);
        let density = sh_compounds as f64 / (data.len() as f64 / 4.0);

        // In real SH firmware, RTS;NOP appears roughly once per 200-1000
        // bytes (density ~0.001 to 0.005). In non-SH data, these exact
        // 4-byte sequences are extremely rare.
        if sh_compounds >= 20 && density > 0.0005 {
            sh_evidence += 2;
        } else if sh_compounds >= 5 {
            sh_evidence += 1;
        }
    }

    // ─── Apply penalty based on accumulated evidence ───
    if sh_evidence >= 3 {
        // Very strong SH evidence (sparse vector table or vector table +
        // compound patterns). This is definitively SH firmware.
        0.08
    } else if sh_evidence >= 2 {
        // Strong SH evidence (packed vector table or compound patterns).
        0.15
    } else if sh_evidence >= 1 {
        // Moderate SH evidence (some compound patterns only).
        0.40
    } else {
        1.0 // No SH evidence, no penalty
    }
}

/// Check if a 32-bit address is a valid SuperH vector table entry.
///
/// Valid SH address ranges:
/// - ROM: 0x00000040–0x00FFFFFF (internal/external flash)
/// - ROM alias: 0xFF000000–0xFF0FFFFF (SH7058 alias window)
/// - RAM: 0xFFF80000–0xFFFFBFFF (varies by chip: SH7052=16KB, SH7058=48KB, SH7055F=512KB)
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

/// Count SH compound delay-slot patterns in data.
///
/// SuperH uses delay slots after control-flow instructions. The most common
/// patterns are:
/// - RTS;NOP  = 0x000B 0x0009 (return from subroutine; delay slot NOP)
/// - RTE;NOP  = 0x002B 0x0009 (return from exception; delay slot NOP)
/// - JMP;NOP  = 0x402B 0x0009 (indirect jump; delay slot NOP) — but JMP @Rn
///   has varying register, so the full pattern varies: 0x4n2B 0x0009
/// - JSR;NOP  = 0x4n0B 0x0009 (indirect call; delay slot NOP)
/// - BRA;NOP  = 0xAnxx 0x0009 (branch; delay slot NOP)
/// - BSR;NOP  = 0xBnxx 0x0009 (branch to subroutine; delay slot NOP)
///
/// We scan for the NOP (0x0009) at halfword boundaries and check if the
/// preceding halfword is a control-flow instruction.
fn count_sh_compound_patterns(data: &[u8]) -> u32 {
    let mut count: u32 = 0;

    // We need at least 4 bytes and must be on 2-byte (halfword) boundaries
    if data.len() < 4 {
        return 0;
    }

    let end = data.len() - 3;
    let mut i = 2; // Start at offset 2 (second halfword)
    while i < end {
        // Check for SH NOP (0x0009) at this halfword position (big-endian)
        if data[i] == 0x00 && data[i + 1] == 0x09 {
            // Check the preceding halfword for a control-flow instruction
            let prev_hi = data[i - 2];
            let prev_lo = data[i - 1];

            let is_rts_nop = prev_hi == 0x00 && prev_lo == 0x0B; // RTS = 0x000B
            let is_rte_nop = prev_hi == 0x00 && prev_lo == 0x2B; // RTE = 0x002B
            let is_jmp_nop = (prev_hi & 0xF0) == 0x40 && prev_lo == 0x2B; // JMP @Rn = 0x4n2B
            let is_jsr_nop = (prev_hi & 0xF0) == 0x40 && prev_lo == 0x0B; // JSR @Rn = 0x4n0B
            let is_bra_nop = (prev_hi & 0xF0) == 0xA0; // BRA disp = 0xAnxx
            let is_bsr_nop = (prev_hi & 0xF0) == 0xB0; // BSR disp = 0xBnxx

            if is_rts_nop || is_rte_nop || is_jmp_nop || is_jsr_nop || is_bra_nop || is_bsr_nop {
                count += 1;
            }
        }

        i += 2; // Step by halfword
    }

    count
}

/// Detect C166 (Infineon/Siemens C16x/ST10) firmware structural signatures and
/// return a multiplier penalty for the HC12 score. Returns 1.0 (no penalty) if
/// no C166 evidence is found, or a value < 1.0 if C166 patterns are detected.
///
/// IMPORTANT: This penalty must use only high-specificity multi-byte patterns
/// that are genuinely rare in HCS12 data. Single-byte opcode matches (JMPR by
/// lower-nibble, BSET/BCLR by lower-nibble) produce massive false positives on
/// HCS12 firmware because HC12 opcodes share many byte values with C166. The
/// key discriminators are:
///
/// - **RET (0xCB 0x00)** — HC12 has no 0xCB opcode, and the 2-byte sequence
///   0xCB00 is extremely rare in non-C166 data. Real C166 code has RET at
///   ~2-5% density (per halfword).
/// - **RETS (0xDB 0x00)** — segmented return, unique to C166.
/// - **RET;NOP compound (0xCB 0x00 0xCC 0x00)** — 4-byte sequence, very specific.
/// - **CALLR (0xBB nn) followed by RET at function end** — real C166 code has
///   CALLR at high density (>0.4%); HCS12 has 0xBB but at much lower density
///   because it's a specific opcode (not a call).
/// - **EXTS (0xD7) with proper operand** — unique to C166, but the single byte
///   0xD7 can appear in HCS12 data by chance. We require density > 0.5% to count.
fn detect_c166_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    // Count high-specificity C166 multi-byte patterns by scanning in 2-byte
    // steps (little-endian instruction format: opcode at even offset, operand
    // at odd offset). We intentionally exclude single-byte-class matches like
    // JMPR (lower nibble 0xD) and BSET/BCLR (lower nibble 0xF/0xE) because
    // those produce massive false positives on HCS12 data.
    let mut ret_count: u32 = 0; // RET = 0xCB 0x00
    let mut rets_count: u32 = 0; // RETS = 0xDB 0x00
    let mut callr_count: u32 = 0; // CALLR = 0xBB nn
    let mut calls_count: u32 = 0; // CALLS = 0xDA nn nn nn (4-byte)
    let mut exts_count: u32 = 0; // EXTS = 0xD7 (unique segment override)
    let mut extr_count: u32 = 0; // EXTR = 0xD1 (unique register override)
    let mut push_pop_count: u32 = 0; // PUSH (0xEC Fn) / POP (0xFC Fn)
    let mut ret_nop_count: u32 = 0; // RET;NOP = 0xCB 0x00 0xCC 0x00

    // Skip leading erased flash (0xFF/0x00 regions) to focus on code
    let start = skip_padding(data);
    if start >= data.len().saturating_sub(32) {
        return 1.0; // File is mostly erased
    }

    let scan_end = data.len().saturating_sub(1);
    let mut i = start;
    // Align to even offset
    if i & 1 != 0 {
        i += 1;
    }

    while i + 1 < scan_end {
        let opcode = data[i];
        let operand = data[i + 1];

        match opcode {
            // RET = 0xCB 0x00 — the strongest 2-byte discriminator.
            // HC12 has no 0xCB opcode, so this pair is very rare in HCS12 data.
            0xCB if operand == 0x00 => {
                ret_count += 1;
                // Check for RET;NOP compound (0xCB 0x00 0xCC 0x00)
                if i + 3 < data.len() && data[i + 2] == 0xCC && data[i + 3] == 0x00 {
                    ret_nop_count += 1;
                }
            }
            // RETS = 0xDB 0x00 — segmented return, unique to C166
            0xDB if operand == 0x00 => {
                rets_count += 1;
            }
            // EXTS = 0xD7 — extended segment, unique to C166.
            // Validate operand: bits 7:6 encode irang2 (count 1-4), must be 00/01/10/11
            // all are valid, but we additionally require bits 5:0 (seg) to be a
            // plausible segment number (0-255, which is always true for 6 bits).
            0xD7 => {
                exts_count += 1;
            }
            // EXTR = 0xD1 — extended register bank, unique to C166.
            // Operand bits 7:6 encode count 1-4, bits 5:0 are reserved/zero in
            // most usage. We count any occurrence.
            0xD1 => {
                extr_count += 1;
            }
            // CALLR = 0xBB nn — relative call with 8-bit displacement.
            0xBB => {
                callr_count += 1;
            }
            // CALLS = 0xDA nn nn nn — segmented call (4-byte instruction).
            // The second byte is segment number, bytes 3-4 are offset.
            0xDA => {
                calls_count += 1;
                // CALLS is 4 bytes; skip the extra 2
                i += 4;
                continue;
            }
            // PUSH reg = 0xEC Fn — register in operand byte, F0-FF = word registers
            0xEC if operand >= 0xF0 => {
                push_pop_count += 1;
            }
            // POP reg = 0xFC Fn
            0xFC if operand >= 0xF0 => {
                push_pop_count += 1;
            }
            _ => {}
        }

        i += 2;
    }

    // ─── Evaluate evidence using density-normalized metrics ───
    //
    // The key insight: raw counts are meaningless for cross-architecture
    // comparison because a 768KB HCS12 file will accumulate hundreds of
    // coincidental pattern matches. We must use **density** (count per
    // halfword of code) as the discriminator.
    //
    // Real C166 firmware densities (measured from C167BootTool .bin files):
    //   RET+RETS:   0.015 - 0.057 per halfword
    //   EXTS/EXTR:  0.010 - 0.055 per halfword
    //   CALLR:      0.004 - 0.200 per halfword
    //
    // HCS12 firmware densities (measured from Solano 768KB):
    //   RET+RETS:   0.00003 per halfword  (1800x lower)
    //   EXTS/EXTR:  0.00280 per halfword  (4-20x lower)
    //   CALLR:      0.00048 per halfword  (8-400x lower)

    let code_len = data.len() - start;
    if code_len < 32 {
        return 1.0;
    }
    let halfwords = code_len as f64 / 2.0;

    let ret_total = ret_count + rets_count;
    let exts_extr_total = exts_count + extr_count;

    let ret_density = ret_total as f64 / halfwords;
    let exts_density = exts_extr_total as f64 / halfwords;
    let callr_density = callr_count as f64 / halfwords;

    let mut c166_evidence: u32 = 0;

    // RET+RETS density is the single strongest discriminator.
    // Real C166: >= 0.015. HCS12: ~0.00003. Threshold at 0.005.
    if ret_density >= 0.010 {
        c166_evidence += 3; // Very strong — definitively C166
    } else if ret_density >= 0.005 {
        c166_evidence += 2;
    } else if ret_total >= 3 && ret_density >= 0.001 {
        c166_evidence += 1;
    }

    // EXTS/EXTR density. Real C166: >= 0.010. HCS12: ~0.003.
    // Use a higher threshold to avoid false triggers.
    if exts_density >= 0.008 {
        c166_evidence += 2;
    } else if exts_density >= 0.004 && exts_extr_total >= 3 {
        c166_evidence += 1;
    }

    // CALLR density. Real C166: >= 0.004. HCS12: ~0.0005.
    if callr_density >= 0.003 {
        c166_evidence += 1;
    }

    // RET;NOP compound (4-byte sequence) — extremely specific
    if ret_nop_count >= 2 {
        c166_evidence += 1;
    }

    // PUSH/POP with register operand — somewhat distinctive at high density
    let push_pop_density = push_pop_count as f64 / halfwords;
    if push_pop_density >= 0.005 && push_pop_count >= 4 {
        c166_evidence += 1;
    }

    // Correlation: having BOTH returns and calls is strong evidence of real code
    let call_total = callr_count + calls_count;
    if ret_total >= 2 && call_total >= 2 {
        c166_evidence += 1;
    }

    // ─── Apply penalty based on accumulated evidence ───
    if c166_evidence >= 5 {
        // Overwhelming C166 evidence — this is definitely C166 firmware.
        0.08
    } else if c166_evidence >= 3 {
        // Strong C166 evidence.
        0.15
    } else if c166_evidence >= 2 {
        // Moderate C166 evidence.
        0.40
    } else {
        // Weak or no C166 evidence — no penalty.
        // We deliberately don't apply a penalty for evidence < 2, because
        // random coincidences in large HCS12 files can reach evidence=1.
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hcs12_rts() {
        // RTS (0x3D) is the most basic function return
        let code = [
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
            0x3D, // RTS
        ];
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_hcs12_basic_function() {
        // Simple HC12 function: LDAA #0x42, STAA $0050, RTS
        // Verified with: cstool cpu12 "8642 5a50 3d"
        let code = [
            0x86, 0x42, // LDAA #$42
            0x5A, 0x50, // STAA $0050
            0x3D, // RTS
            0x86, 0x42, // LDAA #$42
            0x5A, 0x50, // STAA $0050
            0x3D, // RTS
            0x86, 0x42, // LDAA #$42
            0x5A, 0x50, // STAA $0050
            0x3D, // RTS
            0x86, 0x42, // LDAA #$42
        ];
        let s = score(&code);
        assert!(s > 10, "Basic HC12 function should score well, got {}", s);
    }

    #[test]
    fn test_hcs12_branches() {
        // BRA, BNE, BEQ, BSR — common in HC12 code
        let code = [
            0x86, 0x10, // LDAA #$10
            0xC6, 0x11, // LDAB #$11
            0x27, 0x04, // BEQ +4
            0x26, 0x02, // BNE +2
            0x20, 0x0A, // BRA +10
            0x07, 0x10, // BSR +16
            0x3D, // RTS
            0x86, 0x10, // LDAA #$10
            0x3D, // RTS
            0x86, 0x10, // filler
        ];
        let s = score(&code);
        assert!(s > 10, "HC12 branch code should score well, got {}", s);
    }

    #[test]
    fn test_hcs12_page2_instructions() {
        // Page 2 instructions with 0x18 prefix
        let code = [
            0x18, 0x06, // ABA (A + B → A)
            0x18, 0x0E, // TAB (A → B)
            0x18, 0x16, // SBA (A - B → A)
            0x18, 0x26, 0x00, 0x10, // LBNE +16
            0x18, 0x27, 0x00, 0x20, // LBEQ +32
            0x3D, // RTS
            0x3D, // RTS
        ];
        let s = score(&code);
        assert!(
            s > 10,
            "HC12 page2 instructions should score well, got {}",
            s
        );
    }

    #[test]
    fn test_hcs12_jsr_extended() {
        // JSR $BA86 — verified from real Solano firmware
        // cstool cpu12 "16ba86" → jsr $ba86
        let code = [
            0x16, 0xBA, 0x86, // JSR $BA86
            0x16, 0xCF, 0x88, // JSR $CF88
            0x16, 0xD7, 0x62, // JSR $D762
            0x3D, // RTS
            0x16, 0xBA, 0x86, // JSR $BA86
            0x3D, // RTS
            0x16, 0xBA, 0x86, // filler
        ];
        let s = score(&code);
        assert!(s > 10, "HC12 JSR code should score well, got {}", s);
    }

    #[test]
    fn test_hcs12_push_pull() {
        // Stack operations — function prologue/epilogue pattern
        let code = [
            0x36, // PSHA
            0x37, // PSHB
            0x34, // PSHX
            0x86, 0x42, // LDAA #$42
            0x5A, 0x50, // STAA $0050
            0x30, // PULX
            0x33, // PULB
            0x32, // PULA
            0x3D, // RTS
            0x36, // filler
            0x37, // filler
            0x34, // filler
            0x86, 0x42, // filler
            0x5A, 0x50, // filler
        ];
        let s = score(&code);
        assert!(s > 10, "HC12 push/pull should score well, got {}", s);
    }

    #[test]
    fn test_hcs12_rtc_banked() {
        // RTC (0x0A) — banked return, HCS12X specific
        let code = [
            0x4A, 0xBA, 0x86, 0xF0, // CALL $BA86 page $F0
            0x0A, // RTC
            0x4A, 0xCF, 0x88, 0xF1, // CALL $CF88 page $F1
            0x0A, // RTC
            0x86, 0x42, // LDAA #$42
            0x3D, // RTS
            0x86, 0x42, // filler
            0x3D, // filler
        ];
        let s = score(&code);
        assert!(s > 10, "HC12 RTC/CALL should score well, got {}", s);
    }

    #[test]
    fn test_hcs12_with_leading_zeros() {
        // Simulate firmware with leading zero padding
        let mut data = vec![0x00u8; 256];
        // Append actual code
        data.extend_from_slice(&[
            0x86, 0x42, // LDAA #$42
            0x5A, 0x50, // STAA $0050
            0x16, 0xBA, 0x86, // JSR $BA86
            0x27, 0x04, // BEQ +4
            0x3D, // RTS
            0x86, 0x42, // LDAA #$42
            0x5A, 0x50, // STAA $0050
            0xC6, 0x11, // LDAB #$11
            0x16, 0xCF, 0x88, // JSR $CF88
            0x3D, // RTS
        ]);
        let s = score(&data);
        assert!(s > 0, "Should handle leading zero padding, got score {}", s);
    }

    #[test]
    fn test_hcs12_not_x86() {
        // x86 prologue should not score well as HC12
        let x86_code = [
            0x55, // push ebp
            0x89, 0xE5, // mov ebp, esp
            0x83, 0xEC, 0x10, // sub esp, 0x10
            0x89, 0x45, 0xFC, // mov [ebp-4], eax
            0xC9, // leave
            0xC3, // ret
            0x55, // push ebp
            0x89, 0xE5, // mov ebp, esp
            0x83, 0xEC, 0x10, // filler
        ];
        let s = score(&x86_code);
        // x86 code might get some incidental hits but should be modest
        assert!(
            s < 50,
            "x86 code should not score highly as HC12, got {}",
            s
        );
    }

    #[test]
    fn test_hcs12_vector_table() {
        // Simulate a minimal file with a vector table at the end
        let mut data = vec![0x00u8; 256];
        // Fill in some code
        for j in 0..64 {
            data[j] = 0x3D; // RTS instructions as filler code
        }
        // Add vector table at the end (last 128 bytes)
        let ivt_start = data.len() - 128;
        for j in (0..128).step_by(2) {
            // Vectors pointing to 0xF600-0xF6xx range
            data[ivt_start + j] = 0xF6;
            data[ivt_start + j + 1] = ((j / 2) % 64) as u8;
        }
        // Reset vector at the very end
        let len = data.len();
        data[len - 2] = 0xF8;
        data[len - 1] = 0x08;

        let s = score(&data);
        assert!(
            s > 100,
            "Vector table should boost score significantly, got {}",
            s
        );
    }

    #[test]
    fn test_hcs12_real_firmware_bytes() {
        // First 64 bytes of actual Solano ECU code (from offset 0x087A62)
        // Verified with: cstool cpu12 "795e5b16ba86..." 0xF808
        let code: Vec<u8> = hex_decode(
            "795e5b16ba8618045e845e57c61116cf887b5e56698216b7da6282e682c11125f51b830afc5e843bccc6ef16d7627c5e781801805e84cc822416d7627c5e76"
        );
        let s = score(&code);
        assert!(s > 20, "Real HC12 firmware should score well, got {}", s);
    }

    /// Helper: decode a hex string into bytes
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
