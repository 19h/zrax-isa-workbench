//! Heuristic scoring for Motorola 68HC11 instruction set architecture.
//!
//! The 68HC11 is an 8-bit big-endian microcontroller in the Motorola 6800
//! family lineage. It was widely used in automotive ECUs, industrial controls,
//! medical devices, and embedded systems from the mid-1980s through the 2000s.
//! It is the direct predecessor to the 68HC12/HCS12 family.
//!
//! Key characteristics for heuristic detection:
//! - **Big-endian** (Motorola byte order): addresses stored MSB first
//! - **Variable-length instructions**: 1 to 5 bytes, byte-aligned
//! - **Accumulator-based**: two 8-bit accumulators A and B, combinable as
//!   the 16-bit D register (A=high byte, B=low byte)
//! - **Index registers**: X, Y (16-bit), stack pointer SP (16-bit)
//! - **Addressing modes**: inherent, immediate, direct (8-bit addr), extended
//!   (16-bit addr), indexed (offset + X or Y), relative (branches)
//!
//! **Instruction prefixes**:
//! - 0x18: Y-indexed prefix — redirects X-indexed instructions to use Y instead
//! - 0x1A: Y-indexed prefix for additional instructions (e.g., CPD, LDY)
//! - 0xCD: prefix for extended Y-indexed addressing forms (LDY ext, STY ext, etc.)
//!
//! **Opcode map highlights** (distinctive to HC11):
//! - RTS = 0x39 (return from subroutine) — extremely common, every function
//!   ends with it. This is the strongest single-byte signature.
//! - RTI = 0x3B (return from interrupt)
//! - WAI = 0x3E (wait for interrupt)
//! - SWI = 0x3F (software interrupt)
//! - NOP = 0x01 (NOT 0x00 — 0x00 is TEST, a factory test instruction)
//! - TAB = 0x16, TBA = 0x17 (transfer between A and B)
//! - ABA = 0x1B (add B to A)
//! - SBA = 0x10 (subtract B from A)
//! - CBA = 0x11 (compare B with A)
//! - DAA = 0x19 (decimal adjust A after BCD arithmetic)
//!
//! **HC11 vs HC12 disambiguation**:
//! HC11 and HC12 share many opcodes from their common M6800 heritage, but
//! differ in critical ways:
//! - HC12 RTS is 0x3D; HC11 RTS is 0x39
//! - HC12 has complex indexed addressing (postbyte-based); HC11 uses simple
//!   8-bit offset + X (or + Y with prefix)
//! - HC12 has page-2 instructions via 0x18 prefix with a different opcode set;
//!   HC11 uses 0x18 to redirect X-indexed modes to Y-indexed modes
//! - HC12 BSR is 0x07; HC11 BSR is 0x8D
//! - HC12 JMP extended is 0x06; HC11 JMP extended is 0x7E
//! - HC12 JSR extended is 0x16/0x17; HC11 JSR extended is 0xBD
//!
//! **Zero handling**: 0x00 = TEST (factory test instruction), NOT NOP. Zero runs
//! in firmware data are padding/erased flash and must be penalized, not rewarded.
//!
//! References:
//! - Motorola MC68HC11 Reference Manual (MC68HC11RM/AD)
//! - Motorola M68HC11E Family Data Sheet
//! - MC68HC11A8 Technical Reference

use std::cmp;

/// Score raw data as Motorola 68HC11 code.
///
/// The scorer walks through the data byte-by-byte, interpreting each position
/// as a potential HC11 instruction. It recognizes page-1 (single-byte) opcodes,
/// prefixed opcodes (0x18/0x1A/0xCD for Y-indexed modes), and assigns
/// per-instruction scores weighted by distinctiveness. Structural bonuses are
/// applied when patterns characteristic of real HC11 firmware are detected.
///
/// A cross-architecture penalty is applied when strong HC12/HCS12 evidence is
/// detected, since HC11 and HC12 share many opcode values and can confuse each
/// other's scorers.
///
/// Returns a non-negative score (clamped at 0).
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 16 {
        return 0;
    }

    // Skip leading zero/0xFF padding — common in firmware flash images
    let start = skip_padding(data);
    let working = &data[start..];

    if working.len() < 16 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut i = 0;

    // ─── Structural counters ───
    let mut rts_count: u32 = 0; // RTS (0x39)
    let mut rti_count: u32 = 0; // RTI (0x3B)
    let mut swi_count: u32 = 0; // SWI (0x3F)
    let mut wai_count: u32 = 0; // WAI (0x3E)
    let mut _bra_count: u32 = 0; // BRA (0x20) — unconditional branch
    let mut bcc_count: u32 = 0; // Conditional branches (0x22-0x2F)
    let mut bsr_count: u32 = 0; // BSR (0x8D)
    let mut jsr_count: u32 = 0; // JSR (0x9D/0xAD/0xBD)
    let mut jmp_count: u32 = 0; // JMP (0x6E/0x7E)
    let mut load_count: u32 = 0; // LDAA/LDAB/LDD/LDX/LDS
    let mut store_count: u32 = 0; // STAA/STAB/STD/STX/STS
    let mut push_pull_count: u32 = 0; // PSHA/PSHB/PSHX/PULA/PULB/PULX
    let mut nop_count: u32 = 0; // NOP (0x01)
    let mut prefix_count: u32 = 0; // 0x18/0x1A/0xCD prefix sequences
    let mut xfer_count: u32 = 0; // TAB/TBA/ABA/SBA/CBA inter-register ops
    let mut clr_tst_count: u32 = 0; // CLR/CLRA/CLRB/TSTA/TSTB
    let mut flag_count: u32 = 0; // SEC/CLC/SEI/CLI/SEV/CLV
    let mut valid_insn_count: u32 = 0;
    let mut invalid_count: u32 = 0;
    let mut zero_run: u32 = 0;

    while i < working.len() {
        let opcode = working[i];

        // ─── Handle zero bytes ───
        // 0x00 = TEST (factory test instruction), NOT NOP. In real HC11 code
        // this instruction is never used (it's for Motorola factory testing).
        // Zero runs indicate padding or erased flash — penalize them.
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

        // ─── Update structural counters based on opcode ───
        match opcode {
            0x39 => rts_count += 1,
            0x3B => rti_count += 1,
            0x3F => swi_count += 1,
            0x3E => wai_count += 1,
            0x01 => nop_count += 1,
            0x20 => _bra_count += 1,
            0x22..=0x2F => bcc_count += 1,
            0x8D => bsr_count += 1,
            0x9D | 0xAD | 0xBD => jsr_count += 1,
            0x6E | 0x7E => jmp_count += 1,
            // Load A
            0x86 | 0x96 | 0xA6 | 0xB6 => load_count += 1,
            // Load B
            0xC6 | 0xD6 | 0xE6 | 0xF6 => load_count += 1,
            // LDD
            0xCC | 0xDC | 0xEC | 0xFC => load_count += 1,
            // LDX
            0xCE | 0xDE | 0xEE | 0xFE => load_count += 1,
            // LDS
            0x8E | 0x9E | 0xAE | 0xBE => load_count += 1,
            // Store A
            0x97 | 0xA7 | 0xB7 => store_count += 1,
            // Store B
            0xD7 | 0xE7 | 0xF7 => store_count += 1,
            // STD
            0xDD | 0xED | 0xFD => store_count += 1,
            // STX
            0xDF | 0xEF | 0xFF => store_count += 1,
            // STS
            0x9F | 0xAF | 0xBF => store_count += 1,
            // Push/Pull
            0x36 | 0x37 | 0x3C => push_pull_count += 1, // PSHA, PSHB, PSHX
            0x32 | 0x33 | 0x38 => push_pull_count += 1, // PULA, PULB, PULX
            // Inter-register transfers
            0x16 | 0x17 | 0x1B | 0x10 | 0x11 => xfer_count += 1,
            // CLR/TST inherent
            0x4F | 0x5F => clr_tst_count += 1, // CLRA, CLRB
            0x4D | 0x5D => clr_tst_count += 1, // TSTA, TSTB
            0x6F | 0x7F => clr_tst_count += 1, // CLR idx, CLR ext
            0x6D | 0x7D => clr_tst_count += 1, // TST idx, TST ext
            // Flag manipulation
            0x0A | 0x0B | 0x0C | 0x0D | 0x0E | 0x0F => flag_count += 1,
            // Y-indexed prefixes
            0x18 | 0x1A | 0xCD => prefix_count += 1,
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

        // RTS (0x39) — function return. Every subroutine ends with it.
        // This is the single most common instruction in HC11 code.
        if rts_count > 5 {
            total_score += (rts_count as i64) * 8;
        }

        // RTI (0x3B) — interrupt return. Limited count but very specific.
        if rti_count > 0 {
            total_score += (rti_count as i64) * 12;
        }

        // WAI (0x3E) — wait for interrupt. Rare but distinctive.
        if wai_count > 0 {
            total_score += (wai_count as i64) * 10;
        }

        // SWI (0x3F) — software interrupt. Rare but distinctive.
        if swi_count > 0 {
            total_score += (swi_count as i64) * 8;
        }

        // Conditional branches (0x22-0x2F) — extremely common in real code.
        // BNE (0x26) and BEQ (0x27) are the most frequent.
        if bcc_count > 10 {
            total_score += (bcc_count as i64) * 3;
        }

        // BSR (0x8D) — branch to subroutine, relative call
        if bsr_count > 2 {
            total_score += (bsr_count as i64) * 6;
        }

        // JSR (0x9D/0xAD/0xBD) — absolute/indexed subroutine call, very common
        if jsr_count > 5 {
            total_score += (jsr_count as i64) * 5;
        }

        // JMP (0x6E/0x7E) — unconditional jump
        if jmp_count > 2 {
            total_score += (jmp_count as i64) * 3;
        }

        // Load instructions are extremely common in firmware
        if load_count > 20 {
            total_score += (load_count as i64) * 2;
        }

        // Store instructions
        if store_count > 10 {
            total_score += (store_count as i64) * 2;
        }

        // Push/Pull (function prologue/epilogue)
        if push_pull_count > 3 {
            total_score += (push_pull_count as i64) * 4;
        }

        // Inter-register transfers (TAB/TBA/ABA/SBA/CBA) — distinctive to
        // 6800-family MCUs, no modern RISC has these
        if xfer_count > 2 {
            total_score += (xfer_count as i64) * 6;
        }

        // Y-indexed prefix (0x18/0x1A/0xCD) — characteristic of HC11 when
        // using the Y register. HC12 also uses 0x18 but for a completely
        // different page-2 opcode expansion.
        if prefix_count > 3 {
            total_score += (prefix_count as i64) * 3;
        }

        // CLR/TST instructions (common for flag/register initialization)
        if clr_tst_count > 3 {
            total_score += (clr_tst_count as i64) * 2;
        }

        // Flag manipulation (SEC/CLC/SEI/CLI/SEV/CLV) — distinctive inherent
        // instructions. SEI (0x0F) = disable interrupts is extremely common
        // in interrupt service routines.
        if flag_count > 2 {
            total_score += (flag_count as i64) * 4;
        }

        // NOP (0x01) — sometimes used for timing delays in HC11 firmware
        if nop_count > 2 {
            total_score += (nop_count as i64) * 2;
        }

        // Combined structural signature: multiple HC11-specific features present
        let signature_features = [
            rts_count > 10,                 // Function returns
            bcc_count > 20,                 // Conditional branches
            jsr_count > 5 || bsr_count > 3, // Subroutine calls
            load_count > 30,                // Load instructions
            store_count > 15,               // Store instructions
            push_pull_count > 3,            // Stack operations
            xfer_count > 2,                 // Inter-register transfers (very HC11-specific)
            flag_count > 2,                 // Flag manipulation
            prefix_count > 3,               // Y-indexed prefix usage
        ];
        let feature_count = signature_features.iter().filter(|&&f| f).count();
        if feature_count >= 6 {
            total_score += (valid_insn_count as i64) / 2;
        } else if feature_count >= 4 {
            total_score += (valid_insn_count as i64) / 4;
        } else if feature_count >= 3 {
            total_score += (valid_insn_count as i64) / 6;
        }
    }

    // ─── Interrupt vector table detection ───
    // HC11 has an interrupt vector table at the end of address space
    // (0xFFD6–0xFFFE for the MC68HC11A8). The reset vector is at 0xFFFE.
    // In a raw flash image, this maps to the last bytes of the image.
    total_score += score_vector_table(data);

    // ─── Cross-architecture penalty: HC12/HCS12 detection ───
    //
    // HC11 and HC12 share many opcodes from the M6800 heritage. When scanning
    // HC12 firmware as HC11, many bytes will coincidentally match valid HC11
    // opcodes. We detect HC12-specific patterns and penalize accordingly.
    //
    // Key HC12 discriminators:
    // - HC12 RTS is 0x3D (HC11 uses 0x39, and 0x3D has no meaning in HC11)
    // - HC12 page-2 prefix 0x18 followed by ABA (0x06), TAB (0x0E), TBA (0x0F),
    //   LBRA (0x20-0x2F), etc. — these 2-byte sequences differ from HC11's
    //   0x18+indexed patterns
    // - HC12 uses complex indexed postbyte addressing; HC11 does not
    // - HC12 BSR is 0x07; in HC11, 0x07 is not a valid opcode
    // - HC12 JMP extended is 0x06; in HC11, 0x06 is TAP
    let hc12_penalty = detect_hc12_cross_arch_penalty(data);
    if hc12_penalty > 0.0 && hc12_penalty < 1.0 {
        total_score = (total_score as f64 * hc12_penalty) as i64;
    }

    cmp::max(0, total_score)
}

/// Score a single HC11 instruction at position `i` in `data`.
/// Returns (score, instruction_length_in_bytes).
fn score_instruction(opcode: u8, data: &[u8], i: usize) -> (i64, usize) {
    // ─── Y-indexed prefix (0x18) ───
    // When 0x18 appears, the following instruction uses Y instead of X for
    // indexed addressing. The next byte is the actual opcode, and operands
    // are reinterpreted for Y. This adds 1 byte to the instruction length.
    if opcode == 0x18 {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        let next = data[i + 1];
        return score_prefix_18_instruction(next, data, i);
    }

    // ─── 0x1A prefix: additional Y-indexed forms ───
    // Used for CPD and LDY in some addressing modes.
    if opcode == 0x1A {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        let next = data[i + 1];
        return score_prefix_1a_instruction(next, data, i);
    }

    // ─── 0xCD prefix: LDY extended and STY extended ───
    if opcode == 0xCD {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        let next = data[i + 1];
        return score_prefix_cd_instruction(next, data, i);
    }

    // ─── Inherent (1-byte) instructions ───
    // These take no operand — the opcode IS the entire instruction.
    match opcode {
        // ── Control flow ──
        0x39 => return (14, 1), // RTS — return from subroutine (VERY common)
        0x3B => return (15, 1), // RTI — return from interrupt
        0x3E => return (12, 1), // WAI — wait for interrupt
        0x3F => return (10, 1), // SWI — software interrupt
        0x01 => return (6, 1),  // NOP

        // ── Inter-register transfers (unique to 6800/HC11 family) ──
        0x16 => return (8, 1), // TAB — transfer A to B
        0x17 => return (8, 1), // TBA — transfer B to A
        0x1B => return (8, 1), // ABA — add B to A
        0x10 => return (7, 1), // SBA — subtract B from A
        0x11 => return (7, 1), // CBA — compare B with A

        // ── Decimal adjust ──
        0x19 => return (8, 1), // DAA — decimal adjust A (BCD arithmetic)

        // ── Index register / stack pointer manipulation ──
        0x08 => return (5, 1), // INX — increment X
        0x09 => return (5, 1), // DEX — decrement X
        0x31 => return (5, 1), // INS — increment SP
        0x34 => return (5, 1), // DES — decrement SP
        0x30 => return (4, 1), // TSX — transfer SP to X
        0x35 => return (4, 1), // TXS — transfer X to SP

        // ── Condition code register ──
        0x06 => return (5, 1), // TAP — transfer A to CCR
        0x07 => return (5, 1), // TPA — transfer CCR to A

        // ── Flag manipulation (inherent, 1-byte) ──
        0x0A => return (6, 1), // CLV — clear overflow flag
        0x0B => return (6, 1), // SEV — set overflow flag
        0x0C => return (6, 1), // CLC — clear carry flag
        0x0D => return (6, 1), // SEC — set carry flag
        0x0E => return (7, 1), // CLI — clear interrupt mask (enable interrupts)
        0x0F => return (7, 1), // SEI — set interrupt mask (disable interrupts)

        // ── Push/Pull (1-byte) ──
        0x36 => return (6, 1), // PSHA — push A onto stack
        0x37 => return (6, 1), // PSHB — push B onto stack
        0x3C => return (6, 1), // PSHX — push X onto stack
        0x32 => return (6, 1), // PULA — pull A from stack
        0x33 => return (6, 1), // PULB — pull B from stack
        0x38 => return (6, 1), // PULX — pull X from stack

        // ── Accumulator A unary operations (inherent, 1-byte) ──
        0x4F => return (5, 1), // CLRA — clear A
        0x4C => return (4, 1), // INCA — increment A
        0x4A => return (4, 1), // DECA — decrement A
        0x4D => return (4, 1), // TSTA — test A (set flags)
        0x43 => return (4, 1), // COMA — complement A (1's complement)
        0x40 => return (4, 1), // NEGA — negate A (2's complement)
        0x48 => return (3, 1), // ASLA/LSLA — arithmetic shift left A
        0x47 => return (3, 1), // ASRA — arithmetic shift right A
        0x44 => return (3, 1), // LSRA — logical shift right A
        0x49 => return (3, 1), // ROLA — rotate left through carry A
        0x46 => return (3, 1), // RORA — rotate right through carry A

        // ── Accumulator B unary operations (inherent, 1-byte) ──
        0x5F => return (5, 1), // CLRB — clear B
        0x5C => return (4, 1), // INCB — increment B
        0x5A => return (4, 1), // DECB — decrement B
        0x5D => return (4, 1), // TSTB — test B
        0x53 => return (4, 1), // COMB — complement B
        0x50 => return (4, 1), // NEGB — negate B
        0x58 => return (3, 1), // ASLB/LSLB
        0x57 => return (3, 1), // ASRB
        0x54 => return (3, 1), // LSRB
        0x59 => return (3, 1), // ROLB
        0x56 => return (3, 1), // RORB

        // ── Multiply/Divide ──
        0x3D => return (6, 1), // MUL — A × B → D (unsigned multiply)

        // ── STOP ──
        0xCF => {
            // STOP — stop all clocks (1 byte, but same position as LDS #imm16)
            // This could be LDS #imm16 if followed by 2 bytes. Context-dependent.
            // Score it as LDS immediate which is more likely in real firmware.
            if i + 2 < data.len() {
                return (5, 3); // LDS #imm16
            }
            return (2, 1);
        }

        _ => {}
    }

    // ─── 2-byte relative branch instructions (0x20-0x2F) ───
    // Format: opcode + signed 8-bit relative offset
    if (0x20..=0x2F).contains(&opcode) {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        let _rel = data[i + 1] as i8;
        match opcode {
            0x20 => return (7, 2),        // BRA — unconditional branch
            0x21 => return (3, 2),        // BRN — branch never (2-byte NOP)
            0x26 | 0x27 => return (7, 2), // BNE / BEQ — extremely common
            0x24 | 0x25 => return (6, 2), // BCC/BHS / BCS/BLO
            0x22 | 0x23 => return (5, 2), // BHI / BLS
            0x28 | 0x29 => return (5, 2), // BVC / BVS
            0x2A | 0x2B => return (5, 2), // BPL / BMI
            0x2C | 0x2D => return (5, 2), // BGE / BLT
            0x2E | 0x2F => return (5, 2), // BGT / BLE
            _ => return (4, 2),
        }
    }

    // ─── BSR rel8 (0x8D) — branch to subroutine ───
    if opcode == 0x8D {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        return (9, 2);
    }

    // ─── JSR/JMP instructions ───
    match opcode {
        0x9D => {
            // JSR direct (2 bytes: opcode + 8-bit addr)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (7, 2);
        }
        0xAD => {
            // JSR indexed (2 bytes: opcode + 8-bit offset from X)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (7, 2);
        }
        0xBD => {
            // JSR extended (3 bytes: opcode + 16-bit addr)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            // Validate target address looks reasonable
            let addr = u16::from_be_bytes([data[i + 1], data[i + 2]]);
            if addr >= 0x0100 {
                return (9, 3); // Reasonable code address
            }
            return (5, 3);
        }
        0x6E => {
            // JMP indexed (2 bytes: opcode + 8-bit offset from X)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0x7E => {
            // JMP extended (3 bytes: opcode + 16-bit addr)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (6, 3);
        }
        _ => {}
    }

    // ─── BSET/BCLR/BRSET/BRCLR — bit manipulation (HC11-specific) ───
    // These are distinctive: they operate on direct-page addresses with a
    // bitmask, and the BRSET/BRCLR forms include a branch offset.
    match opcode {
        0x14 => {
            // BSET direct (3 bytes: opcode + addr + mask)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (7, 3);
        }
        0x15 => {
            // BCLR direct (3 bytes: opcode + addr + mask)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (7, 3);
        }
        0x12 => {
            // BRSET direct (4 bytes: opcode + addr + mask + rel)
            if i + 3 >= data.len() {
                return (-1, 1);
            }
            return (8, 4);
        }
        0x13 => {
            // BRCLR direct (4 bytes: opcode + addr + mask + rel)
            if i + 3 >= data.len() {
                return (-1, 1);
            }
            return (8, 4);
        }
        0x1C => {
            // BSET indexed (3 bytes: opcode + offset + mask)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (6, 3);
        }
        0x1D => {
            // BCLR indexed (3 bytes: opcode + offset + mask)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (6, 3);
        }
        0x1E => {
            // BRSET indexed (4 bytes: opcode + offset + mask + rel)
            if i + 3 >= data.len() {
                return (-1, 1);
            }
            return (7, 4);
        }
        0x1F => {
            // BRCLR indexed (4 bytes: opcode + offset + mask + rel)
            if i + 3 >= data.len() {
                return (-1, 1);
            }
            return (7, 4);
        }
        _ => {}
    }

    // ─── Load/Store accumulator A (LDAA/STAA) ───
    // LDAA: 0x86=imm(2), 0x96=dir(2), 0xA6=idx(2), 0xB6=ext(3)
    // STAA: 0x97=dir(2), 0xA7=idx(2), 0xB7=ext(3)
    match opcode {
        0x86 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDAA #imm8
        }
        0x96 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDAA dir
        }
        0xA6 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDAA idx
        }
        0xB6 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // LDAA ext
        }
        0x97 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STAA dir
        }
        0xA7 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STAA idx
        }
        0xB7 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // STAA ext
        }
        _ => {}
    }

    // ─── Load/Store accumulator B (LDAB/STAB) ───
    // LDAB: 0xC6=imm(2), 0xD6=dir(2), 0xE6=idx(2), 0xF6=ext(3)
    // STAB: 0xD7=dir(2), 0xE7=idx(2), 0xF7=ext(3)
    match opcode {
        0xC6 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDAB #imm8
        }
        0xD6 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDAB dir
        }
        0xE6 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDAB idx
        }
        0xF6 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // LDAB ext
        }
        0xD7 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STAB dir
        }
        0xE7 => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STAB idx
        }
        0xF7 => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // STAB ext
        }
        _ => {}
    }

    // ─── Load/Store D register (16-bit: LDD/STD) ───
    // LDD: 0xCC=imm(3), 0xDC=dir(2), 0xEC=idx(2), 0xFC=ext(3)
    // STD: 0xDD=dir(2), 0xED=idx(2), 0xFD=ext(3)
    match opcode {
        0xCC => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (6, 3); // LDD #imm16
        }
        0xDC => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDD dir
        }
        0xEC => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDD idx
        }
        0xFC => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // LDD ext
        }
        0xDD => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STD dir
        }
        0xED => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STD idx
        }
        0xFD => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // STD ext
        }
        _ => {}
    }

    // ─── Load/Store X register (LDX/STX) ───
    // LDX: 0xCE=imm(3), 0xDE=dir(2), 0xEE=idx(2), 0xFE=ext(3)
    // STX: 0xDF=dir(2), 0xEF=idx(2), 0xFF=ext(3)
    match opcode {
        0xCE => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // LDX #imm16
        }
        0xDE => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDX dir
        }
        0xEE => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDX idx
        }
        0xFE => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // LDX ext
        }
        0xDF => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STX dir
        }
        0xEF => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STX idx
        }
        0xFF => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // STX ext
        }
        _ => {}
    }

    // ─── Load/Store SP (LDS/STS) ───
    // LDS: 0x8E=imm(3), 0x9E=dir(2), 0xAE=idx(2), 0xBE=ext(3)
    // STS: 0x9F=dir(2), 0xAF=idx(2), 0xBF=ext(3)
    match opcode {
        0x8E => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (6, 3); // LDS #imm16
        }
        0x9E => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDS dir
        }
        0xAE => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // LDS idx
        }
        0xBE => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // LDS ext
        }
        0x9F => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STS dir
        }
        0xAF => {
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2); // STS idx
        }
        0xBF => {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // STS ext
        }
        _ => {}
    }

    // ─── ALU operations on accumulator A ───
    // Pattern: 0x8x=imm(2), 0x9x=dir(2), 0xAx=idx(2), 0xBx=ext(3)
    // ADDA=0x8B, ADCA=0x89, SUBA=0x80, SBCA=0x82, ANDA=0x84,
    // ORAA=0x8A, EORA=0x88, CMPA=0x81, BITA=0x85
    if (0x80..=0x8F).contains(&opcode) && opcode != 0x86 && opcode != 0x8D && opcode != 0x8E {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        return (4, 2); // 8x = immediate mode, 2 bytes
    }
    if (0x90..=0x9F).contains(&opcode)
        && opcode != 0x96
        && opcode != 0x97
        && opcode != 0x9D
        && opcode != 0x9E
        && opcode != 0x9F
    {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        return (4, 2); // 9x = direct mode, 2 bytes
    }
    if (0xA0..=0xAF).contains(&opcode)
        && opcode != 0xA6
        && opcode != 0xA7
        && opcode != 0xAD
        && opcode != 0xAE
        && opcode != 0xAF
    {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        return (4, 2); // Ax = indexed mode, 2 bytes
    }
    if (0xB0..=0xBF).contains(&opcode)
        && opcode != 0xB6
        && opcode != 0xB7
        && opcode != 0xBD
        && opcode != 0xBE
        && opcode != 0xBF
    {
        if i + 2 >= data.len() {
            return (-1, 1);
        }
        return (4, 3); // Bx = extended mode, 3 bytes
    }

    // ─── ALU operations on accumulator B and D register ───
    // Pattern: 0xCx=imm, 0xDx=dir, 0xEx=idx, 0xFx=ext
    // ADDB, ADCB, SUBB, SBCB, ANDB, ORAB, EORB, CMPB, BITB
    // Also: ADDD, SUBD, CPX (the 16-bit operations in these rows)
    if (0xC0..=0xCF).contains(&opcode)
        && opcode != 0xC6
        && opcode != 0xCC
        && opcode != 0xCE
        && opcode != 0xCD
        && opcode != 0xCF
    {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        // C3=ADDD#, C0=SUBB#, etc. — some are 3-byte (16-bit imm)
        // ADDD imm16 (0xC3), SUBD imm16 (0x83 already handled above), CPX imm16 (0x8C already above)
        if opcode == 0xC3 {
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3); // ADDD #imm16
        }
        return (3, 2);
    }
    if (0xD0..=0xDF).contains(&opcode)
        && opcode != 0xD6
        && opcode != 0xD7
        && opcode != 0xDC
        && opcode != 0xDD
        && opcode != 0xDE
        && opcode != 0xDF
    {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        if opcode == 0xD3 {
            return (5, 2); // ADDD dir
        }
        return (4, 2);
    }
    if (0xE0..=0xEF).contains(&opcode)
        && opcode != 0xE6
        && opcode != 0xE7
        && opcode != 0xEC
        && opcode != 0xED
        && opcode != 0xEE
        && opcode != 0xEF
    {
        if i + 1 >= data.len() {
            return (-1, 1);
        }
        if opcode == 0xE3 {
            return (5, 2); // ADDD idx
        }
        return (3, 2);
    }
    if (0xF0..=0xFF).contains(&opcode)
        && opcode != 0xF6
        && opcode != 0xF7
        && opcode != 0xFC
        && opcode != 0xFD
        && opcode != 0xFE
        && opcode != 0xFF
    {
        if i + 2 >= data.len() {
            return (-1, 1);
        }
        if opcode == 0xF3 {
            return (5, 3); // ADDD ext
        }
        return (4, 3);
    }

    // ─── Memory unary operations: CLR/INC/DEC/TST/COM/NEG (indexed and extended) ───
    match opcode {
        0x6F => {
            // CLR indexed (2 bytes)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        0x7F => {
            // CLR extended (3 bytes)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0x6C => {
            // INC indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        0x7C => {
            // INC extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0x6A => {
            // DEC indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        0x7A => {
            // DEC extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0x6D => {
            // TST indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        0x7D => {
            // TST extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (4, 3);
        }
        0x63 => {
            // COM indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (4, 2);
        }
        0x73 => {
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
            return (4, 2);
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

    // ─── Shift/Rotate memory: ASL/ASR/LSR/ROL/ROR (indexed and extended) ───
    match opcode {
        0x68 => {
            // ASL/LSL indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        0x78 => {
            // ASL/LSL extended
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
            return (3, 2);
        }
        0x77 => {
            // ASR extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        0x64 => {
            // LSR indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        0x74 => {
            // LSR extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        0x69 => {
            // ROL indexed
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (3, 2);
        }
        0x79 => {
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
            return (3, 2);
        }
        0x76 => {
            // ROR extended
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (3, 3);
        }
        _ => {}
    }

    // ─── CPX (compare X register) — 0x8C, 0x9C, 0xAC, 0xBC ───
    match opcode {
        0x8C => {
            // CPX #imm16 (3 bytes)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        0x9C => {
            // CPX dir (2 bytes)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xAC => {
            // CPX idx (2 bytes)
            if i + 1 >= data.len() {
                return (-1, 1);
            }
            return (5, 2);
        }
        0xBC => {
            // CPX ext (3 bytes)
            if i + 2 >= data.len() {
                return (-1, 1);
            }
            return (5, 3);
        }
        _ => {}
    }

    // ─── SUBD: 0x83=imm(3), 0x93=dir(2), 0xA3=idx(2), 0xB3=ext(3) ───
    // Already handled in the ALU ranges above.

    // ─── XGDX (0x8F) — exchange D and X registers ───
    if opcode == 0x8F {
        return (7, 1); // Very distinctive HC11 instruction
    }

    // ─── IDIV (0x02) / FDIV (0x03) ───
    if opcode == 0x02 {
        return (6, 1); // IDIV — integer divide D/X → X, rem D
    }
    if opcode == 0x03 {
        return (6, 1); // FDIV — fractional divide D/X → X, rem D
    }

    // ─── Remaining unhandled opcodes ───
    // The HC11 opcode space is fairly sparse compared to HC12 — many byte
    // values in the 0x02-0x05 range and various gaps are undefined/reserved.
    // Apply a mild penalty for unrecognized opcodes.
    match opcode {
        0x04 | 0x05 | 0x41 | 0x42 | 0x45 | 0x4B | 0x4E | 0x51 | 0x52 | 0x55 | 0x5B | 0x5E
        | 0x61 | 0x62 | 0x65 | 0x6B | 0x71 | 0x72 | 0x75 | 0x7B => {
            // Known invalid/undefined opcodes — stronger penalty
            return (-3, 1);
        }
        _ => {
            // Other unmatched opcodes — mild penalty
            return (-1, 1);
        }
    }
}

/// Score a 0x18-prefixed instruction (Y-indexed mode substitution).
///
/// When 0x18 precedes an X-indexed opcode, the instruction uses Y instead of X.
/// The 0x18 prefix adds 1 byte to the instruction length. Most opcodes that
/// support indexed addressing via X have Y-indexed equivalents via 0x18.
///
/// Additionally, 0x18 is used for some inherent instructions that reference Y:
/// - INY (0x18 0x08), DEY (0x18 0x09)
/// - TSY (0x18 0x30), TYS (0x18 0x35)
/// - PSHY (0x18 0x3C), PULY (0x18 0x38)
/// - XGDY (0x18 0x8F) — exchange D and Y
/// - CPY (0x18 0x8C/9C/AC/BC) — compare Y
/// - LDY (0x18 0xCE/DE/EE/FE) — load Y
/// - STY (0x18 0xDF/EF/FF) — store Y
fn score_prefix_18_instruction(next: u8, data: &[u8], i: usize) -> (i64, usize) {
    match next {
        // ── Y-indexed inherent operations ──
        0x08 => return (6, 2), // INY — increment Y
        0x09 => return (6, 2), // DEY — decrement Y
        0x30 => return (5, 2), // TSY — transfer SP to Y
        0x35 => return (5, 2), // TYS — transfer Y to SP
        0x3C => return (7, 2), // PSHY — push Y
        0x38 => return (7, 2), // PULY — pull Y
        0x8F => return (8, 2), // XGDY — exchange D and Y

        // ── CPY (compare Y register) ──
        0x8C => {
            // CPY #imm16 (4 bytes: 0x18 + 0x8C + 16-bit imm)
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (6, 4);
        }
        0x9C => {
            // CPY dir (3 bytes: 0x18 + 0x9C + addr)
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        0xAC => {
            // CPY idx (3 bytes: 0x18 + 0xAC + offset)
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        0xBC => {
            // CPY ext (4 bytes: 0x18 + 0xBC + 16-bit addr)
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (5, 4);
        }

        // ── LDY (load Y register) ──
        0xCE => {
            // LDY #imm16 (4 bytes)
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (6, 4);
        }
        0xDE => {
            // LDY dir (3 bytes)
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        0xEE => {
            // LDY idx (3 bytes)
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        0xFE => {
            // LDY ext (4 bytes)
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (5, 4);
        }

        // ── STY (store Y register) ──
        0xDF => {
            // STY dir (3 bytes)
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        0xEF => {
            // STY idx (3 bytes)
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        0xFF => {
            // STY ext (4 bytes)
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (5, 4);
        }

        _ => {}
    }

    // ── Y-indexed addressing mode substitution for general opcodes ──
    // Any opcode in the indexed-mode columns (0xAx, 0xEx, 0x6x) can be
    // prefixed with 0x18 to use Y instead of X. The instruction is then
    // 1 byte longer (prefix + opcode + offset = 3 bytes for 2-byte X-indexed,
    // or prefix + opcode + addr_hi + addr_lo for extended forms).
    let hi_nib = next >> 4;

    // Indexed mode opcodes (Y-substituted): offset from Y register
    if hi_nib == 0xA || hi_nib == 0xE || hi_nib == 0x6 {
        if i + 2 >= data.len() {
            return (0, 2);
        }
        return (4, 3); // prefix + opcode + offset = 3 bytes
    }

    // For other opcodes after 0x18, this is unusual in HC11 context.
    // Mild score — might be valid but less distinctive.
    (1, 2)
}

/// Score a 0x1A-prefixed instruction.
///
/// The 0x1A prefix is used for:
/// - CPD (compare D register): 0x1A 0x83/93/A3/B3
/// - LDY indexed (alternate form using Y as index): 0x1A 0xEE
/// - STY indexed (alternate form): 0x1A 0xEF
fn score_prefix_1a_instruction(next: u8, data: &[u8], i: usize) -> (i64, usize) {
    match next {
        // ── CPD (compare D) ──
        0x83 => {
            // CPD #imm16 (4 bytes: 0x1A + 0x83 + imm_hi + imm_lo)
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (7, 4);
        }
        0x93 => {
            // CPD dir (3 bytes)
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (6, 3);
        }
        0xA3 => {
            // CPD idx (3 bytes)
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (6, 3);
        }
        0xB3 => {
            // CPD ext (4 bytes)
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (6, 4);
        }

        // ── LDY idx (0x1A 0xEE + offset) — Y-indexed form ──
        0xEE => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }
        // ── STY idx (0x1A 0xEF + offset) — Y-indexed form ──
        0xEF => {
            if i + 2 >= data.len() {
                return (2, 2);
            }
            return (5, 3);
        }

        _ => {
            // Unknown 0x1A-prefixed opcode — not very common
            return (0, 2);
        }
    }
}

/// Score a 0xCD-prefixed instruction.
///
/// The 0xCD prefix is used for:
/// - LDY extended: 0xCD 0xEE + addr_hi + addr_lo (not standard — disambiguation note)
///
/// In practice, 0xCD in HC11 context most commonly appears as part of the
/// Y-indexed addressing extension for a few specific opcodes.
fn score_prefix_cd_instruction(next: u8, data: &[u8], i: usize) -> (i64, usize) {
    match next {
        // LDY ext (4 bytes: 0xCD + 0xEE + addr_hi + addr_lo)
        // Some HC11 documentation shows 0xCD for extended Y-load
        0xEE => {
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (5, 4);
        }
        0xEF => {
            if i + 3 >= data.len() {
                return (2, 2);
            }
            return (5, 4);
        }
        _ => {
            // 0xCD is not a heavily used prefix — treat as mild positive
            // since seeing it at all is somewhat distinctive
            return (1, 2);
        }
    }
}

/// Detect HC11 interrupt vector table at the end of the data.
///
/// The MC68HC11A8 has interrupt vectors at 0xFFD6–0xFFFE (21 vectors, 42 bytes).
/// The MC68HC11E-series and others may have slightly different vector counts.
/// The reset vector is always at 0xFFFE (the last 2 bytes of address space).
///
/// In a raw flash image, these vectors map to the last N bytes of the image.
/// Each vector is a 16-bit big-endian address pointing into the code space
/// (typically 0xB600–0xFFFF for internal ROM/EPROM, or 0x0000–0xFFFF for
/// expanded mode).
fn score_vector_table(data: &[u8]) -> i64 {
    if data.len() < 128 {
        return 0;
    }

    // Try the last 42 bytes as the IVT (21 vectors × 2 bytes)
    // Also try the last 64 bytes to be more generous for variants
    let ivt_size = 64.min(data.len());
    let ivt_start = data.len() - ivt_size;
    let ivt = &data[ivt_start..];

    let mut valid_vectors = 0u32;
    let mut _total_vectors = 0u32;
    let mut vector_values: Vec<u16> = Vec::with_capacity(32);

    for j in (0..ivt_size).step_by(2) {
        if j + 1 >= ivt.len() {
            break;
        }
        let addr = u16::from_be_bytes([ivt[j], ivt[j + 1]]);
        _total_vectors += 1;

        // Valid HC11 vector: points into code space (typically >= 0x0100, < 0xFFF0)
        // Addresses of 0x0000 or 0xFFFF indicate unprogrammed/erased vectors.
        if addr >= 0x0100 && addr < 0xFFF0 {
            valid_vectors += 1;
            vector_values.push(addr);
        }
    }

    // Need a meaningful number of valid-looking vectors
    if valid_vectors < 8 {
        return 0;
    }

    let mut ivt_score: i64 = 0;

    // Check the reset vector (last 2 bytes of file)
    let reset_vec = u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]);
    if reset_vec >= 0x0800 && reset_vec < 0xFFF0 {
        ivt_score += 150; // Very strong signal — the reset vector is the most important
    }

    // Check if vectors cluster in the same memory page (high byte)
    // In real HC11 firmware, most ISR handlers are in the same flash page.
    if vector_values.len() >= 5 {
        let mut page_counts = [0u32; 256];
        for &v in &vector_values {
            page_counts[(v >> 8) as usize] += 1;
        }
        let max_page_count = page_counts.iter().max().copied().unwrap_or(0);

        if max_page_count >= 6 {
            ivt_score += 100;
        } else if max_page_count >= 3 {
            ivt_score += 50;
        }
    }

    // General bonus for having many valid vectors
    ivt_score += (valid_vectors as i64) * 4;

    // Penalty if too many vectors are the same value (fill pattern, not real IVT)
    if vector_values.len() > 3 {
        let mut sorted = vector_values.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() < vector_values.len() / 3 {
            ivt_score /= 3;
        }
    }

    ivt_score
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

/// Detect HC12/HCS12X firmware structural signatures and return a multiplier
/// penalty for the HC11 score. Returns 1.0 (no penalty) if no HC12 evidence
/// is found, or a value < 1.0 if HC12 patterns are detected.
///
/// HC11 and HC12 share many opcodes from the M6800 heritage, but differ in
/// several key ways that we can exploit for disambiguation:
///
/// 1. **RTS opcode**: HC11 RTS = 0x39, HC12 RTS = 0x3D. If we see a high
///    density of 0x3D (which is MUL in HC11, a rare instruction), it's
///    likely HC12 code.
///
/// 2. **HC12 page-2 patterns**: HC12 uses 0x18 as a page-2 prefix followed
///    by opcodes like ABA (0x06), TAB (0x0E), TBA (0x0F), SBA (0x16),
///    CBA (0x17), and long branches (0x20-0x2F with 16-bit offset).
///    In HC11, 0x18 is a Y-index prefix, and the following byte is expected
///    to be an indexed-mode opcode (0xAx, 0xEx, 0x6x, etc.). The HC12
///    page-2 inter-register opcodes (0x06, 0x0E, 0x0F, etc.) would never
///    follow 0x18 in HC11 code.
///
/// 3. **HC12 BSR (0x07)**: In HC11, 0x07 = TPA (transfer CCR to A, inherent
///    1-byte). If 0x07 appears frequently followed by plausible branch
///    offsets, it suggests HC12 code.
///
/// 4. **HC12 NOP (0xA7)**: In HC11, 0xA7 = STAA indexed (2-byte). If 0xA7
///    appears at high density without plausible index offsets, it suggests HC12.
fn detect_hc12_cross_arch_penalty(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 1.0;
    }

    let start = skip_padding(data);
    if start >= data.len().saturating_sub(32) {
        return 1.0;
    }

    let code_len = data.len() - start;
    if code_len < 32 {
        return 1.0;
    }

    let working = &data[start..];

    // Count HC12-specific patterns
    let mut hc12_rts_count: u32 = 0; // 0x3D = HC12 RTS (HC11 MUL)
    let mut hc12_page2_count: u32 = 0; // 0x18 + HC12 page-2 opcodes
    let mut hc12_bsr_count: u32 = 0; // 0x07 used as BSR (HC12)
    let mut hc11_rts_count: u32 = 0; // 0x39 = HC11 RTS

    let mut i = 0;
    while i < working.len() {
        let b = working[i];

        match b {
            // HC12 RTS (0x3D) — in HC11 this is MUL (multiply), which is
            // used infrequently. A high density of 0x3D strongly suggests HC12.
            0x3D => {
                hc12_rts_count += 1;
            }

            // HC11 RTS (0x39) — the real HC11 return instruction
            0x39 => {
                hc11_rts_count += 1;
            }

            // HC12 page-2 prefix 0x18 followed by inter-register ops
            // that would NOT appear after 0x18 in HC11
            0x18 => {
                if i + 1 < working.len() {
                    let next = working[i + 1];
                    match next {
                        // HC12 page-2 inter-register ops
                        0x06 | 0x07 | 0x0E | 0x0F | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x16
                        | 0x17 => {
                            hc12_page2_count += 1;
                        }
                        // HC12 long branches: 0x18 0x20-0x2F + 16-bit rel
                        0x20..=0x2F => {
                            hc12_page2_count += 1;
                        }
                        // HC12 MOVB/MOVW: 0x18 0x00-0x05
                        0x00..=0x05 => {
                            hc12_page2_count += 1;
                        }
                        _ => {}
                    }
                }
            }

            // HC12 BSR (0x07) — in HC11 this is TPA (transfer CCR to A)
            // TPA is relatively rare; if 0x07 appears frequently, it's likely
            // HC12 BSR.
            0x07 => {
                hc12_bsr_count += 1;
            }

            _ => {}
        }

        i += 1;
    }

    // ─── Evaluate evidence ───
    let byte_count = code_len as f64;
    let mut hc12_evidence: u32 = 0;

    // HC12 RTS density: in real HC12 code, 0x3D appears at ~0.5-2% density.
    // In HC11 code, 0x3D (MUL) appears at < 0.05% density.
    let rts_3d_density = hc12_rts_count as f64 / byte_count;
    if rts_3d_density > 0.005 && hc12_rts_count >= 5 {
        hc12_evidence += 3; // Very strong — this is almost certainly HC12
    } else if rts_3d_density > 0.002 && hc12_rts_count >= 3 {
        hc12_evidence += 2;
    }

    // HC12 page-2 patterns: if we see 0x18 followed by HC12-specific page-2
    // opcodes (not Y-indexed substitution), that's strong evidence.
    if hc12_page2_count >= 5 {
        hc12_evidence += 3;
    } else if hc12_page2_count >= 2 {
        hc12_evidence += 1;
    }

    // Ratio of HC12 RTS (0x3D) to HC11 RTS (0x39): if 0x3D appears more
    // often than 0x39, the code is likely HC12.
    if hc12_rts_count > 0 && hc11_rts_count > 0 {
        if hc12_rts_count > hc11_rts_count * 2 {
            hc12_evidence += 2;
        } else if hc12_rts_count > hc11_rts_count {
            hc12_evidence += 1;
        }
    }

    // HC12 BSR (0x07) density
    let bsr_07_density = hc12_bsr_count as f64 / byte_count;
    if bsr_07_density > 0.003 && hc12_bsr_count >= 3 {
        hc12_evidence += 1;
    }

    // ─── Apply penalty ───
    if hc12_evidence >= 5 {
        0.08 // Overwhelmingly HC12 — crush HC11 score
    } else if hc12_evidence >= 3 {
        0.15 // Strong HC12 evidence
    } else if hc12_evidence >= 2 {
        0.40 // Moderate HC12 evidence
    } else {
        1.0 // No or weak HC12 evidence — no penalty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hc11_rts_nop_pattern() {
        // RTS (0x39) followed by NOP (0x01) — common function padding pattern
        let code = [
            0x39, 0x01, // RTS; NOP
            0x39, 0x01, // RTS; NOP
            0x39, 0x01, // RTS; NOP
            0x39, 0x01, // RTS; NOP
            0x39, 0x01, // RTS; NOP
            0x39, 0x01, // RTS; NOP
            0x39, 0x01, // RTS; NOP
            0x39, 0x01, // RTS; NOP
        ];
        let s = score(&code);
        assert!(s > 0, "RTS+NOP pattern should score positively, got {}", s);
    }

    #[test]
    fn test_hc11_rts_stream() {
        // A stream of RTS instructions — each function return
        let code = [
            0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
            0x39, 0x39,
        ];
        let s = score(&code);
        assert!(s > 50, "RTS stream should score very well, got {}", s);
    }

    #[test]
    fn test_hc11_branch_patterns() {
        // Typical conditional branch code with loads and compares
        let code = [
            0x86, 0x42, // LDAA #$42
            0xC6, 0x11, // LDAB #$11
            0x27, 0x04, // BEQ +4
            0x26, 0x02, // BNE +2
            0x20, 0x0A, // BRA +10
            0x8D, 0x10, // BSR +16
            0x39, // RTS
            0x86, 0x10, // LDAA #$10
            0x39, // RTS
            0x01, // NOP
        ];
        let s = score(&code);
        assert!(s > 10, "HC11 branch code should score well, got {}", s);
    }

    #[test]
    fn test_hc11_load_store_patterns() {
        // Typical load/store sequence with multiple addressing modes
        let code = [
            0x86, 0xFF, // LDAA #$FF
            0x97, 0x50, // STAA $50 (direct)
            0xC6, 0x00, // LDAB #$00
            0xD7, 0x51, // STAB $51 (direct)
            0xCC, 0x12, 0x34, // LDD #$1234
            0xDD, 0x60, // STD $60 (direct)
            0xCE, 0xF0, 0x00, // LDX #$F000
            0x39, // RTS
        ];
        let s = score(&code);
        assert!(s > 10, "HC11 load/store code should score well, got {}", s);
    }

    #[test]
    fn test_hc11_basic_function() {
        // A typical HC11 function: push, load, store, BSR, pull, RTS
        let code = [
            0x36, // PSHA
            0x37, // PSHB
            0x86, 0x42, // LDAA #$42
            0x97, 0x50, // STAA $50
            0x8D, 0x10, // BSR +16
            0x33, // PULB
            0x32, // PULA
            0x39, // RTS
            0x86, 0x42, // filler — LDAA #$42
            0x97, 0x50, // filler — STAA $50
            0x39, // filler — RTS
            0x01, // NOP
        ];
        let s = score(&code);
        assert!(s > 20, "HC11 basic function should score well, got {}", s);
    }

    #[test]
    fn test_hc11_inter_register_ops() {
        // Inter-register transfers — very distinctive to 6800/HC11 family
        let code = [
            0x86, 0x42, // LDAA #$42
            0x16, // TAB (A → B)
            0x1B, // ABA (A + B → A)
            0x11, // CBA (compare B with A)
            0x27, 0x02, // BEQ +2
            0x17, // TBA (B → A)
            0x10, // SBA (A - B → A)
            0x39, // RTS
            0x86, 0x42, // filler
            0x16, // TAB (filler)
            0x39, // RTS (filler)
            0x01, // NOP
            0x01, // NOP
            0x01, // NOP
        ];
        let s = score(&code);
        assert!(s > 20, "Inter-register ops should score well, got {}", s);
    }

    #[test]
    fn test_hc11_y_indexed_prefix() {
        // Y-indexed instructions using the 0x18 prefix
        let code = [
            0x18, 0xCE, 0x10, 0x00, // LDY #$1000
            0x18, 0x08, // INY
            0x18, 0x08, // INY
            0x18, 0x3C, // PSHY
            0x18, 0xEE, 0x04, // LDY idx, 4
            0x18, 0x38, // PULY
            0x39, // RTS
        ];
        let s = score(&code);
        assert!(s > 10, "Y-indexed prefix code should score well, got {}", s);
    }

    #[test]
    fn test_hc11_zero_run_penalization() {
        // Zero runs should be penalized (0x00 = TEST, not NOP)
        let mut code = vec![0x00u8; 32];
        // Append some valid code at the end
        code.extend_from_slice(&[
            0x86, 0x42, 0x97, 0x50, 0x39, 0x86, 0x42, 0x97, 0x50, 0x39, 0x86, 0x42, 0x97, 0x50,
            0x39, 0x01,
        ]);
        let s_with_zeros = score(&code);

        // Pure valid code (no zeros)
        let pure_code = [
            0x86, 0x42, 0x97, 0x50, 0x39, 0x86, 0x42, 0x97, 0x50, 0x39, 0x86, 0x42, 0x97, 0x50,
            0x39, 0x01,
        ];
        let s_pure = score(&pure_code);

        // The version with zero runs should score less than pure code
        // (or at most equal, if the padding skip handles it)
        assert!(
            s_with_zeros <= s_pure,
            "Zero-filled data should not boost score: zeros={}, pure={}",
            s_with_zeros,
            s_pure
        );
    }

    #[test]
    fn test_hc11_not_hc12() {
        // HC12 code pattern: RTS is 0x3D, BSR is 0x07, page-2 prefix 0x18+0x06
        let hc12_code = [
            0x86, 0x42, // LDAA #$42 (same in both)
            0x07, 0x10, // HC12 BSR +16 (HC11: TPA)
            0x18, 0x06, // HC12 ABA (page-2) — in HC11 this is 0x18+INY-like
            0x3D, // HC12 RTS (HC11: MUL)
            0x3D, // HC12 RTS
            0x3D, // HC12 RTS
            0x18, 0x0E, // HC12 TAB (page-2)
            0x3D, // HC12 RTS
            0x18, 0x16, // HC12 SBA (page-2)
            0x3D, // HC12 RTS
        ];
        let s = score(&hc12_code);
        // HC12 code should not score highly as HC11 (the cross-arch
        // penalty should kick in)
        assert!(
            s < 40,
            "HC12 code should not score highly as HC11, got {}",
            s
        );
    }

    #[test]
    fn test_hc11_jsr_extended() {
        // JSR $B600 — jump to start of internal ROM
        let code = [
            0xBD, 0xB6, 0x00, // JSR $B600
            0xBD, 0xB6, 0x10, // JSR $B610
            0xBD, 0xF8, 0x00, // JSR $F800
            0x39, // RTS
            0xBD, 0xB6, 0x00, // JSR $B600
            0x39, // RTS
            0x01, // NOP
            0x01, // NOP
        ];
        let s = score(&code);
        assert!(s > 10, "HC11 JSR extended should score well, got {}", s);
    }

    #[test]
    fn test_hc11_flag_manipulation() {
        // Interrupt service routine pattern: SEI, do work, CLI, RTI
        let code = [
            0x0F, // SEI (disable interrupts)
            0x86, 0x80, // LDAA #$80
            0xB7, 0x10, 0x00, // STAA $1000 (write to I/O register)
            0x0E, // CLI (enable interrupts)
            0x3B, // RTI
            0x0F, // SEI (another ISR)
            0x86, 0x01, // LDAA #$01
            0xB7, 0x10, 0x02, // STAA $1002
            0x0E, // CLI
            0x3B, // RTI
        ];
        let s = score(&code);
        assert!(s > 20, "ISR pattern should score well, got {}", s);
    }

    #[test]
    fn test_hc11_bit_manipulation() {
        // BSET/BCLR/BRSET/BRCLR — distinctive to HC11
        let code = [
            0x14, 0x50, 0x80, // BSET $50, #$80 (set bit 7 of $50)
            0x15, 0x50, 0x80, // BCLR $50, #$80 (clear bit 7 of $50)
            0x12, 0x50, 0x01, 0x05, // BRSET $50, #$01, +5
            0x13, 0x50, 0x02, 0x03, // BRCLR $50, #$02, +3
            0x39, // RTS
            0x01, // NOP
        ];
        let s = score(&code);
        assert!(s > 15, "Bit manipulation should score well, got {}", s);
    }

    #[test]
    fn test_hc11_xgdx() {
        // XGDX (0x8F) — exchange D and X, very distinctive HC11 instruction
        let code = [
            0xCE, 0x00, 0x10, // LDX #$0010
            0xCC, 0x00, 0x20, // LDD #$0020
            0x8F, // XGDX — now D=$0010, X=$0020
            0x39, // RTS
            0x8F, // XGDX again
            0xCE, 0x00, 0x30, // LDX #$0030
            0x39, // RTS
            0x01, // NOP
            0x01, // NOP
            0x01, // NOP (padding to reach 16 bytes)
        ];
        let s = score(&code);
        assert!(s > 15, "XGDX pattern should score well, got {}", s);
    }

    /// Helper: decode a hex string into bytes
    #[allow(dead_code)]
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
