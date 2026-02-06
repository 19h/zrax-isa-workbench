//! Texas Instruments MSP430 architecture analysis.
//!
//! MSP430 uses 16-bit instructions with optional extension words,
//! little-endian encoding. It's a 16-bit RISC microcontroller.

/// Instruction format types.
pub mod format {
    /// Single-operand format: [15:12]=0001, [11:7]=opcode, [6]=B/W, [5:4]=As, [3:0]=reg
    pub const SINGLE_OP: u8 = 0x1;

    /// Two-operand format: [15:12]=opcode, [11:8]=src, [7]=Ad, [6]=B/W, [5:4]=As, [3:0]=dst
    /// Opcodes 4-F

    /// Jump format: [15:13]=001, [12:10]=condition, [9:0]=offset
    pub const JUMP: u8 = 0x1; // Actually detected by bits 15:13 = 001
}

/// Single-operand opcodes (when bits 15:12 = 0001).
pub mod single_op {
    pub const RRC: u8 = 0x00; // Rotate right through carry
    pub const SWPB: u8 = 0x01; // Swap bytes
    pub const RRA: u8 = 0x02; // Rotate right arithmetic
    pub const SXT: u8 = 0x03; // Sign extend
    pub const PUSH: u8 = 0x04; // Push
    pub const CALL: u8 = 0x05; // Call
    pub const RETI: u8 = 0x06; // Return from interrupt
}

/// Two-operand opcodes (bits 15:12).
pub mod two_op {
    pub const MOV: u8 = 0x4; // Move
    pub const ADD: u8 = 0x5; // Add
    pub const ADDC: u8 = 0x6; // Add with carry
    pub const SUBC: u8 = 0x7; // Subtract with carry
    pub const SUB: u8 = 0x8; // Subtract
    pub const CMP: u8 = 0x9; // Compare
    pub const DADD: u8 = 0xA; // Decimal add
    pub const BIT: u8 = 0xB; // Bit test
    pub const BIC: u8 = 0xC; // Bit clear
    pub const BIS: u8 = 0xD; // Bit set
    pub const XOR: u8 = 0xE; // Exclusive or
    pub const AND: u8 = 0xF; // And
}

/// Jump conditions (bits 12:10 when bits 15:13 = 001).
pub mod jump_cond {
    pub const JNE: u8 = 0x0; // Jump if not equal/zero
    pub const JEQ: u8 = 0x1; // Jump if equal/zero
    pub const JNC: u8 = 0x2; // Jump if no carry
    pub const JC: u8 = 0x3; // Jump if carry
    pub const JN: u8 = 0x4; // Jump if negative
    pub const JGE: u8 = 0x5; // Jump if greater or equal
    pub const JL: u8 = 0x6; // Jump if less
    pub const JMP: u8 = 0x7; // Jump unconditionally
}

/// Addressing modes (As/Ad fields).
pub mod addr_mode {
    pub const REGISTER: u8 = 0b00; // Rn
    pub const INDEXED: u8 = 0b01; // X(Rn) or symbolic/absolute
    pub const INDIRECT: u8 = 0b10; // @Rn
    pub const INDIRECT_INC: u8 = 0b11; // @Rn+ or immediate
}

/// Register numbers.
pub mod reg {
    pub const PC: u8 = 0; // Program counter
    pub const SP: u8 = 1; // Stack pointer
    pub const SR: u8 = 2; // Status register
    pub const CG: u8 = 3; // Constant generator
    pub const R4: u8 = 4;
    pub const R5: u8 = 5;
    pub const R6: u8 = 6;
    pub const R7: u8 = 7;
    pub const R8: u8 = 8;
    pub const R9: u8 = 9;
    pub const R10: u8 = 10;
    pub const R11: u8 = 11;
    pub const R12: u8 = 12;
    pub const R13: u8 = 13;
    pub const R14: u8 = 14;
    pub const R15: u8 = 15;
}

/// Common MSP430 instruction patterns.
pub mod patterns {
    /// NOP (MOV #0, R3 or other equivalent).
    /// Common NOP encoding: MOV R3, R3 = 0x4303
    pub const NOP: u16 = 0x4303;

    /// RET (MOV @SP+, PC) = 0x4130
    pub const RET: u16 = 0x4130;

    /// RETI = 0x1300
    pub const RETI: u16 = 0x1300;

    /// BR (branch - MOV src, PC).
    pub const BR_MASK: u16 = 0xF08F;
    pub const BR_VAL: u16 = 0x4000; // MOV to PC

    /// CALL mask (single-operand, opcode=5).
    pub const CALL_MASK: u16 = 0xFF80;
    pub const CALL_VAL: u16 = 0x1280;

    /// PUSH mask (single-operand, opcode=4).
    pub const PUSH_MASK: u16 = 0xFF80;
    pub const PUSH_VAL: u16 = 0x1200;

    /// POP (emulated: MOV @SP+, dst).
    /// Can be detected as MOV with As=11, src=SP

    /// CLR (emulated: MOV #0, dst).

    /// Jump instruction mask.
    pub const JUMP_MASK: u16 = 0xE000;
    pub const JUMP_VAL: u16 = 0x2000;

    /// Unconditional JMP mask.
    pub const JMP_MASK: u16 = 0xFC00;
    pub const JMP_VAL: u16 = 0x3C00;
}

/// Extract opcode (bits 15:12).
pub fn get_opcode(instr: u16) -> u8 {
    ((instr >> 12) & 0x0F) as u8
}

/// Extract single-operand sub-opcode (bits 9:7).
pub fn get_single_op(instr: u16) -> u8 {
    ((instr >> 7) & 0x07) as u8
}

/// Extract B/W bit (bit 6). 0=word, 1=byte.
pub fn get_bw(instr: u16) -> bool {
    (instr & 0x0040) != 0
}

/// Extract As field (source addressing mode, bits 5:4).
pub fn get_as(instr: u16) -> u8 {
    ((instr >> 4) & 0x03) as u8
}

/// Extract Ad field (destination addressing mode, bit 7).
pub fn get_ad(instr: u16) -> u8 {
    ((instr >> 7) & 0x01) as u8
}

/// Extract source register (bits 11:8 for two-op).
pub fn get_src_reg(instr: u16) -> u8 {
    ((instr >> 8) & 0x0F) as u8
}

/// Extract destination register (bits 3:0).
pub fn get_dst_reg(instr: u16) -> u8 {
    (instr & 0x0F) as u8
}

/// Extract register for single-operand (bits 3:0).
pub fn get_single_reg(instr: u16) -> u8 {
    (instr & 0x0F) as u8
}

/// Extract jump condition (bits 12:10).
pub fn get_jump_cond(instr: u16) -> u8 {
    ((instr >> 10) & 0x07) as u8
}

/// Extract jump offset (bits 9:0, signed).
pub fn get_jump_offset(instr: u16) -> i16 {
    let val = (instr & 0x03FF) as i16;
    // Sign extend from 10 bits
    if val & 0x0200 != 0 {
        val | !0x03FF
    } else {
        val
    }
}

/// Determine if instruction is a jump format.
pub fn is_jump_format(instr: u16) -> bool {
    (instr & 0xE000) == 0x2000
}

/// Determine if instruction is single-operand format.
pub fn is_single_op_format(instr: u16) -> bool {
    get_opcode(instr) == 0x1 && !is_jump_format(instr)
}

/// Determine if instruction is two-operand format.
pub fn is_two_op_format(instr: u16) -> bool {
    let op = get_opcode(instr);
    op >= 0x4 && op <= 0xF
}

/// Calculate number of extension words needed.
pub fn extension_words(instr: u16) -> usize {
    let mut count = 0;

    if is_jump_format(instr) {
        return 0;
    }

    if is_single_op_format(instr) {
        let as_mode = get_as(instr);
        let reg = get_single_reg(instr);

        // Indexed mode needs extension word
        if as_mode == addr_mode::INDEXED {
            count += 1;
        }
        // Immediate mode (@PC+) needs extension word
        if as_mode == addr_mode::INDIRECT_INC && reg == reg::PC {
            count += 1;
        }
    }

    if is_two_op_format(instr) {
        let as_mode = get_as(instr);
        let ad_mode = get_ad(instr);
        let src = get_src_reg(instr);
        let dst = get_dst_reg(instr);

        // Source extension word
        if as_mode == addr_mode::INDEXED {
            count += 1;
        }
        if as_mode == addr_mode::INDIRECT_INC && src == reg::PC {
            count += 1; // Immediate mode
        }

        // Destination extension word
        if ad_mode == 1 {
            // Indexed addressing
            count += 1;
        }
    }

    count
}

/// Determine instruction length in bytes.
pub fn instruction_length(instr: u16) -> usize {
    2 + (extension_words(instr) * 2)
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u16) -> bool {
    // Various NOP encodings
    instr == patterns::NOP ||
    // MOV R3, R3 variations
    (instr & 0xFFFF) == 0x4303
}

/// Check if instruction is RET.
pub fn is_ret(instr: u16) -> bool {
    instr == patterns::RET
}

/// Check if instruction is RETI.
pub fn is_reti(instr: u16) -> bool {
    instr == patterns::RETI
}

/// Check if instruction is any return type.
pub fn is_return(instr: u16) -> bool {
    is_ret(instr) || is_reti(instr)
}

/// Check if instruction is a conditional jump.
pub fn is_conditional_jump(instr: u16) -> bool {
    is_jump_format(instr) && get_jump_cond(instr) != jump_cond::JMP
}

/// Check if instruction is unconditional JMP.
pub fn is_jmp(instr: u16) -> bool {
    (instr & patterns::JMP_MASK) == patterns::JMP_VAL
}

/// Check if instruction is a branch (any jump).
pub fn is_branch(instr: u16) -> bool {
    is_jump_format(instr)
}

/// Check if instruction is CALL.
pub fn is_call(instr: u16) -> bool {
    is_single_op_format(instr) && get_single_op(instr) == single_op::CALL
}

/// Check if instruction is PUSH.
pub fn is_push(instr: u16) -> bool {
    is_single_op_format(instr) && get_single_op(instr) == single_op::PUSH
}

/// Check if instruction is MOV.
pub fn is_mov(instr: u16) -> bool {
    get_opcode(instr) == two_op::MOV
}

/// Check if instruction is ADD.
pub fn is_add(instr: u16) -> bool {
    get_opcode(instr) == two_op::ADD
}

/// Check if instruction is SUB.
pub fn is_sub(instr: u16) -> bool {
    get_opcode(instr) == two_op::SUB
}

/// Check if instruction is CMP.
pub fn is_cmp(instr: u16) -> bool {
    get_opcode(instr) == two_op::CMP
}

/// Check if instruction is AND.
pub fn is_and(instr: u16) -> bool {
    get_opcode(instr) == two_op::AND
}

/// Check if instruction is XOR.
pub fn is_xor(instr: u16) -> bool {
    get_opcode(instr) == two_op::XOR
}

/// Check if instruction is BR (branch through register/memory).
pub fn is_br(instr: u16) -> bool {
    // BR is MOV src, PC (dst=0, which is PC)
    get_opcode(instr) == two_op::MOV && get_dst_reg(instr) == reg::PC
}

/// Strong indicator patterns for heuristic detection.
pub const STRONG_INDICATORS: &[u16] = &[patterns::NOP, patterns::RET, patterns::RETI];

/// Check if instruction looks like valid MSP430 code.
pub fn is_likely_valid(instr: u16) -> bool {
    let op = get_opcode(instr);

    // Jump format
    if is_jump_format(instr) {
        return true;
    }

    // Single operand format (opcode 1)
    if op == 0x1 {
        let sub_op = get_single_op(instr);
        // Valid sub-opcodes are 0-6
        return sub_op <= 6;
    }

    // Two-operand format (opcodes 4-F)
    if op >= 0x4 && op <= 0xF {
        return true;
    }

    // Reserved/invalid opcodes
    false
}

/// Score likelihood of MSP430 code.
///
/// Analyzes raw bytes for patterns characteristic of MSP430.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut jump_count = 0u32;
    let mut distinctive_count = 0u32; // SP ops, CG/SR constants, PC/SR destinations

    // MSP430 is little-endian, 16-bit aligned
    let num_halfwords = data.len() / 2;
    let mut instruction_count = 0u32;
    let mut idx = 0usize;
    while idx < num_halfwords {
        let orig_idx = idx;
        let i = idx * 2;
        let word = u16::from_le_bytes([data[i], data[i + 1]]);
        let opcode = get_opcode(word);
        instruction_count += 1;
        // Advance idx by 1 immediately; extension words added for recognized MSP430 instructions
        idx += 1;

        // Invalid/padding
        if word == 0x0000 || word == 0xFFFF {
            score -= 3;
            invalid_count += 1;
            continue;
        }

        // --- AVR cross-architecture penalties ---
        if word == 0x9508 { score -= 15; continue; } // AVR RET
        if word == 0x9518 { score -= 15; continue; } // AVR RETI
        if word == 0x9588 { score -= 10; continue; } // AVR SLEEP
        if word == 0x9598 { score -= 8; continue; }  // AVR BREAK
        if word == 0x9478 { score -= 8; continue; }  // AVR SEI
        if word == 0x94F8 { score -= 8; continue; }  // AVR CLI
        if word == 0x9409 { score -= 8; continue; }  // AVR IJMP
        if word == 0x9509 { score -= 8; continue; }  // AVR ICALL
        if (word & 0xFE0F) == 0x920F { score -= 5; continue; } // AVR PUSH
        if (word & 0xFE0F) == 0x900F { score -= 5; continue; } // AVR POP

        // --- Thumb cross-architecture penalties ---
        if word == 0x4770 { score -= 15; continue; } // Thumb BX LR
        if word == 0xBF00 { score -= 10; continue; } // Thumb NOP
        if matches!(word, 0xB672 | 0xB662 | 0xB673 | 0xB663) { score -= 15; continue; }
        if matches!(word, 0xBF30 | 0xBF20 | 0xBF40) { score -= 12; continue; }
        if (word & 0xFF00) == 0xB500 { score -= 8; continue; } // Thumb PUSH{LR}
        if (word & 0xFF00) == 0xBD00 { score -= 8; continue; } // Thumb POP{PC}

        // --- 32-bit LE cross-architecture penalties ---
        if orig_idx % 2 == 0 && orig_idx + 1 < num_halfwords {
            let next_hw = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            let word32 = (next_hw as u32) << 16 | (word as u32);
            if word32 == 0x961EC01E { score -= 20; }
            if (word32 & 0xFFFF0000) == 0x7F000000 { score -= 15; }
            if (word32 & 0xFFFFE000) == 0xA09DC000 { score -= 15; }
            if word32 == 0xD65F03C0 { score -= 20; }
            if word32 == 0xD503201F { score -= 15; }
            if (word32 & 0xFFC0FFFF) == 0xA9007BFD { score -= 15; }
            if (word32 & 0xFFC0FFFF) == 0xA8407BFD { score -= 15; }
            if (word32 >> 26) == 0x25 { score -= 8; }
            if (word32 & 0xFFF00000) == 0xD5300000 || (word32 & 0xFFF00000) == 0xD5100000 { score -= 10; }
            if word32 == 0x00000013 { score -= 10; }
            if word32 == 0x00008067 { score -= 15; }
            if word32 == 0x4E800020 { score -= 15; }
            if word32 == 0x60000000 { score -= 10; }
            if word32 == 0x7C0802A6 { score -= 10; }
            if word32 == 0x7C0803A6 { score -= 10; }
            if word32 == 0x03400000 { score -= 10; }
            if word32 == 0x4C000020 { score -= 12; }
            if (word32 & 0xFFFF0000) == 0x89480000 || (word32 & 0xFFFF0000) == 0x8B480000 { score -= 5; }
            // AArch64 FP data processing (0x1Exxxxxx) — very common in float code
            if (word32 >> 24) as u8 == 0x1E { score -= 5; }
            // AArch64 LDR/STR unsigned immediate
            if matches!((word32 >> 24) as u8, 0xB9 | 0xF9 | 0xB8 | 0xF8 | 0x39 | 0x79 | 0x38 | 0x78) { score -= 3; }
            // AArch64 ADD/SUB immediate
            if (word32 >> 24) as u8 & 0x1F == 0x11 { score -= 3; }
            // AArch64 ADRP
            if (word32 & 0x9F000000) == 0x90000000 { score -= 3; }
            // AArch64 MOV wide (MOVZ/MOVK/MOVN)
            if matches!((word32 >> 24) as u8, 0x52 | 0x72 | 0xD2 | 0xF2 | 0x92) { score -= 3; }
            // AArch64 B.cond
            if (word32 & 0xFF000010) == 0x54000000 { score -= 3; }
            // AArch64 CBZ/CBNZ
            if (word32 & 0x7E000000) == 0x34000000 { score -= 3; }
            // AArch64 STP/LDP general (pre-index and post-index forms)
            {
                let opc22 = (word32 >> 22) & 0x1FF;
                if matches!(opc22, 0x150 | 0x151 | 0x144 | 0x145 | 0x148 | 0x149 | 0x14C | 0x14D) { score -= 5; }
            }
            // AArch64 MADD/MSUB
            if (word32 & 0x7FE08000) == 0x1B000000 { score -= 5; }
            // AArch64 CSEL/CSINC/CSINV/CSNEG
            if (word32 & 0x7FE00C00) == 0x1A800000 { score -= 5; }
        }

        // Exact match patterns (high confidence)
        if is_nop(word) {
            score += 20;
            valid_count += 1;
            continue;
        }
        if is_ret(word) {
            score += 25;
            ret_count += 1;
            valid_count += 1;
            continue;
        }
        if is_reti(word) {
            score += 20;
            ret_count += 1;
            valid_count += 1;
            continue;
        }

        // Unconditional JMP (no extension words)
        if is_jmp(word) {
            score += 8;
            jump_count += 1;
            valid_count += 1;
            continue;
        }

        // Conditional jumps (no extension words)
        if is_jump_format(word) {
            let offset = get_jump_offset(word);
            if offset.unsigned_abs() < 128 {
                score += 6;
            } else {
                score += 3;
            }
            jump_count += 1;
            valid_count += 1;
            continue;
        }

        // Single-operand format — skip extension words
        if is_single_op_format(word) {
            let sub_op = get_single_op(word);
            match sub_op {
                o if o == single_op::PUSH => score += 8,
                o if o == single_op::CALL => { score += 10; call_count += 1; }
                o if o == single_op::RETI => { score += 6; ret_count += 1; }
                o if o == single_op::RRC => score += 4,
                o if o == single_op::SWPB => score += 4,
                o if o == single_op::RRA => score += 4,
                o if o == single_op::SXT => score += 5,
                _ if sub_op <= 6 => score += 2,
                _ => { score -= 1; invalid_count += 1; continue; }
            }
            valid_count += 1;
            idx += extension_words(word); // Skip extension words (data halfwords)
            continue;
        }

        // Two-operand format — skip extension words
        if is_two_op_format(word) {
            let src = get_src_reg(word);
            let dst = get_dst_reg(word);
            let as_mode = get_as(word);

            let sp_involved = dst == reg::SP || src == reg::SP;
            let cg_const = src == reg::CG && as_mode >= 1;
            let sr_const = src == reg::SR && as_mode >= 2;

            if sp_involved || cg_const || sr_const || dst == reg::PC || dst == reg::SR {
                distinctive_count += 1;
                match opcode {
                    o if o == two_op::MOV => score += 5,
                    o if o == two_op::ADD || o == two_op::SUB => score += 5,
                    o if o == two_op::BIC || o == two_op::BIS => {
                        if dst == reg::SR { score += 6; } else { score += 3; }
                    }
                    _ => score += 3,
                }
            } else {
                score += 1;
            }
            valid_count += 1;
            idx += extension_words(word); // Skip extension words (data halfwords)
            continue;
        }

        // Unrecognized (opcode 0, 2, 3): reserved in MSP430
        score -= 3;
        invalid_count += 1;
    }

    // Structural bonus for MSP430-specific patterns
    if ret_count > 0 && (call_count > 0 || jump_count > 0) {
        score += 15;
    }

    // Structural requirement: use instruction_count (not raw halfwords) to avoid
    // penalizing small files that appear large due to extension words.
    // Use a higher threshold (40) to avoid killing scores on micro-benchmark
    // code blobs that have valid MSP430 but no function structure.
    if instruction_count > 40 {
        if ret_count == 0 {
            score = (score as f64 * 0.10) as i64;
        } else if ret_count == 1 && call_count == 0 && jump_count < 2 {
            score = (score as f64 * 0.30) as i64;
        }
    } else if instruction_count > 20 && ret_count == 0 && call_count == 0 && jump_count == 0 {
        // Smaller files with zero control flow evidence — moderate penalty
        score = (score as f64 * 0.40) as i64;
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop_detection() {
        assert!(is_nop(patterns::NOP));
        assert!(!is_nop(patterns::RET));
    }

    #[test]
    fn test_return_detection() {
        assert!(is_ret(patterns::RET));
        assert!(is_reti(patterns::RETI));
        assert!(is_return(patterns::RET));
        assert!(is_return(patterns::RETI));
    }

    #[test]
    fn test_jump_format() {
        // JMP .+0 = 0x3C00
        assert!(is_jump_format(0x3C00));
        assert!(is_jmp(0x3C00));

        // JEQ .+4 = 0x2402
        assert!(is_jump_format(0x2402));
        assert!(is_conditional_jump(0x2402));
    }

    #[test]
    fn test_opcode_extraction() {
        // MOV R4, R5 = 0x4504
        assert_eq!(get_opcode(0x4504), two_op::MOV);
        assert_eq!(get_src_reg(0x4504), 5);
        assert_eq!(get_dst_reg(0x4504), 4);
    }

    #[test]
    fn test_call_detection() {
        // CALL R5 = 0x1285
        let call_r5 = 0x1285;
        assert!(is_call(call_r5));
    }

    #[test]
    fn test_push_detection() {
        // PUSH R5 = 0x1205
        let push_r5 = 0x1205;
        assert!(is_push(push_r5));
    }

    #[test]
    fn test_br_detection() {
        // BR R5 (MOV R5, PC) = 0x4500
        let br_r5 = 0x4500;
        assert!(is_br(br_r5));
    }

    #[test]
    fn test_jump_offset() {
        // JMP .+0
        assert_eq!(get_jump_offset(0x3C00), 0);
        // JMP .-2 (offset -1)
        assert_eq!(get_jump_offset(0x3FFF), -1);
        // JMP .+10 (offset 5)
        assert_eq!(get_jump_offset(0x3C05), 5);
    }

    #[test]
    fn test_bw_bit() {
        // MOV.B = bit 6 set
        assert!(get_bw(0x4540));
        // MOV.W = bit 6 clear
        assert!(!get_bw(0x4500));
    }

    #[test]
    fn test_score() {
        // MSP430 RET (little-endian)
        let ret = patterns::RET.to_le_bytes();
        assert!(score(&ret) > 0);
    }
}
