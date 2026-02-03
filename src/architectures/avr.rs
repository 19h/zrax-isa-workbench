//! Atmel AVR architecture analysis.
//!
//! AVR uses mostly 16-bit instructions with some 32-bit instructions,
//! little-endian encoding, 16-bit aligned. It's a Harvard architecture
//! microcontroller series.

/// Instruction format groups based on bits 15:10.
pub mod format {
    // Single 16-bit instructions
    pub const NOP: u16 = 0x0000;

    // Two-word (32-bit) instructions - identified by specific patterns
    pub const JMP_MASK: u16 = 0xFE0E;
    pub const JMP_VAL: u16 = 0x940C;
    pub const CALL_MASK: u16 = 0xFE0E;
    pub const CALL_VAL: u16 = 0x940E;
    pub const LDS_MASK: u16 = 0xFE0F;
    pub const LDS_VAL: u16 = 0x9000;
    pub const STS_MASK: u16 = 0xFE0F;
    pub const STS_VAL: u16 = 0x9200;
}

/// Common AVR instruction patterns.
pub mod patterns {
    /// NOP.
    pub const NOP: u16 = 0x0000;

    /// RET (return from subroutine).
    pub const RET: u16 = 0x9508;

    /// RETI (return from interrupt).
    pub const RETI: u16 = 0x9518;

    /// SLEEP.
    pub const SLEEP: u16 = 0x9588;

    /// BREAK (for debuggers).
    pub const BREAK: u16 = 0x9598;

    /// WDR (watchdog reset).
    pub const WDR: u16 = 0x95A8;

    /// SPM (store program memory).
    pub const SPM: u16 = 0x95E8;

    /// IJMP (indirect jump via Z).
    pub const IJMP: u16 = 0x9409;

    /// ICALL (indirect call via Z).
    pub const ICALL: u16 = 0x9509;

    /// EIJMP (extended indirect jump).
    pub const EIJMP: u16 = 0x9419;

    /// EICALL (extended indirect call).
    pub const EICALL: u16 = 0x9519;

    /// SEC (set carry flag).
    pub const SEC: u16 = 0x9408;

    /// CLC (clear carry flag).
    pub const CLC: u16 = 0x9488;

    /// SEN (set negative flag).
    pub const SEN: u16 = 0x9428;

    /// CLN (clear negative flag).
    pub const CLN: u16 = 0x94A8;

    /// SEZ (set zero flag).
    pub const SEZ: u16 = 0x9418;

    /// CLZ (clear zero flag).
    pub const CLZ: u16 = 0x9498;

    /// SEI (set interrupt enable).
    pub const SEI: u16 = 0x9478;

    /// CLI (clear interrupt enable).
    pub const CLI: u16 = 0x94F8;

    // Masks for instruction groups
    pub const RJMP_MASK: u16 = 0xF000;
    pub const RJMP_VAL: u16 = 0xC000;

    pub const RCALL_MASK: u16 = 0xF000;
    pub const RCALL_VAL: u16 = 0xD000;

    pub const BRBS_MASK: u16 = 0xFC00; // Branch if bit set
    pub const BRBS_VAL: u16 = 0xF000;

    pub const BRBC_MASK: u16 = 0xFC00; // Branch if bit clear
    pub const BRBC_VAL: u16 = 0xF400;

    pub const LDI_MASK: u16 = 0xF000; // Load immediate
    pub const LDI_VAL: u16 = 0xE000;

    pub const MOV_MASK: u16 = 0xFC00; // Copy register
    pub const MOV_VAL: u16 = 0x2C00;

    pub const ADD_MASK: u16 = 0xFC00; // Add
    pub const ADD_VAL: u16 = 0x0C00;

    pub const SUB_MASK: u16 = 0xFC00; // Subtract
    pub const SUB_VAL: u16 = 0x1800;

    pub const AND_MASK: u16 = 0xFC00; // Logical AND
    pub const AND_VAL: u16 = 0x2000;

    pub const OR_MASK: u16 = 0xFC00; // Logical OR
    pub const OR_VAL: u16 = 0x2800;

    pub const EOR_MASK: u16 = 0xFC00; // Exclusive OR
    pub const EOR_VAL: u16 = 0x2400;

    pub const CP_MASK: u16 = 0xFC00; // Compare
    pub const CP_VAL: u16 = 0x1400;

    pub const CPC_MASK: u16 = 0xFC00; // Compare with carry
    pub const CPC_VAL: u16 = 0x0400;

    pub const CPI_MASK: u16 = 0xF000; // Compare with immediate
    pub const CPI_VAL: u16 = 0x3000;

    pub const IN_MASK: u16 = 0xF800; // In from I/O
    pub const IN_VAL: u16 = 0xB000;

    pub const OUT_MASK: u16 = 0xF800; // Out to I/O
    pub const OUT_VAL: u16 = 0xB800;

    pub const PUSH_MASK: u16 = 0xFE0F; // Push register
    pub const PUSH_VAL: u16 = 0x920F;

    pub const POP_MASK: u16 = 0xFE0F; // Pop register
    pub const POP_VAL: u16 = 0x900F;
}

/// Extract destination register Rd (bits 8:4 typically).
pub fn get_rd_5bit(instr: u16) -> u8 {
    ((instr >> 4) & 0x1F) as u8
}

/// Extract source register Rr (bits 9, 3:0 combined).
pub fn get_rr_5bit(instr: u16) -> u8 {
    let low = (instr & 0x0F) as u8;
    let high = ((instr >> 9) & 0x01) as u8;
    (high << 4) | low
}

/// Extract 4-bit destination register for high-reg ops (Rd: r16-r31).
pub fn get_rd_4bit(instr: u16) -> u8 {
    (((instr >> 4) & 0x0F) + 16) as u8
}

/// Extract 8-bit immediate (K) for LDI, CPI, etc.
/// LDI encoding: 1110 KKKK dddd KKKK (K in bits [11:8] and [3:0])
pub fn get_k8(instr: u16) -> u8 {
    let low = (instr & 0x0F) as u8;
    let high = ((instr >> 4) & 0xF0) as u8;
    high | low
}

/// Extract 12-bit relative offset for RJMP/RCALL.
pub fn get_k12(instr: u16) -> i16 {
    let val = (instr & 0x0FFF) as i16;
    // Sign extend from 12 bits
    if val & 0x0800 != 0 {
        val | !0x0FFF
    } else {
        val
    }
}

/// Extract 7-bit relative offset for conditional branches.
pub fn get_k7(instr: u16) -> i8 {
    let val = ((instr >> 3) & 0x7F) as i8;
    // Sign extend from 7 bits
    if val & 0x40 != 0 {
        val | !0x7F
    } else {
        val
    }
}

/// Extract 6-bit I/O address for IN/OUT.
pub fn get_io_addr(instr: u16) -> u8 {
    let low = ((instr >> 0) & 0x0F) as u8;
    let high = ((instr >> 5) & 0x30) as u8;
    high | low
}

/// Extract bit number for BRBS/BRBC (bits 2:0).
pub fn get_bit_num(instr: u16) -> u8 {
    (instr & 0x07) as u8
}

/// Check if instruction is a two-word (32-bit) instruction.
pub fn is_two_word(instr: u16) -> bool {
    // JMP, CALL, LDS, STS are 32-bit
    ((instr & format::JMP_MASK) == format::JMP_VAL)
        || ((instr & format::CALL_MASK) == format::CALL_VAL)
        || ((instr & format::LDS_MASK) == format::LDS_VAL)
        || ((instr & format::STS_MASK) == format::STS_VAL)
}

/// Determine instruction length in bytes.
pub fn instruction_length(instr: u16) -> usize {
    if is_two_word(instr) {
        4
    } else {
        2
    }
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u16) -> bool {
    instr == patterns::NOP
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
    matches!(instr, patterns::RET | patterns::RETI)
}

/// Check if instruction is RJMP.
pub fn is_rjmp(instr: u16) -> bool {
    (instr & patterns::RJMP_MASK) == patterns::RJMP_VAL
}

/// Check if instruction is RCALL.
pub fn is_rcall(instr: u16) -> bool {
    (instr & patterns::RCALL_MASK) == patterns::RCALL_VAL
}

/// Check if instruction is IJMP.
pub fn is_ijmp(instr: u16) -> bool {
    instr == patterns::IJMP
}

/// Check if instruction is ICALL.
pub fn is_icall(instr: u16) -> bool {
    instr == patterns::ICALL
}

/// Check if instruction is JMP (32-bit).
pub fn is_jmp(instr: u16) -> bool {
    (instr & format::JMP_MASK) == format::JMP_VAL
}

/// Check if instruction is CALL (32-bit).
pub fn is_call_32(instr: u16) -> bool {
    (instr & format::CALL_MASK) == format::CALL_VAL
}

/// Check if instruction is a branch (RJMP, IJMP, conditional branches).
pub fn is_branch(instr: u16) -> bool {
    is_rjmp(instr)
        || is_ijmp(instr)
        || is_jmp(instr)
        || ((instr & patterns::BRBS_MASK) == patterns::BRBS_VAL)
        || ((instr & patterns::BRBC_MASK) == patterns::BRBC_VAL)
}

/// Check if instruction is a call (RCALL, ICALL, CALL).
pub fn is_call(instr: u16) -> bool {
    is_rcall(instr) || is_icall(instr) || is_call_32(instr)
}

/// Check if instruction is a conditional branch.
pub fn is_conditional_branch(instr: u16) -> bool {
    ((instr & patterns::BRBS_MASK) == patterns::BRBS_VAL)
        || ((instr & patterns::BRBC_MASK) == patterns::BRBC_VAL)
}

/// Check if instruction is LDI (load immediate).
pub fn is_ldi(instr: u16) -> bool {
    (instr & patterns::LDI_MASK) == patterns::LDI_VAL
}

/// Check if instruction is MOV.
pub fn is_mov(instr: u16) -> bool {
    (instr & patterns::MOV_MASK) == patterns::MOV_VAL
}

/// Check if instruction is PUSH.
pub fn is_push(instr: u16) -> bool {
    (instr & patterns::PUSH_MASK) == patterns::PUSH_VAL
}

/// Check if instruction is POP.
pub fn is_pop(instr: u16) -> bool {
    (instr & patterns::POP_MASK) == patterns::POP_VAL
}

/// Check if instruction is IN.
pub fn is_in(instr: u16) -> bool {
    (instr & patterns::IN_MASK) == patterns::IN_VAL
}

/// Check if instruction is OUT.
pub fn is_out(instr: u16) -> bool {
    (instr & patterns::OUT_MASK) == patterns::OUT_VAL
}

/// Strong indicator patterns for heuristic detection.
pub const STRONG_INDICATORS: &[u16] = &[
    patterns::NOP,
    patterns::RET,
    patterns::RETI,
    patterns::SLEEP,
    patterns::BREAK,
    patterns::WDR,
    patterns::IJMP,
    patterns::ICALL,
    patterns::SEI,
    patterns::CLI,
];

/// Check if instruction looks like valid AVR code.
pub fn is_likely_valid(instr: u16) -> bool {
    // NOP is 0x0000, which is also common in padding
    if instr == patterns::NOP {
        return true;
    }

    // Check for known instruction patterns
    // This is a simplified check - real validation would be more thorough
    let high_nibble = (instr >> 12) & 0xF;

    match high_nibble {
        0x0 => {
            // NOP, MOVW, MULS, MULSU, FMUL, etc.
            true
        }
        0x1 | 0x2 | 0x3 => {
            // ALU operations
            true
        }
        0x4 | 0x5 | 0x6 | 0x7 => {
            // Immediate operations (SBCI, SUBI, ORI, ANDI, LDD, STD)
            true
        }
        0x8 | 0x9 | 0xA => {
            // Load/store, LDD/STD with displacement
            true
        }
        0xB => {
            // IN/OUT
            true
        }
        0xC | 0xD => {
            // RJMP, RCALL
            true
        }
        0xE => {
            // LDI
            true
        }
        0xF => {
            // BRBS, BRBC, BLD, BST, SBRC, SBRS
            true
        }
        _ => false,
    }
}

/// Score likelihood of AVR code.
///
/// Analyzes raw bytes for patterns characteristic of AVR.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut i = 0;
    let mut zero_run: u32 = 0;

    // AVR is little-endian, mostly 16-bit instructions (some 32-bit)
    while i + 2 <= data.len() {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);

        // NOP (0x0000) - but be careful: zeros are often padding, not real NOPs
        // Only score NOPs that appear isolated, not in long runs
        if is_nop(word) {
            zero_run += 1;
            if zero_run <= 2 {
                // Only score first couple zeros in a row
                score += 5;
            } else if zero_run > 8 {
                // Long zero runs are likely padding, penalize slightly
                score -= 1;
            }
            i += 2;
            continue;
        } else {
            zero_run = 0;
        }

        // RET (return from subroutine)
        if is_ret(word) {
            score += 30;
        }

        // RETI (return from interrupt)
        if is_reti(word) {
            score += 25;
        }

        // SLEEP
        if word == patterns::SLEEP {
            score += 15;
        }

        // BREAK
        if word == patterns::BREAK {
            score += 15;
        }

        // CLI (disable interrupts)
        if word == patterns::CLI {
            score += 10;
        }

        // SEI (enable interrupts)
        if word == patterns::SEI {
            score += 10;
        }

        // RJMP (relative jump)
        if is_rjmp(word) {
            score += 8;
        }

        // RCALL (relative call)
        if is_rcall(word) {
            score += 8;
        }

        // LDI (load immediate)
        if is_ldi(word) {
            score += 5;
        }

        // PUSH
        if is_push(word) {
            score += 8;
        }

        // POP
        if is_pop(word) {
            score += 8;
        }

        // IN (I/O read)
        if is_in(word) {
            score += 3;
        }

        // OUT (I/O write)
        if is_out(word) {
            score += 3;
        }

        // MOV (register copy)
        if is_mov(word) {
            score += 3;
        }

        // Check if 32-bit instruction
        if is_two_word(word) {
            score += 5;
            i += 2; // Skip extra word
        }

        // Invalid (all Fs)
        if word == 0xFFFF {
            score -= 5;
        }

        i += 2;
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
    fn test_rjmp_detection() {
        // RJMP .+0 = 0xC000
        assert!(is_rjmp(0xC000));
        // RJMP .-2 = 0xCFFF
        assert!(is_rjmp(0xCFFF));
    }

    #[test]
    fn test_rcall_detection() {
        // RCALL .+0 = 0xD000
        assert!(is_rcall(0xD000));
    }

    #[test]
    fn test_ldi_detection() {
        // LDI R16, 0 = 0xE000
        assert!(is_ldi(0xE000));
        // LDI R31, 0xFF = 0xEFFF
        assert!(is_ldi(0xEFFF));
    }

    #[test]
    fn test_two_word() {
        // JMP = 0x940C + low bits
        assert!(is_two_word(0x940C));
        // CALL = 0x940E + low bits
        assert!(is_two_word(0x940E));
        // Regular instruction should not be two-word
        assert!(!is_two_word(patterns::NOP));
        assert!(!is_two_word(patterns::RET));
    }

    #[test]
    fn test_k12_extraction() {
        // RJMP .+0
        assert_eq!(get_k12(0xC000), 0);
        // RJMP .-2 (0xFFF = -1 in 12-bit signed)
        assert_eq!(get_k12(0xCFFF), -1);
        // RJMP .+100
        assert_eq!(get_k12(0xC064), 100);
    }

    #[test]
    fn test_k8_extraction() {
        // LDI encoding: 1110 KKKK dddd KKKK
        // K high nibble in bits [11:8], K low nibble in bits [3:0]
        // d (register - 16) in bits [7:4]

        // LDI R16, 0x00 = 1110 0000 0000 0000 = 0xE000
        assert_eq!(get_k8(0xE000), 0x00);
        // LDI R16, 0xFF = 1110 1111 0000 1111 = 0xEF0F
        assert_eq!(get_k8(0xEF0F), 0xFF);
        // LDI R16, 0xAB = 1110 1010 0000 1011 = 0xEA0B
        assert_eq!(get_k8(0xEA0B), 0xAB);
    }

    #[test]
    fn test_push_pop() {
        // PUSH R0 = 0x920F
        assert!(is_push(0x920F));
        // PUSH R31 = 0x93FF (actually 0x93EF for R31? Let's verify the encoding)
        // PUSH Rr: 1001 001r rrrr 1111, so PUSH R31 = 1001 0011 1111 1111 = 0x93FF
        assert!(is_push(0x93FF));

        // POP R0 = 0x900F
        assert!(is_pop(0x900F));
    }

    #[test]
    fn test_score() {
        // AVR RET (little-endian)
        let ret = patterns::RET.to_le_bytes();
        assert!(score(&ret) > 0);
    }
}
