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
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;
    let mut valid_count = 0u32;

    // AVR is little-endian, mostly 16-bit instructions (some 32-bit)
    while i + 2 <= data.len() {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);

        // NOP (0x0000) - but be careful: zeros are often padding, not real NOPs
        // Only score NOPs that appear isolated, not in long runs
        if is_nop(word) {
            zero_run += 1;
            if zero_run <= 2 {
                score += 5;
                valid_count += 1;
            } else if zero_run > 8 {
                score -= 1;
            }
            i += 2;
            continue;
        } else {
            zero_run = 0;
        }

        // Invalid (all Fs)
        if word == 0xFFFF {
            score -= 5;
            i += 2;
            continue;
        }

        // --- MSP430 cross-architecture penalties ---
        // MSP430 uses same 16-bit LE format; penalize distinctive MSP430 patterns
        if word == 0x4130 { score -= 15; i += 2; continue; } // MSP430 RET
        if word == 0x4303 { score -= 12; i += 2; continue; } // MSP430 NOP
        if word == 0x1300 { score -= 12; i += 2; continue; } // MSP430 RETI
        // MSP430 CALL (0x12xx)
        if (word & 0xFF80) == 0x1280 { score -= 8; i += 2; continue; }
        // MSP430 PUSH (0x12xx)
        if (word & 0xFF80) == 0x1200 && (word & 0xFF80) != 0x1280 {
            score -= 5; i += 2; continue;
        }

        // --- Thumb cross-architecture penalties ---
        // Thumb uses same 16-bit LE format; penalize distinctive Thumb patterns
        if word == 0x4770 { score -= 12; i += 2; continue; } // Thumb BX LR
        if word == 0xBF00 { score -= 10; i += 2; continue; } // Thumb NOP
        // CPSID/CPSIE variants (very firmware-specific, unlikely in AVR context)
        if matches!(word, 0xB672 | 0xB662 | 0xB673 | 0xB663) {
            score -= 10; i += 2; continue;
        }
        // WFI/WFE/SEV
        if matches!(word, 0xBF30 | 0xBF20 | 0xBF40) {
            score -= 8; i += 2; continue;
        }
        // Thumb PUSH {.., LR} (0xB5xx) - very common function prologue
        if (word & 0xFF00) == 0xB500 { score -= 10; i += 2; continue; }
        // Thumb POP {.., PC} (0xBDxx) - very common function epilogue/return
        if (word & 0xFF00) == 0xBD00 { score -= 10; i += 2; continue; }
        // Thumb ADD/SUB SP, #imm (0xB0xx) - stack frame adjustment
        if (word & 0xFF00) == 0xB000 { score -= 6; i += 2; continue; }
        // Thumb SVC (0xDFxx) - skip: 0xDxxx are all valid AVR RCALLs
        // Penalizing this range causes massive false negatives on AVR code
        // Thumb CBZ/CBNZ (0xB1xx, 0xB9xx, 0xB3xx, 0xBBxx)
        if (word & 0xF500) == 0xB100 { score -= 8; i += 2; continue; }

        // --- Exact match patterns (high confidence) ---

        // RET (return from subroutine)
        if is_ret(word) {
            score += 30;
            ret_count += 1;
            valid_count += 1;
            i += 2;
            continue;
        }

        // RETI (return from interrupt)
        if is_reti(word) {
            score += 25;
            ret_count += 1;
            valid_count += 1;
            i += 2;
            continue;
        }

        // SLEEP
        if word == patterns::SLEEP {
            score += 15;
            valid_count += 1;
            i += 2;
            continue;
        }

        // BREAK
        if word == patterns::BREAK {
            score += 15;
            valid_count += 1;
            i += 2;
            continue;
        }

        // CLI (disable interrupts)
        if word == patterns::CLI {
            score += 10;
            valid_count += 1;
            i += 2;
            continue;
        }

        // SEI (enable interrupts)
        if word == patterns::SEI {
            score += 10;
            valid_count += 1;
            i += 2;
            continue;
        }

        // WDR (watchdog reset) - very distinctive
        if word == patterns::WDR {
            score += 10;
            valid_count += 1;
            i += 2;
            continue;
        }

        // ICALL / IJMP - distinctive
        if word == patterns::ICALL {
            score += 10;
            call_count += 1;
            valid_count += 1;
            i += 2;
            continue;
        }
        if word == patterns::IJMP {
            score += 8;
            branch_count += 1;
            valid_count += 1;
            i += 2;
            continue;
        }

        // PUSH
        if is_push(word) {
            score += 8;
            valid_count += 1;
            i += 2;
            continue;
        }

        // POP
        if is_pop(word) {
            score += 8;
            valid_count += 1;
            i += 2;
            continue;
        }

        // RCALL (relative call) - 6.25% of space
        if is_rcall(word) {
            score += 5;
            call_count += 1;
            valid_count += 1;
            i += 2;
            continue;
        }

        // RJMP (relative jump) - 6.25% of space
        if is_rjmp(word) {
            score += 4;
            branch_count += 1;
            valid_count += 1;
            i += 2;
            continue;
        }

        // Conditional branches (BRBS/BRBC)
        if is_conditional_branch(word) {
            score += 4;
            branch_count += 1;
            valid_count += 1;
            i += 2;
            continue;
        }

        // LDI (load immediate) - 6.25% of space
        if is_ldi(word) {
            score += 3;
            valid_count += 1;
            i += 2;
            continue;
        }

        // IN (I/O read)
        if is_in(word) {
            score += 4;
            valid_count += 1;
            i += 2;
            continue;
        }

        // OUT (I/O write)
        if is_out(word) {
            score += 4;
            valid_count += 1;
            i += 2;
            continue;
        }

        // Check if 32-bit instruction (JMP, CALL, LDS, STS)
        if is_two_word(word) {
            if is_call_32(word) {
                score += 8;
                call_count += 1;
            } else if is_jmp(word) {
                score += 6;
                branch_count += 1;
            } else {
                score += 5; // LDS/STS
            }
            valid_count += 1;
            i += 4; // Skip entire 32-bit instruction
            continue;
        }

        // CPI (compare immediate) - 6.25% of space
        if (word & patterns::CPI_MASK) == patterns::CPI_VAL {
            score += 3;
            valid_count += 1;
            i += 2;
            continue;
        }

        // MOV (register copy)
        if is_mov(word) {
            score += 2;
            valid_count += 1;
            i += 2;
            continue;
        }

        // ALU operations (ADD, SUB, AND, OR, EOR, CP, CPC) - each 1.5% of space
        if (word & patterns::ADD_MASK) == patterns::ADD_VAL
            || (word & patterns::SUB_MASK) == patterns::SUB_VAL
            || (word & patterns::AND_MASK) == patterns::AND_VAL
            || (word & patterns::OR_MASK) == patterns::OR_VAL
            || (word & patterns::EOR_MASK) == patterns::EOR_VAL
            || (word & patterns::CP_MASK) == patterns::CP_VAL
            || (word & patterns::CPC_MASK) == patterns::CPC_VAL
        {
            score += 2;
            valid_count += 1;
            i += 2;
            continue;
        }

        // --- Additional recognized AVR instructions ---
        // These cover broad parts of the encoding space. Score at 0 (avoid -1 penalty)
        // to prevent false positives while still helping AVR files by not penalizing
        // their legitimate instructions.

        // ADC/ROL (0x1Cxx-0x1Fxx), SBC (0x08xx-0x0Bxx), CPSE (0x10xx-0x13xx)
        if (word & 0xFC00) == 0x1C00
            || (word & 0xFC00) == 0x0800
            || (word & 0xFC00) == 0x1000
        {
            valid_count += 1;
            i += 2;
            continue;
        }

        // MOVW (0x01xx) - somewhat distinctive (0.4% of space)
        if (word & 0xFF00) == 0x0100 {
            score += 1;
            valid_count += 1;
            i += 2;
            continue;
        }

        // ADIW (0x96xx) - very distinctive AVR-specific instruction (0.4% of space)
        if (word & 0xFF00) == 0x9600 {
            score += 4;
            valid_count += 1;
            i += 2;
            continue;
        }

        // SBIW (0x97xx) - very distinctive AVR-specific instruction (0.4% of space)
        if (word & 0xFF00) == 0x9700 {
            score += 4;
            valid_count += 1;
            i += 2;
            continue;
        }

        // Immediate operations: SBCI(0x4), SUBI(0x5), ORI(0x6), ANDI(0x7) - 25% total
        // Too broad for positive scoring — just avoid the -1 penalty
        {
            let high_nib = (word >> 12) & 0xF;
            if matches!(high_nib, 0x4 | 0x5 | 0x6 | 0x7) {
                valid_count += 1;
                i += 2;
                continue;
            }
        }

        // LDD/STD with displacement (0x8xxx, 0xAxxx) - 12.5% total
        // Too broad for positive scoring — just avoid the -1 penalty
        if (word & 0xD000) == 0x8000 {
            valid_count += 1;
            i += 2;
            continue;
        }

        // Single-register ops in 0x94xx/0x95xx range:
        // COM(0), NEG(1), SWAP(2), INC(3), ASR(5), LSR(6), ROR(7), DEC(A)
        if (word & 0xFE00) == 0x9400 {
            let sub_op = word & 0x000F;
            if matches!(sub_op, 0x0 | 0x1 | 0x2 | 0x3 | 0x5 | 0x6 | 0x7 | 0xA) {
                score += 1;
                valid_count += 1;
                i += 2;
                continue;
            }
        }

        // BLD/BST, SBRC/SBRS (bit manipulation in 0xFxxx range already covered by BRBS/BRBC)

        // Unrecognized - small penalty
        score -= 1;
        i += 2;
    }

    // Structural bonus: real code has returns and calls/branches
    if ret_count > 0 && (call_count > 0 || branch_count > 0) {
        score += 15;
    }

    // AVR interrupt vector table detection:
    // AVR firmwares start with a table of RJMP instructions (reset + interrupt vectors).
    // Look for 3+ consecutive RJMP at the beginning of the data.
    if data.len() >= 8 {
        let mut ivt_rjmp_count = 0u32;
        let mut j = 0;
        while j + 1 < data.len().min(128) {
            let w = u16::from_le_bytes([data[j], data[j + 1]]);
            if is_rjmp(w) {
                ivt_rjmp_count += 1;
            } else {
                break;
            }
            j += 2;
        }
        if ivt_rjmp_count >= 3 {
            // Strong AVR IVT signature: 3+ consecutive RJMP
            score += (ivt_rjmp_count * 15) as i64;
        }
    }

    // AVR function prologue detection:
    // Common pattern: PUSH rN; PUSH rN+1; ... ; IN r28, 0x3D; IN r29, 0x3E
    // (save registers then load stack pointer)
    {
        let mut j = 0;
        while j + 5 < data.len() {
            let w0 = u16::from_le_bytes([data[j], data[j + 1]]);
            let w1 = u16::from_le_bytes([data[j + 2], data[j + 3]]);
            let w2 = u16::from_le_bytes([data[j + 4], data[j + 5]]);

            // PUSH followed by PUSH
            if is_push(w0) && is_push(w1) {
                score += 10;
            }
            // IN r28, 0x3D (SPL) = 0xB7CD followed by IN r29, 0x3E (SPH) = 0xB7DE
            if w0 == 0xB7CD && w1 == 0xB7DE {
                score += 25;
            }
            // OUT 0x3F, rN (SREG save) with mask: OUT = 0xB800..0xBFFF, A=0x3F
            // OUT encoding: 1011 1AAd dddd AAAA, A=0x3F → 10111 1 1 ddddd 1111 = Bxxx where A bits = 111111
            if (w0 & 0xF80F) == 0xB80F && ((w0 >> 4) & 0x01 == 1) && ((w0 >> 9) & 0x03 == 3) {
                score += 10;
            }
            j += 2;
        }
    }

    // --- 32-bit BE cross-architecture penalties ---
    // AVR data is 16-bit LE. When the underlying data is from a 32-bit BE ISA
    // (SPARC, PPC, MIPS), distinctive patterns show up in 32-bit BE reads.
    // Check every 4-byte aligned position.
    {
        let mut j = 0;
        while j + 3 < data.len() {
            let be32 = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);

            // SPARC patterns
            if be32 == 0x01000000 { score -= 15; } // SPARC NOP
            if be32 == 0x81C7E008 { score -= 20; } // SPARC RET
            if be32 == 0x81C3E008 { score -= 20; } // SPARC RETL
            if be32 == 0x81E80000 { score -= 15; } // SPARC RESTORE
            if be32 == 0x91D02000 { score -= 12; } // SPARC TA 0
            // SPARC SAVE %sp, -N, %sp (format 10, op3=0x3C, rs1=14, rd=14, i=1)
            if (be32 & 0xFFFFE000) == 0x9DE3A000 { score -= 15; }

            // PPC patterns
            if be32 == 0x4E800020 { score -= 20; } // PPC BLR
            if be32 == 0x60000000 { score -= 15; } // PPC NOP
            if be32 == 0x7C0802A6 { score -= 15; } // PPC MFLR r0
            if be32 == 0x7C0803A6 { score -= 15; } // PPC MTLR r0
            // PPC STW r1 (stack frame setup): 0x9421xxxx
            if (be32 & 0xFFFF0000) == 0x94210000 { score -= 10; }
            // PPC STWU r1 (stack frame with update): common in function prologues
            if (be32 & 0xFC1F0000) == 0x94010000 { score -= 8; }

            // MIPS patterns (BE)
            if be32 == 0x03E00008 { score -= 20; } // MIPS JR $ra
            if be32 == 0x00000000 { score -= 5; }  // MIPS NOP (also zeros)

            // Cell SPU patterns
            if (be32 & 0xFFE00000) == 0x24000000 { score -= 8; } // SPU STQD
            if (be32 & 0xFFE00000) == 0x34000000 { score -= 8; } // SPU LQDI

            j += 4;
        }
    }

    // --- 32-bit LE cross-architecture penalties ---
    // Also check for 32-bit LE ISAs (AArch64, RISC-V, x86, LoongArch)
    {
        let mut j = 0;
        while j + 3 < data.len() {
            let le32 = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);

            // AArch64
            if le32 == 0xD65F03C0 { score -= 20; } // AArch64 RET
            if le32 == 0xD503201F { score -= 15; } // AArch64 NOP
            // AArch64 BL (top6=0x25) - reduced from -5 to -2 because
            // AVR instructions 0x94xx-0x97xx in the upper halfword trigger this falsely
            if (le32 >> 26) == 0x25 { score -= 2; }

            // RISC-V
            if le32 == 0x00008067 { score -= 15; } // RISC-V RET
            if le32 == 0x00000013 { score -= 10; } // RISC-V NOP

            // PPC (LE mode) - PPC64 LE stores instructions in LE byte order
            if le32 == 0x4E800020 { score -= 15; } // PPC BLR (return)
            if le32 == 0x60000000 { score -= 10; } // PPC NOP
            if le32 == 0x7C0802A6 { score -= 12; } // PPC MFLR r0
            if le32 == 0x7C0803A6 { score -= 12; } // PPC MTLR r0
            // PPC64 prologue/epilogue patterns
            if (le32 & 0xFFFF0000) == 0xF8010000 { score -= 10; } // STD r0,N(r1) - save LR
            if (le32 & 0xFFFF0000) == 0xE8010000 { score -= 10; } // LD r0,N(r1) - restore LR
            if (le32 & 0xFFFF0000) == 0xF8210000 { score -= 10; } // STDU r1,-N(r1) - frame setup
            // PPC ADDI/LI common patterns
            if (le32 & 0xFC000000) == 0x38000000 { score -= 3; }  // ADDI (very common)

            // LoongArch (LE 32-bit)
            if le32 == 0x03400000 { score -= 10; } // LoongArch NOP
            if le32 == 0x4C000020 { score -= 12; } // LoongArch JIRL ra (RET)

            // Hexagon (LE 32-bit)
            if (le32 & 0xFFFF0000) == 0x7F000000 { score -= 12; } // Hexagon NOP
            if le32 == 0x961EC01E { score -= 15; }                 // Hexagon DEALLOC_RETURN
            if (le32 & 0xFFFFE000) == 0xA09DC000 { score -= 12; } // Hexagon ALLOCFRAME

            // Thumb-2 32-bit patterns (hw0 in low 16 bits, hw1 in high 16 bits of LE32)
            {
                let hw_low = (le32 & 0xFFFF) as u16;
                let hw_high = (le32 >> 16) as u16;
                // Thumb-2 PUSH.W (E92D xxxx)
                if hw_low == 0xE92D { score -= 10; }
                // Thumb-2 POP.W (E8BD xxxx)
                if hw_low == 0xE8BD { score -= 10; }
                // Thumb-2 BL (F0xx-F7FF Dxxx)
                if (hw_low & 0xF800) == 0xF000 && (hw_high & 0xD000) == 0xD000 {
                    score -= 8;
                }
            }

            j += 4;
        }
    }

    // --- SH (SuperH) cross-architecture penalties ---
    // SH also uses 16-bit LE instructions
    {
        let mut j = 0;
        while j + 1 < data.len() {
            let hw = u16::from_le_bytes([data[j], data[j + 1]]);
            if hw == 0x000B { score -= 15; } // SH RTS
            if hw == 0x0009 { score -= 10; } // SH NOP
            if hw == 0x002B { score -= 12; } // SH RTE
            j += 2;
        }
    }

    // Structural requirement: AVR code of meaningful size should contain
    // some distinctive patterns. With the cross-architecture penalties above,
    // the structural check can be light.
    let num_halfwords = data.len() / 2;
    if num_halfwords > 32 {
        if ret_count == 0 && call_count == 0 && branch_count == 0 {
            // No returns, calls, or branches at all - not code
            score = (score as f64 * 0.20) as i64;
        }
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
