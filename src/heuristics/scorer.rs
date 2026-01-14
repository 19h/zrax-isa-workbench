//! Architecture-specific instruction pattern scoring.
//!
//! Each scoring function analyzes raw bytes for patterns characteristic
//! of a specific ISA, returning a score that represents the likelihood
//! that the data contains code for that architecture.

use crate::architectures::{
    aarch64, arm, avr, hexagon, loongarch, m68k, mips, msp430, ppc, riscv, s390x, sparc, superh,
    x86,
};

/// Score likelihood of x86/x86-64 code.
///
/// Looks for:
/// - Common opcodes (NOP, RET, CALL, JMP, PUSH)
/// - Prefix bytes (REX for 64-bit, VEX/EVEX for extensions)
/// - Prologue patterns
/// - System calls
pub fn score_x86(data: &[u8], bits: u8) -> i64 {
    let mut score: i64 = 0;
    let is_64 = bits == 64;

    let mut i = 0;
    while i < data.len() {
        let b = data[i];

        // Single-byte patterns using architecture constants
        match b {
            b if b == x86::opcodes::NOP => score += 5,
            b if b == x86::opcodes::RET => score += 10,
            b if b == x86::opcodes::INT3 => score += 8,
            b if b == x86::opcodes::PUSH_EBP => score += 10,
            b if b == x86::opcodes::CALL_REL32 => score += 8,
            b if b == x86::opcodes::JMP_REL32 => score += 5,
            b if b == x86::opcodes::JMP_REL8 => score += 3,
            0x8D => score += 3, // LEA
            0xB8..=0xBF => score += 2, // MOV immediate
            0x70..=0x7F => score += 3, // Conditional jumps
            _ => {}
        }

        // REX prefix (64-bit indicator)
        if is_64 && (x86::opcodes::REX_BASE..=x86::opcodes::REX_MAX).contains(&b) {
            score += 8;
        }

        // Legacy prefixes (not great for 64-bit code but common)
        if !is_64 && b == 0x66 {
            score += 2;
        }

        // Two-byte patterns
        if i + 1 < data.len() {
            let next = data[i + 1];

            // SYSCALL (64-bit)
            if [b, next] == x86::opcodes::SYSCALL {
                if is_64 {
                    score += 20;
                } else {
                    score -= 10;
                }
            }
            // INT 0x80 (32-bit syscall)
            else if b == x86::opcodes::INT && next == 0x80 {
                if is_64 {
                    score -= 10;
                } else {
                    score += 20;
                }
            }
            // UD2 (undefined instruction, often used as trap)
            else if [b, next] == x86::opcodes::UD2 {
                score += 5;
            }
            // Multi-byte NOP (0F 1F)
            else if b == x86::opcodes::TWO_BYTE && next == 0x1F {
                score += 8;
            }
            // MOV r/m, r (common)
            else if matches!(b, 0x89 | 0x8B) {
                score += 2;
            }
            // TEST r/m, r
            else if matches!(b, 0x85 | 0x84) {
                score += 2;
            }
            // CMP r/m, r
            else if matches!(b, 0x39 | 0x3B) {
                score += 2;
            }
        }

        // VEX prefix (AVX)
        if b == x86::opcodes::VEX2 && i + 2 < data.len() {
            score += 15;
        }
        if b == x86::opcodes::VEX3 && i + 3 < data.len() {
            score += 15;
        }

        // EVEX prefix (AVX-512)
        if b == x86::opcodes::EVEX && i + 4 < data.len() {
            // Verify EVEX encoding
            if i + 1 < data.len() {
                let p1 = data[i + 1];
                // Check for valid EVEX pattern (bits [3:2] should be 0)
                if (p1 & 0x0C) == 0x00 {
                    score += 25;
                }
            }
        }

        // REX2 prefix (APX - Intel Advanced Performance Extensions)
        if b == x86::opcodes::REX2 && i + 2 < data.len() {
            score += 20;
        }

        // ENDBR64/ENDBR32 (CET)
        if i + 4 <= data.len() && &data[i..i + 4] == &[0xF3, 0x0F, 0x1E, 0xFA] {
            if is_64 {
                score += 20;
            }
        }
        if i + 4 <= data.len() && &data[i..i + 4] == &[0xF3, 0x0F, 0x1E, 0xFB] {
            if !is_64 {
                score += 20;
            }
        }

        // Use architecture helper for prologue detection
        if i + 4 <= data.len() && x86::is_prologue(&data[i..]) {
            score += 15;
        }

        // Penalize patterns that are invalid or unlikely
        if i + 4 <= data.len() {
            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            if word == 0x00000000 || word == 0xFFFFFFFF {
                score -= 5;
            }
        }

        i += 1;
    }

    score.max(0)
}

/// Score likelihood of ARM32 code.
///
/// Looks for:
/// - Condition codes in bits [31:28]
/// - Common instructions (NOP, BX LR, PUSH, POP)
/// - Data processing patterns
pub fn score_arm(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // ARM32 instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Check condition code using architecture helper
        let cond = arm::get_condition(word);

        // AL (always) condition is most common
        if cond == arm::condition::AL {
            score += 3;
        } else if cond <= arm::condition::LE {
            // Valid condition codes
            score += 1;
        } else if cond == arm::condition::NV {
            // Unconditional - less common but valid
            score += 1;
        }

        // NOP (MOV R0, R0)
        if word == arm::patterns::NOP {
            score += 20;
        }

        // NOP.W (ARMv6K+)
        if word == arm::patterns::NOP_HINT {
            score += 20;
        }

        // BX LR (return)
        if word == arm::patterns::BX_LR {
            score += 25;
        }

        // Use architecture helpers for PUSH/POP detection
        if arm::is_push(word) {
            score += 15;
        }

        if arm::is_pop(word) {
            score += 15;
        }

        // BL (branch with link) using architecture helper
        if arm::is_bl(word) {
            score += 8;
        }

        // LDR/STR
        if (word & 0x0E000000) == 0x04000000 && cond <= arm::condition::AL {
            score += 3;
        }

        // Data processing (AND, EOR, SUB, ADD, etc.)
        if (word & 0x0C000000) == 0x00000000 && cond <= arm::condition::AL {
            score += 2;
        }

        // SVC/SWI (system call)
        if (word & 0x0F000000) == 0x0F000000 && cond == arm::condition::AL {
            score += 15;
        }

        // Invalid - all zeros or all ones
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 10;
        }
    }

    score.max(0)
}

/// Score likelihood of AArch64 code.
///
/// Looks for:
/// - Fixed 32-bit instructions
/// - Encoding groups in bits [28:25]
/// - Common patterns (NOP, RET, SVC)
pub fn score_aarch64(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // AArch64 instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // NOP using architecture constant
        if word == aarch64::system::NOP {
            score += 25;
        }

        // RET using architecture constant
        if word == aarch64::ret::RET {
            score += 30;
        }

        // RETAA (PAC return)
        if word == aarch64::ret::RETAA {
            score += 25;
        }

        // RETAB
        if word == aarch64::ret::RETAB {
            score += 25;
        }

        // BL (branch with link) using architecture helper
        if aarch64::is_bl(word) {
            score += 10;
        }

        // B (unconditional branch) using architecture helper
        if aarch64::is_branch(word) && !aarch64::is_bl(word) {
            score += 8;
        }

        // SVC (system call)
        if (word & 0xFFE0001F) == 0xD4000001 {
            score += 20;
        }

        // BRK (breakpoint)
        if (word & 0xFFE0001F) == 0xD4200000 {
            score += 15;
        }

        // BTI (branch target identification) using architecture helper
        if aarch64::is_bti(word) {
            score += 20;
        }

        // PACIASP (pointer authentication)
        if word == aarch64::system::PACIASP {
            score += 20;
        }

        // AUTIASP
        if word == aarch64::system::AUTIASP {
            score += 20;
        }

        // STP (store pair - common in prologue) using architecture helper
        if aarch64::is_stp(word) {
            score += 10;
        }

        // LDP (load pair - common in epilogue) using architecture helper
        if aarch64::is_ldp(word) {
            score += 10;
        }

        // MOV (wide immediate)
        if (word >> 23) & 0x1FF == 0x1A5 {
            score += 5;
        }

        // ADD/SUB immediate
        if (word >> 24) & 0x1F == 0x11 {
            score += 3;
        }

        // Check encoding groups using architecture helper
        let group = aarch64::get_encoding_group(word);
        match group {
            aarch64::EncodingGroup::DataProcessingImmediate => score += 2,
            aarch64::EncodingGroup::BranchExceptionSystem => score += 2,
            aarch64::EncodingGroup::LoadStore => score += 2,
            aarch64::EncodingGroup::DataProcessingRegister => score += 2,
            _ => {}
        }

        // Invalid patterns
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 10;
        }
    }

    score.max(0)
}

/// Score likelihood of RISC-V code.
///
/// Looks for:
/// - Instruction length encoding (bits [1:0])
/// - Standard opcodes
/// - Compressed instructions
pub fn score_riscv(data: &[u8], bits: u8) -> i64 {
    let mut score: i64 = 0;
    let is_64 = bits == 64;
    let mut i = 0;

    while i < data.len() {
        // Use architecture helper for instruction length
        let instr_len = riscv::instruction_length(&data[i..]);
        
        if instr_len == 2 {
            // Compressed instruction (16-bit)
            if i + 2 > data.len() {
                break;
            }

            let half = u16::from_le_bytes([data[i], data[i + 1]]);

            // C.NOP using architecture constant
            if half == riscv::patterns::C_NOP {
                score += 20;
            }

            // C.RET using architecture constant
            if half == riscv::patterns::C_RET {
                score += 25;
            }

            // C.EBREAK using architecture constant
            if half == riscv::patterns::C_EBREAK {
                score += 15;
            }

            // C.ADDI16SP
            if (half & 0xEF83) == 0x6101 {
                score += 10;
            }

            // Valid compressed quadrants
            let quadrant = half & 0x03;
            if quadrant <= 2 {
                score += 2;
            }

            i += 2;
        } else {
            // 32-bit instruction
            if i + 4 > data.len() {
                break;
            }

            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            let opcode = riscv::get_opcode(word);

            // NOP using architecture constant
            if word == riscv::patterns::NOP {
                score += 25;
            }

            // RET using architecture constant
            if word == riscv::patterns::RET {
                score += 30;
            }

            // ECALL using architecture constant
            if word == riscv::patterns::ECALL {
                score += 20;
            }

            // EBREAK using architecture constant
            if word == riscv::patterns::EBREAK {
                score += 15;
            }

            // Check for valid standard opcodes using architecture constants
            match opcode {
                op if op == riscv::opcode::LOAD => score += 5,
                op if op == riscv::opcode::OP_IMM => score += 5,
                op if op == riscv::opcode::AUIPC => score += 5,
                op if op == riscv::opcode::STORE => score += 5,
                op if op == riscv::opcode::OP => score += 5,
                op if op == riscv::opcode::LUI => score += 5,
                op if op == riscv::opcode::BRANCH => score += 5,
                op if op == riscv::opcode::JALR => score += 5,
                op if op == riscv::opcode::JAL => score += 5,
                op if op == riscv::opcode::SYSTEM => score += 5,
                // 64-bit specific
                op if op == riscv::opcode::OP_IMM_32 && is_64 => score += 5,
                op if op == riscv::opcode::OP_32 && is_64 => score += 5,
                // Extensions
                op if op == riscv::opcode::LOAD_FP => score += 3,
                op if op == riscv::opcode::STORE_FP => score += 3,
                op if op == riscv::opcode::AMO => score += 3,
                op if op == riscv::opcode::OP_FP => score += 3,
                op if op == riscv::opcode::OP_V => score += 3,
                _ => {}
            }

            // Check for M extension using architecture helper
            if riscv::uses_m_extension(word) {
                score += 5;
            }

            i += 4;
        }
    }

    score.max(0)
}

/// Score likelihood of MIPS code.
///
/// Returns (big_endian_score, little_endian_score)
pub fn score_mips(data: &[u8]) -> (i64, i64) {
    let mut score_be: i64 = 0;
    let mut score_le: i64 = 0;

    // MIPS instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        // Big-endian
        let word_be = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        score_be += score_mips_word(word_be);

        // Little-endian
        let word_le = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        score_le += score_mips_word(word_le);
    }

    (score_be.max(0), score_le.max(0))
}

fn score_mips_word(word: u32) -> i64 {
    let mut score: i64 = 0;
    let opcode = mips::get_opcode(word);

    // NOP (sll $0, $0, 0) using architecture constant
    if word == mips::patterns::NOP {
        score += 15;
    }

    // JR $ra (return) using architecture helper
    if mips::is_ret(word) {
        score += 30;
    }

    // SYSCALL using architecture helper
    if mips::is_syscall(word) {
        score += 20;
    }

    // BREAK (check for SPECIAL opcode with BREAK funct)
    if opcode == mips::opcode::SPECIAL && mips::get_funct(word) == mips::funct::BREAK {
        score += 15;
    }

    // Check common opcodes using architecture constants
    match opcode {
        op if op == mips::opcode::SPECIAL => score += 3,  // R-type
        op if op == mips::opcode::REGIMM => score += 3,   // REGIMM
        op if op == mips::opcode::J => score += 5,        // J
        op if op == mips::opcode::JAL => score += 5,      // JAL
        op if op == mips::opcode::BEQ => score += 4,      // BEQ
        op if op == mips::opcode::BNE => score += 4,      // BNE
        op if op == mips::opcode::BLEZ => score += 3,     // BLEZ
        op if op == mips::opcode::BGTZ => score += 3,     // BGTZ
        op if op == mips::opcode::ADDI => score += 3,     // ADDI
        op if op == mips::opcode::ADDIU => score += 3,    // ADDIU
        op if op == mips::opcode::SLTI => score += 3,     // SLTI
        op if op == mips::opcode::SLTIU => score += 3,    // SLTIU
        op if op == mips::opcode::ANDI => score += 3,     // ANDI
        op if op == mips::opcode::ORI => score += 3,      // ORI
        op if op == mips::opcode::XORI => score += 3,     // XORI
        op if op == mips::opcode::LUI => score += 5,      // LUI
        op if op == mips::opcode::LB => score += 4,       // LB
        op if op == mips::opcode::LH => score += 4,       // LH
        op if op == mips::opcode::LW => score += 5,       // LW
        op if op == mips::opcode::LBU => score += 4,      // LBU
        op if op == mips::opcode::LHU => score += 4,      // LHU
        op if op == mips::opcode::SB => score += 4,       // SB
        op if op == mips::opcode::SH => score += 4,       // SH
        op if op == mips::opcode::SW => score += 5,       // SW
        _ => {}
    }

    // Invalid
    if word == 0xFFFFFFFF {
        score -= 10;
    }

    score
}

/// Score likelihood of PowerPC code.
pub fn score_ppc(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // PowerPC is big-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = ppc::get_opcode(word);

        // NOP (ori 0,0,0) using architecture constant
        if ppc::is_nop(word) {
            score += 25;
        }

        // BLR (return) using architecture helper
        if ppc::is_blr(word) {
            score += 30;
        }

        // SC (system call) using architecture constant
        if word == ppc::patterns::SC {
            score += 20;
        }

        // TRAP using architecture constant
        if word == ppc::patterns::TRAP {
            score += 15;
        }

        // MFLR r0 (save link register) using architecture constant
        if word == ppc::patterns::MFLR_R0 {
            score += 25;
        }

        // MTLR r0 (restore link register) using architecture constant
        if word == ppc::patterns::MTLR_R0 {
            score += 20;
        }

        // Check common opcodes using architecture constants
        match opcode {
            op if op == ppc::opcode::ADDI || op == ppc::opcode::ADDIS => score += 5,
            op if op == ppc::opcode::BC => score += 5,      // BCx
            op if op == ppc::opcode::B => score += 5,       // Bx
            op if op == ppc::opcode::XL_FORM => score += 3, // CR ops
            op if op == ppc::opcode::X_FORM => score += 3,  // Extended ops
            op if op == ppc::opcode::LWZ => score += 4,     // Load/Store integer
            op if op == ppc::opcode::LWZU => score += 4,
            op if op == ppc::opcode::LBZ => score += 4,
            op if op == ppc::opcode::LBZU => score += 4,
            op if op == ppc::opcode::STW => score += 4,
            op if op == ppc::opcode::STWU => score += 4,
            op if op == ppc::opcode::STB => score += 4,
            op if op == ppc::opcode::STBU => score += 4,
            op if op == ppc::opcode::LHZ => score += 4,
            op if op == ppc::opcode::LHZU => score += 4,
            op if op == ppc::opcode::LHA => score += 4,
            op if op == ppc::opcode::LHAU => score += 4,
            op if op == ppc::opcode::STH => score += 4,
            op if op == ppc::opcode::STHU => score += 4,
            op if op == ppc::opcode::LMW => score += 4,
            op if op == ppc::opcode::STMW => score += 4,
            op if op == ppc::opcode::LFS => score += 3,     // Load/Store FP
            op if op == ppc::opcode::LFSU => score += 3,
            op if op == ppc::opcode::LFD => score += 3,
            op if op == ppc::opcode::LFDU => score += 3,
            op if op == ppc::opcode::STFS => score += 3,
            op if op == ppc::opcode::STFSU => score += 3,
            op if op == ppc::opcode::STFD => score += 3,
            op if op == ppc::opcode::STFDU => score += 3,
            _ => {}
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of SPARC code.
pub fn score_sparc(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // SPARC is big-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let fmt = sparc::get_format(word);

        // NOP using architecture helper
        if sparc::is_nop(word) {
            score += 25;
        }

        // RETL/RET using architecture helper
        if sparc::is_return(word) {
            score += 30;
        }

        // CALL using architecture helper
        if sparc::is_call(word) {
            score += 10;
        }

        // Arithmetic (format 10) using architecture constant
        if fmt == sparc::format::ARITHMETIC {
            score += 3;
        }

        // Load/Store (format 11) using architecture constant
        if fmt == sparc::format::LOAD_STORE {
            score += 3;
        }

        // Branch/SETHI (format 00) using architecture constants
        if fmt == sparc::format::BRANCH_SETHI {
            let op2 = sparc::get_op2(word);
            if op2 == sparc::op2::SETHI {
                // SETHI
                score += 5;
            } else if op2 == sparc::op2::BICC || op2 == sparc::op2::FBFCC {
                // Branches
                score += 5;
            }
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of s390x code.
pub fn score_s390x(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut i = 0;

    while i < data.len() {
        let first = data[i];

        // Determine instruction length using architecture helper
        let len = s390x::length::from_first_byte(first);

        if i + len > data.len() {
            break;
        }

        // 2-byte instructions
        if len == 2 && i + 2 <= data.len() {
            let half = u16::from_be_bytes([data[i], data[i + 1]]);

            // NOP (BCR 0,0) using architecture constant
            if half == s390x::patterns::NOP_2B {
                score += 20;
            }

            // BR r14 (return) using architecture helper
            if s390x::is_return(half) {
                score += 30;
            }

            // SVC using architecture helper
            if s390x::is_svc(half) {
                score += 15;
            }

            // Common RR instructions using architecture constants
            let op = s390x::get_opcode_2b(half);
            if s390x::VALID_2B_OPCODES.contains(&op) {
                score += 3;
            }
        }

        // 4-byte instructions
        if len == 4 && i + 4 <= data.len() {
            let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

            // NOP (BC 0,0) using architecture constant
            if word == s390x::patterns::NOP_4B {
                score += 20;
            }

            let op = s390x::get_opcode_4b(word);
            match op {
                op if op == s390x::opcode_rx::LA => score += 5,
                op if op == s390x::opcode_rx::BC => score += 5,
                op if op == s390x::opcode_rx::ST => score += 5,
                op if op == s390x::opcode_rx::L => score += 5,
                _ => {}
            }
        }

        i += len;
    }

    score.max(0)
}

/// Score likelihood of m68k code.
pub fn score_m68k(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // m68k is big-endian
    for i in (0..data.len().saturating_sub(1)).step_by(2) {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);

        // NOP using architecture helper
        if m68k::is_nop(word) {
            score += 25;
        }

        // RTS (return) using architecture helper
        if m68k::is_rts(word) {
            score += 30;
        }

        // RTE (return from exception) using architecture constant
        if word == m68k::patterns::RTE {
            score += 15;
        }

        // TRAP using architecture helper
        if m68k::is_trap(word) {
            score += 15;
        }

        // JSR using architecture helper
        if m68k::is_jsr(word) {
            score += 10;
        }

        // JMP using architecture helper
        if m68k::is_jmp(word) {
            score += 8;
        }

        // MOVE.L (most common) using architecture constant
        if m68k::get_opcode_group(word) == m68k::opcode_group::MOVE_LONG {
            score += 3;
        }

        // MOVEQ using architecture helper
        if m68k::is_moveq(word) {
            score += 5;
        }

        // LEA using architecture helper
        if m68k::is_lea(word) {
            score += 5;
        }

        // Invalid
        if word == 0x0000 || word == 0xFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of SuperH code.
pub fn score_superh(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // SuperH is 16-bit aligned
    for i in (0..data.len().saturating_sub(1)).step_by(2) {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);

        // NOP using architecture helper
        if superh::is_nop(word) {
            score += 25;
        }

        // RTS (return) using architecture helper
        if superh::is_rts(word) {
            score += 30;
        }

        // TRAPA using architecture helper
        if superh::is_trapa(word) {
            score += 15;
        }

        // BRA using architecture helper
        if superh::is_bra(word) {
            score += 8;
        }

        // BSR using architecture helper
        if superh::is_bsr(word) {
            score += 8;
        }

        // MOV.L @(disp,PC), Rn (common pattern) using architecture constant
        if superh::get_format(word) == superh::format::FMT_D {
            score += 5;
        }

        // MOV Rm, Rn - check for MOV instruction
        if superh::is_mov(word) && (word & 0xF00F) == 0x6003 {
            score += 3;
        }

        // Invalid
        if word == 0x0000 || word == 0xFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of Alpha code.
pub fn score_alpha(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // Alpha is little-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        // NOP (bis $31, $31, $31 or unop)
        if word == 0x47FF041F || word == 0x2FFE0000 {
            score += 25;
        }

        // RET (ret $31, ($26), 1)
        if word == 0x6BFA8001 {
            score += 30;
        }

        // CALL_PAL
        if opcode == 0x00 {
            score += 15;
        }

        // Common opcodes
        match opcode {
            0x08..=0x0F => score += 3, // Load/Store
            0x10 => score += 5,        // Integer arithmetic
            0x11 => score += 3,        // Integer logical
            0x12 => score += 3,        // Integer shift
            0x13 => score += 3,        // Integer multiply
            0x1A => score += 5,        // Jump
            0x1C => score += 3,        // Floating
            0x30..=0x3F => score += 4, // Branch
            _ => {}
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of LoongArch code.
pub fn score_loongarch(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // LoongArch is little-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // NOP using architecture helper
        if loongarch::is_nop(word) {
            score += 25;
        }

        // RET using architecture helper
        if loongarch::is_ret(word) {
            score += 30;
        }

        // SYSCALL using architecture helper
        if loongarch::is_syscall(word) {
            score += 20;
        }

        // BREAK using architecture helper
        if loongarch::is_break(word) {
            score += 15;
        }

        // Check for valid instruction patterns using architecture helpers
        if loongarch::is_branch(word) {
            score += 3;
        }

        if loongarch::is_load(word) || loongarch::is_store(word) {
            score += 3;
        }

        // BL (call) using architecture helper
        if loongarch::is_bl(word) {
            score += 5;
        }

        // B (unconditional branch) using architecture helper
        if loongarch::is_b(word) {
            score += 5;
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of Hexagon code.
pub fn score_hexagon(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // Hexagon is little-endian, 4-byte aligned (VLIW packets)
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // NOP using architecture helper
        if hexagon::is_nop(word) {
            score += 25;
        }

        // End of packet marker using architecture helper
        if hexagon::is_end_of_packet(word) {
            score += 5;
        }

        // Instruction class using architecture helper
        let iclass = hexagon::get_iclass(word);
        
        // ALU32 using architecture helper
        if hexagon::is_alu32(word) {
            score += 2;
        }
        
        // XTYPE/Memory using architecture helper
        if hexagon::is_xtype(word) {
            score += 2;
        }
        
        // ALU64/M using architecture helper
        if hexagon::is_alu64(word) {
            score += 2;
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of AVR code.
pub fn score_avr(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut i = 0;

    // AVR is little-endian, mostly 16-bit instructions (some 32-bit)
    while i + 2 <= data.len() {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);

        // NOP using architecture helper
        if avr::is_nop(word) {
            score += 15;
        }

        // RET (return from subroutine) using architecture helper
        if avr::is_ret(word) {
            score += 30;
        }

        // RETI (return from interrupt) using architecture helper
        if avr::is_reti(word) {
            score += 25;
        }

        // SLEEP using architecture constant
        if word == avr::patterns::SLEEP {
            score += 15;
        }

        // BREAK using architecture constant
        if word == avr::patterns::BREAK {
            score += 15;
        }

        // CLI (disable interrupts) using architecture constant
        if word == avr::patterns::CLI {
            score += 10;
        }

        // SEI (enable interrupts) using architecture constant
        if word == avr::patterns::SEI {
            score += 10;
        }

        // RJMP (relative jump) using architecture helper
        if avr::is_rjmp(word) {
            score += 8;
        }

        // RCALL (relative call) using architecture helper
        if avr::is_rcall(word) {
            score += 8;
        }

        // LDI (load immediate) using architecture helper
        if avr::is_ldi(word) {
            score += 5;
        }

        // PUSH using architecture helper
        if avr::is_push(word) {
            score += 8;
        }

        // POP using architecture helper
        if avr::is_pop(word) {
            score += 8;
        }

        // IN (I/O read) using architecture helper
        if avr::is_in(word) {
            score += 3;
        }

        // OUT (I/O write) using architecture helper
        if avr::is_out(word) {
            score += 3;
        }

        // MOV (register copy) using architecture helper
        if avr::is_mov(word) {
            score += 3;
        }

        // Check if 32-bit instruction using architecture helper
        if avr::is_two_word(word) {
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

/// Score likelihood of MSP430 code.
pub fn score_msp430(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // MSP430 is little-endian, 16-bit aligned
    for i in (0..data.len().saturating_sub(1)).step_by(2) {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);
        let opcode = msp430::get_opcode(word);

        // NOP using architecture helper
        if msp430::is_nop(word) {
            score += 25;
        }

        // RET using architecture helper
        if msp430::is_ret(word) {
            score += 30;
        }

        // RETI using architecture helper
        if msp430::is_reti(word) {
            score += 25;
        }

        // Jump instructions using architecture helper
        if msp430::is_jump_format(word) {
            score += 8;
        }

        // JMP (unconditional) using architecture helper
        if msp430::is_jmp(word) {
            score += 10;
        }

        // Single-operand format using architecture helper
        if msp430::is_single_op_format(word) {
            let sub_op = msp430::get_single_op(word);
            match sub_op {
                op if op == msp430::single_op::PUSH => score += 8,
                op if op == msp430::single_op::CALL => score += 8,
                op if op == msp430::single_op::RETI => score += 5,
                _ => score += 2,
            }
        }

        // Two-operand format using architecture helpers and constants
        if msp430::is_two_op_format(word) {
            match opcode {
                op if op == msp430::two_op::MOV => score += 5,
                op if op == msp430::two_op::ADD => score += 4,
                op if op == msp430::two_op::SUB => score += 4,
                op if op == msp430::two_op::CMP => score += 4,
                op if op == msp430::two_op::AND => score += 3,
                _ => score += 2,
            }
        }

        // Invalid
        if word == 0x0000 || word == 0xFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of PA-RISC (HP Precision Architecture) code.
///
/// PA-RISC uses big-endian 32-bit instructions with specific patterns:
/// - NOP: 08000240 (OR 0,0,0)
/// - RET: E840C002 (BV,N 0(%rp))
pub fn score_parisc(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // PA-RISC is big-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        // NOP (OR 0,0,0)
        if word == 0x08000240 {
            score += 25;
        }

        // BV,N 0(%rp) - common return
        if word == 0xE840C002 {
            score += 30;
        }

        // BV 0(%rp) - return without nullify
        if word == 0xE840C000 {
            score += 25;
        }

        // BE,L - branch external with link
        if (word & 0xFC00E000) == 0xE0000000 {
            score += 10;
        }

        // BL - branch and link
        if opcode == 0x3A {
            score += 10;
        }

        // LDW/STW - load/store word
        if opcode == 0x12 || opcode == 0x1A {
            score += 3;
        }

        // LDWM/STWM - load/store with modify
        if opcode == 0x13 || opcode == 0x1B {
            score += 4;
        }

        // ADD/SUB/AND/OR (opcode 0x02)
        if opcode == 0x02 {
            score += 3;
        }

        // COMIB/COMB - compare immediate and branch
        if opcode == 0x21 || opcode == 0x23 {
            score += 5;
        }

        // ADDI/SUBI
        if opcode == 0x2D || opcode == 0x25 {
            score += 3;
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of ARC (Argonaut RISC Core) code.
///
/// ARC uses little-endian instructions, with 16 or 32-bit length.
/// Common patterns from ARCompact/ARCv2:
/// - NOP: 78E0 (16-bit) or 264A7000 (32-bit)
/// - J.D [blink]: 7EE0 (16-bit return)
pub fn score_arc(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut i = 0;

    while i < data.len() {
        if i + 2 > data.len() {
            break;
        }

        let half = u16::from_le_bytes([data[i], data[i + 1]]);

        // Check if 16-bit or 32-bit instruction
        // In ARCompact, major opcode in bits [15:11]
        let major = (half >> 11) & 0x1F;

        // 16-bit compact instructions have specific patterns
        if major >= 0x0C && major <= 0x1F {
            // 16-bit instruction

            // NOP_S (16-bit NOP)
            if half == 0x78E0 {
                score += 20;
            }

            // J_S [blink] - return
            if half == 0x7EE0 {
                score += 25;
            }

            // J_S.D [blink] - delayed return
            if half == 0x7FE0 {
                score += 25;
            }

            // POP_S blink
            if half == 0xC0D1 {
                score += 15;
            }

            // PUSH_S blink
            if half == 0xC0F1 {
                score += 15;
            }

            // MOV_S
            if (half & 0xF8E0) == 0x7000 {
                score += 3;
            }

            // ADD_S/SUB_S
            if (half & 0xF800) == 0x6000 {
                score += 3;
            }

            i += 2;
        } else {
            // 32-bit instruction
            if i + 4 > data.len() {
                break;
            }

            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

            // 32-bit NOP
            if word == 0x264A7000 || word == 0x7000264A {
                score += 20;
            }

            // Check major opcode for 32-bit
            let major32 = (word >> 27) & 0x1F;

            match major32 {
                0x04 => score += 3, // General ops
                0x05 => score += 3, // General ops with extension
                0x01 => score += 4, // Branch
                0x00 => score += 4, // Branch/Link
                0x02 => score += 3, // Load
                0x03 => score += 3, // Store
                _ => {}
            }

            // Invalid
            if word == 0x00000000 || word == 0xFFFFFFFF {
                score -= 5;
            }

            i += 4;
        }
    }

    score.max(0)
}

/// Score likelihood of Xtensa code.
///
/// Xtensa uses little-endian instructions with variable length:
/// - 16-bit narrow instructions (when Density option enabled)
/// - 24-bit standard instructions
/// Common patterns:
/// - NOP: 20F0 (16-bit) or 0020F0 (24-bit NOP.N interpreted)
/// - RET/RET.N: 0D/F00D
pub fn score_xtensa(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut i = 0;

    while i < data.len() {
        if i + 2 > data.len() {
            break;
        }

        let b0 = data[i];
        let b1 = data[i + 1];

        // Check for 16-bit (narrow) instruction
        // Narrow instructions have bits [3:0] of first byte indicating narrow format
        let is_narrow = (b0 & 0x08) != 0;

        if is_narrow {
            // 16-bit narrow instruction
            let half = u16::from_le_bytes([b0, b1]);

            // NOP.N (20F0 or F020 depending on encoding)
            if half == 0x20F0 || half == 0xF020 {
                score += 20;
            }

            // RET.N
            if half == 0xF00D || half == 0x0DF0 {
                score += 25;
            }

            // RETW.N (windowed return)
            if half == 0xF01D || half == 0x1DF0 {
                score += 20;
            }

            // MOV.N
            if (half & 0xF00F) == 0x000D {
                score += 3;
            }

            // MOVI.N
            if (half & 0xF00F) == 0x000C {
                score += 3;
            }

            // L32I.N / S32I.N
            if (half & 0xF000) == 0x8000 || (half & 0xF000) == 0x9000 {
                score += 3;
            }

            i += 2;
        } else {
            // 24-bit instruction
            if i + 3 > data.len() {
                break;
            }

            let b2 = data[i + 2];
            let word = (b2 as u32) << 16 | (b1 as u32) << 8 | (b0 as u32);

            // NOP (standard 3-byte)
            if word == 0x0020F0 {
                score += 15;
            }

            // RET
            if word == 0x000080 {
                score += 25;
            }

            // RETW (windowed return)
            if word == 0x000090 {
                score += 20;
            }

            // CALL0/CALL4/CALL8/CALL12
            if (b0 & 0x0F) == 0x05 {
                score += 10;
            }

            // ENTRY (function prologue)
            if (b0 & 0x0F) == 0x06 && (b1 & 0x03) == 0x03 {
                score += 15;
            }

            // L32I/S32I
            if (b0 & 0x0F) == 0x02 {
                score += 3;
            }

            // ADDI
            if (b0 & 0x0F) == 0x0C && (b1 & 0xF0) == 0x20 {
                score += 3;
            }

            // Invalid
            if word == 0x000000 || word == 0xFFFFFF {
                score -= 5;
            }

            i += 3;
        }
    }

    score.max(0)
}

/// Score likelihood of MicroBlaze code.
///
/// MicroBlaze uses big-endian 32-bit instructions (configurable but usually BE).
/// Common patterns:
/// - NOP: 80000000 (OR r0,r0,r0)
/// - RTSD: B60F0008 (return from subroutine, delay slot)
pub fn score_microblaze(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // MicroBlaze is typically big-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        // NOP (OR r0,r0,r0)
        if word == 0x80000000 {
            score += 25;
        }

        // RTSD r15,8 (common return)
        if word == 0xB60F0008 {
            score += 30;
        }

        // RTSD with other offsets
        if (word & 0xFFFF0000) == 0xB60F0000 {
            score += 20;
        }

        // RTID (return from interrupt)
        if (word & 0xFFFF0000) == 0xB6200000 {
            score += 15;
        }

        // BRI/BRAI (branch immediate)
        if opcode == 0x2E || opcode == 0x2F {
            score += 8;
        }

        // BRLID/BRALD (branch and link with delay)
        if opcode == 0x2E && (word & 0x00100000) != 0 {
            score += 10;
        }

        // ADD/RSUB/ADDC
        if opcode == 0x00 || opcode == 0x01 || opcode == 0x02 {
            score += 3;
        }

        // ADDI/RSUBI
        if opcode == 0x08 || opcode == 0x09 {
            score += 3;
        }

        // AND/OR/XOR
        if opcode == 0x21 || opcode == 0x20 || opcode == 0x22 {
            score += 3;
        }

        // LW/SW (load/store word)
        if opcode == 0x32 || opcode == 0x36 {
            score += 4;
        }

        // LWI/SWI (load/store word immediate)
        if opcode == 0x30 || opcode == 0x34 {
            score += 4;
        }

        // IMM (immediate prefix)
        if opcode == 0x2C {
            score += 5;
        }

        // Invalid
        if word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of Nios II code.
///
/// Nios II uses little-endian 32-bit instructions.
/// Common patterns:
/// - NOP: 0001883A (add r0,r0,r0 or similar)
/// - RET: F800283A (ret)
pub fn score_nios2(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // Nios II is little-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = word & 0x3F;

        // NOP (usually encoded as add r0,r0,r0 or mov r0,r0)
        if word == 0x0001883A {
            score += 25;
        }

        // RET
        if word == 0xF800283A {
            score += 30;
        }

        // ERET (exception return)
        if word == 0xE800003A {
            score += 20;
        }

        // BREAK
        if (word & 0x07FFFFFF) == 0x003A003A {
            score += 10;
        }

        // R-type instructions (opcode 0x3A)
        if opcode == 0x3A {
            let opx = (word >> 6) & 0x3F;
            match opx {
                0x31 => score += 8,  // ADD
                0x39 => score += 8,  // SUB
                0x0E => score += 6,  // AND
                0x16 => score += 6,  // OR
                0x1E => score += 6,  // XOR
                0x05 => score += 10, // RET/JMP
                0x1D => score += 10, // CALL
                _ => score += 2,
            }
        }

        // I-type instructions
        match opcode {
            0x04 => score += 4, // ADDI
            0x0C => score += 4, // ANDI
            0x14 => score += 4, // ORI
            0x17 => score += 5, // LDW
            0x15 => score += 5, // STW
            0x06 => score += 5, // BR
            0x26 => score += 5, // BEQ
            0x1E => score += 5, // BNE
            0x00 => score += 8, // CALL
            _ => {}
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

/// Score likelihood of OpenRISC code.
///
/// OpenRISC uses big-endian 32-bit instructions.
/// Common patterns:
/// - NOP: 15000000 (l.nop 0)
/// - RET: 44004800 (l.jr r9; l.nop in delay slot)
pub fn score_openrisc(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // OpenRISC is big-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        // l.nop
        if (word & 0xFFFF0000) == 0x15000000 {
            score += 20;
        }

        // l.jr r9 (return via link register)
        if word == 0x44004800 {
            score += 30;
        }

        // l.jr with any register
        if (word & 0xFFFF07FF) == 0x44000000 {
            score += 15;
        }

        // l.jalr (jump and link register)
        if (word & 0xFFFF07FF) == 0x48000000 {
            score += 12;
        }

        // l.jal (jump and link immediate)
        if opcode == 0x01 {
            score += 10;
        }

        // l.j (jump immediate)
        if opcode == 0x00 {
            score += 8;
        }

        // l.bf/l.bnf (branch if flag)
        if opcode == 0x04 || opcode == 0x03 {
            score += 5;
        }

        // l.add/l.sub/l.and/l.or/l.xor (opcode 0x38)
        if opcode == 0x38 {
            score += 3;
        }

        // l.addi/l.andi/l.ori/l.xori
        if opcode == 0x27 || opcode == 0x29 || opcode == 0x2A || opcode == 0x2B {
            score += 3;
        }

        // l.lwz/l.lbs/l.lbz/l.lhs/l.lhz (loads)
        if opcode == 0x21 || opcode == 0x24 || opcode == 0x23 || opcode == 0x26 || opcode == 0x25 {
            score += 4;
        }

        // l.sw/l.sb/l.sh (stores)
        if opcode == 0x35 || opcode == 0x36 || opcode == 0x37 {
            score += 4;
        }

        // l.movhi (load upper immediate)
        if opcode == 0x06 {
            score += 5;
        }

        // l.sys (system call)
        if (word & 0xFFFF0000) == 0x20000000 {
            score += 15;
        }

        // l.trap (trap)
        if (word & 0xFFFF0000) == 0x21000000 {
            score += 10;
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_scoring() {
        let code = [0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        assert!(score_x86(&code, 64) > 0);
    }

    #[test]
    fn test_aarch64_scoring() {
        let code = [
            0x1F, 0x20, 0x03, 0xD5, // NOP
            0xC0, 0x03, 0x5F, 0xD6, // RET
        ];
        assert!(score_aarch64(&code) > 0);
    }

    #[test]
    fn test_riscv_scoring() {
        let code = [
            0x13, 0x00, 0x00, 0x00, // NOP
            0x67, 0x80, 0x00, 0x00, // RET
        ];
        assert!(score_riscv(&code, 64) > 0);
    }

    #[test]
    fn test_mips_scoring() {
        // Big-endian NOP + JR $ra
        let code_be = [
            0x00, 0x00, 0x00, 0x00, // NOP
            0x03, 0xE0, 0x00, 0x08, // JR $ra
        ];
        let (be_score, _) = score_mips(&code_be);
        assert!(be_score > 0);
    }

    #[test]
    fn test_avr_scoring() {
        let code = [
            0x00, 0x00, // NOP
            0x08, 0x95, // RET
        ];
        assert!(score_avr(&code) > 0);
    }

    #[test]
    fn test_msp430_scoring() {
        let code = [
            0x03, 0x43, // NOP (MOV R3, R3)
            0x30, 0x41, // RET (MOV @SP+, PC)
        ];
        assert!(score_msp430(&code) > 0);
    }

    #[test]
    fn test_sparc_scoring() {
        // Big-endian NOP + RETL
        let code = [
            0x01, 0x00, 0x00, 0x00, // NOP
            0x81, 0xC3, 0xE0, 0x08, // RETL
        ];
        assert!(score_sparc(&code) > 0);
    }

    #[test]
    fn test_s390x_scoring() {
        // Big-endian NOP + BR R14
        let code = [
            0x07, 0x00, // NOP (BCR 0,0)
            0x07, 0xFE, // BR R14
        ];
        assert!(score_s390x(&code) > 0);
    }

    #[test]
    fn test_m68k_scoring() {
        // Big-endian NOP + RTS
        let code = [
            0x4E, 0x71, // NOP
            0x4E, 0x75, // RTS
        ];
        assert!(score_m68k(&code) > 0);
    }

    #[test]
    fn test_superh_scoring() {
        // Little-endian NOP + RTS
        let code = [
            0x09, 0x00, // NOP
            0x0B, 0x00, // RTS
        ];
        assert!(score_superh(&code) > 0);
    }

    #[test]
    fn test_loongarch_scoring() {
        // Little-endian NOP + RET
        let code = [
            0x00, 0x00, 0x40, 0x03, // NOP
            0x20, 0x00, 0x00, 0x4C, // RET
        ];
        assert!(score_loongarch(&code) > 0);
    }

    #[test]
    fn test_parisc_scoring() {
        // Big-endian NOP + RET
        let code = [
            0x08, 0x00, 0x02, 0x40, // NOP (OR 0,0,0)
            0xE8, 0x40, 0xC0, 0x02, // BV,N 0(%rp)
        ];
        assert!(score_parisc(&code) > 0);
    }

    #[test]
    fn test_arc_scoring() {
        // Little-endian 16-bit NOP + RET
        let code = [
            0xE0, 0x78, // NOP_S
            0xE0, 0x7E, // J_S [blink]
        ];
        assert!(score_arc(&code) > 0);
    }

    #[test]
    fn test_xtensa_scoring() {
        // 24-bit instructions (bit 3 clear means 24-bit format)
        // NOP (0x0020F0) and RET (0x000080) in little-endian
        let code = [
            0xF0, 0x20, 0x00, // NOP (24-bit: 0x0020F0)
            0x80, 0x00, 0x00, // RET (24-bit: 0x000080)
        ];
        assert!(score_xtensa(&code) > 0);
    }

    #[test]
    fn test_microblaze_scoring() {
        // Big-endian NOP + RTSD
        let code = [
            0x80, 0x00, 0x00, 0x00, // NOP
            0xB6, 0x0F, 0x00, 0x08, // RTSD r15,8
        ];
        assert!(score_microblaze(&code) > 0);
    }

    #[test]
    fn test_nios2_scoring() {
        // Little-endian NOP + RET
        let code = [
            0x3A, 0x88, 0x01, 0x00, // NOP (add r0,r0,r0)
            0x3A, 0x28, 0x00, 0xF8, // RET
        ];
        assert!(score_nios2(&code) > 0);
    }

    #[test]
    fn test_openrisc_scoring() {
        // Big-endian NOP + l.jr r9
        let code = [
            0x15, 0x00, 0x00, 0x00, // l.nop
            0x44, 0x00, 0x48, 0x00, // l.jr r9
        ];
        assert!(score_openrisc(&code) > 0);
    }
}
