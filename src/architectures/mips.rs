//! MIPS architecture analysis.

/// MIPS primary opcodes.
pub mod opcode {
    pub const SPECIAL: u8 = 0x00;
    pub const REGIMM: u8 = 0x01;
    pub const J: u8 = 0x02;
    pub const JAL: u8 = 0x03;
    pub const BEQ: u8 = 0x04;
    pub const BNE: u8 = 0x05;
    pub const BLEZ: u8 = 0x06;
    pub const BGTZ: u8 = 0x07;
    pub const ADDI: u8 = 0x08;
    pub const ADDIU: u8 = 0x09;
    pub const SLTI: u8 = 0x0A;
    pub const SLTIU: u8 = 0x0B;
    pub const ANDI: u8 = 0x0C;
    pub const ORI: u8 = 0x0D;
    pub const XORI: u8 = 0x0E;
    pub const LUI: u8 = 0x0F;
    pub const COP0: u8 = 0x10;
    pub const COP1: u8 = 0x11;
    pub const COP2: u8 = 0x12;
    pub const COP1X: u8 = 0x13;
    pub const SPECIAL2: u8 = 0x1C;
    pub const SPECIAL3: u8 = 0x1F;
    pub const LB: u8 = 0x20;
    pub const LH: u8 = 0x21;
    pub const LWL: u8 = 0x22;
    pub const LW: u8 = 0x23;
    pub const LBU: u8 = 0x24;
    pub const LHU: u8 = 0x25;
    pub const LWR: u8 = 0x26;
    pub const SB: u8 = 0x28;
    pub const SH: u8 = 0x29;
    pub const SWL: u8 = 0x2A;
    pub const SW: u8 = 0x2B;
    pub const SWR: u8 = 0x2E;
    pub const LL: u8 = 0x30;
    pub const SC: u8 = 0x38;
}

/// MIPS SPECIAL function codes.
pub mod funct {
    pub const SLL: u8 = 0x00;
    pub const SRL: u8 = 0x02;
    pub const SRA: u8 = 0x03;
    pub const SLLV: u8 = 0x04;
    pub const SRLV: u8 = 0x06;
    pub const SRAV: u8 = 0x07;
    pub const JR: u8 = 0x08;
    pub const JALR: u8 = 0x09;
    pub const SYSCALL: u8 = 0x0C;
    pub const BREAK: u8 = 0x0D;
    pub const SYNC: u8 = 0x0F;
    pub const MFHI: u8 = 0x10;
    pub const MTHI: u8 = 0x11;
    pub const MFLO: u8 = 0x12;
    pub const MTLO: u8 = 0x13;
    pub const MULT: u8 = 0x18;
    pub const MULTU: u8 = 0x19;
    pub const DIV: u8 = 0x1A;
    pub const DIVU: u8 = 0x1B;
    pub const ADD: u8 = 0x20;
    pub const ADDU: u8 = 0x21;
    pub const SUB: u8 = 0x22;
    pub const SUBU: u8 = 0x23;
    pub const AND: u8 = 0x24;
    pub const OR: u8 = 0x25;
    pub const XOR: u8 = 0x26;
    pub const NOR: u8 = 0x27;
    pub const SLT: u8 = 0x2A;
    pub const SLTU: u8 = 0x2B;
}

/// Common MIPS patterns.
pub mod patterns {
    pub const NOP: u32 = 0x00000000; // sll $0, $0, 0
    pub const JR_RA: u32 = 0x03E00008; // jr $ra
    pub const SYSCALL: u32 = 0x0000000C; // syscall
    pub const BREAK: u32 = 0x0000000D; // break
}

/// Extract opcode from instruction.
pub fn get_opcode(instr: u32) -> u8 {
    ((instr >> 26) & 0x3F) as u8
}

/// Extract function code from R-type instruction.
pub fn get_funct(instr: u32) -> u8 {
    (instr & 0x3F) as u8
}

/// Extract rs field.
pub fn get_rs(instr: u32) -> u8 {
    ((instr >> 21) & 0x1F) as u8
}

/// Extract rt field.
pub fn get_rt(instr: u32) -> u8 {
    ((instr >> 16) & 0x1F) as u8
}

/// Extract rd field.
pub fn get_rd(instr: u32) -> u8 {
    ((instr >> 11) & 0x1F) as u8
}

/// Extract shamt field.
pub fn get_shamt(instr: u32) -> u8 {
    ((instr >> 6) & 0x1F) as u8
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    let op = get_opcode(instr);
    matches!(op, opcode::BEQ | opcode::BNE | opcode::BLEZ | opcode::BGTZ)
}

/// Check if instruction is JAL.
pub fn is_jal(instr: u32) -> bool {
    get_opcode(instr) == opcode::JAL
}

/// Check if instruction is JR $ra (return).
pub fn is_ret(instr: u32) -> bool {
    let op = get_opcode(instr);
    if op != opcode::SPECIAL {
        return false;
    }
    let fn_code = get_funct(instr);
    let rs = get_rs(instr);
    fn_code == funct::JR && rs == 31 // $ra
}

/// Check if instruction is SYSCALL.
pub fn is_syscall(instr: u32) -> bool {
    let op = get_opcode(instr);
    let fn_code = get_funct(instr);
    op == opcode::SPECIAL && fn_code == funct::SYSCALL
}

/// MIPS has a branch delay slot.
pub const HAS_DELAY_SLOT: bool = true;

/// Score a single MIPS word.
fn score_word(word: u32) -> i64 {
    let mut score: i64 = 0;
    let op = get_opcode(word);

    // NOP (sll $0, $0, 0)
    if word == patterns::NOP {
        score += 15;
    }

    // JR $ra (return)
    if is_ret(word) {
        score += 30;
    }

    // SYSCALL
    if is_syscall(word) {
        score += 20;
    }

    // BREAK
    if op == opcode::SPECIAL && get_funct(word) == funct::BREAK {
        score += 15;
    }

    // Check common opcodes
    match op {
        o if o == opcode::SPECIAL => score += 3,
        o if o == opcode::REGIMM => score += 3,
        o if o == opcode::J => score += 5,
        o if o == opcode::JAL => score += 5,
        o if o == opcode::BEQ => score += 4,
        o if o == opcode::BNE => score += 4,
        o if o == opcode::BLEZ => score += 3,
        o if o == opcode::BGTZ => score += 3,
        o if o == opcode::ADDI => score += 3,
        o if o == opcode::ADDIU => score += 3,
        o if o == opcode::SLTI => score += 3,
        o if o == opcode::SLTIU => score += 3,
        o if o == opcode::ANDI => score += 3,
        o if o == opcode::ORI => score += 3,
        o if o == opcode::XORI => score += 3,
        o if o == opcode::LUI => score += 5,
        o if o == opcode::LB => score += 4,
        o if o == opcode::LH => score += 4,
        o if o == opcode::LW => score += 5,
        o if o == opcode::LBU => score += 4,
        o if o == opcode::LHU => score += 4,
        o if o == opcode::SB => score += 4,
        o if o == opcode::SH => score += 4,
        o if o == opcode::SW => score += 5,
        _ => {}
    }

    // Invalid
    if word == 0xFFFFFFFF {
        score -= 10;
    }

    score
}

/// Score likelihood of MIPS code.
///
/// Returns (big_endian_score, little_endian_score)
pub fn score(data: &[u8]) -> (i64, i64) {
    let mut score_be: i64 = 0;
    let mut score_le: i64 = 0;
    let mut zero_run = 0u32;
    let mut last_word = 0u32;
    let mut repeat_count = 0u32;

    // MIPS instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        // Big-endian
        let word_be = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        // Little-endian
        let word_le = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Handle zero padding - while 0x00000000 is MIPS NOP, long runs suggest padding
        if word_be == 0x00000000 {
            zero_run += 1;
            if zero_run <= 2 {
                // First few NOPs are OK
                score_be += 10;
                score_le += 10;
            } else if zero_run > 4 {
                // Long runs are likely padding, penalize
                score_be -= 3;
                score_le -= 3;
            }
            last_word = word_be;
            continue;
        }
        zero_run = 0;

        // Detect repeated non-zero patterns (padding)
        if word_be == last_word {
            repeat_count += 1;
            if repeat_count > 4 {
                // Likely padding, not code - skip
                continue;
            }
        } else {
            repeat_count = 0;
        }
        last_word = word_be;

        score_be += score_word(word_be);
        score_le += score_word(word_le);
    }

    (score_be.max(0), score_le.max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_extraction() {
        assert_eq!(get_opcode(patterns::NOP), opcode::SPECIAL);
        assert_eq!(get_opcode(patterns::JR_RA), opcode::SPECIAL);
    }

    #[test]
    fn test_ret_detection() {
        assert!(is_ret(patterns::JR_RA));
        assert!(!is_ret(patterns::NOP));
    }

    #[test]
    fn test_syscall_detection() {
        assert!(is_syscall(patterns::SYSCALL));
    }

    #[test]
    fn test_score() {
        // MIPS NOP (big-endian)
        let nop = patterns::NOP.to_be_bytes();
        let (be, _le) = score(&nop);
        assert!(be > 0);
    }
}
