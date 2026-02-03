//! RISC-V architecture analysis.

/// Standard RISC-V opcodes (bits [6:0]).
pub mod opcode {
    pub const LOAD: u8 = 0x03;
    pub const LOAD_FP: u8 = 0x07;
    pub const MISC_MEM: u8 = 0x0F;
    pub const OP_IMM: u8 = 0x13;
    pub const AUIPC: u8 = 0x17;
    pub const OP_IMM_32: u8 = 0x1B;
    pub const STORE: u8 = 0x23;
    pub const STORE_FP: u8 = 0x27;
    pub const AMO: u8 = 0x2F;
    pub const OP: u8 = 0x33;
    pub const LUI: u8 = 0x37;
    pub const OP_32: u8 = 0x3B;
    pub const MADD: u8 = 0x43;
    pub const MSUB: u8 = 0x47;
    pub const NMSUB: u8 = 0x4B;
    pub const NMADD: u8 = 0x4F;
    pub const OP_FP: u8 = 0x53;
    pub const OP_V: u8 = 0x57;
    pub const BRANCH: u8 = 0x63;
    pub const JALR: u8 = 0x67;
    pub const JAL: u8 = 0x6F;
    pub const SYSTEM: u8 = 0x73;
}

/// Common RISC-V instruction patterns.
pub mod patterns {
    pub const NOP: u32 = 0x00000013; // addi x0, x0, 0
    pub const RET: u32 = 0x00008067; // jalr x0, x1, 0
    pub const ECALL: u32 = 0x00000073; // ecall
    pub const EBREAK: u32 = 0x00100073; // ebreak
    pub const C_NOP: u16 = 0x0001; // c.nop
    pub const C_RET: u16 = 0x8082; // c.jr ra / c.ret
    pub const C_EBREAK: u16 = 0x9002; // c.ebreak
}

/// Determine instruction length from first bytes.
pub fn instruction_length(first_two_bytes: &[u8]) -> usize {
    if first_two_bytes.is_empty() {
        return 0;
    }

    let low_bits = first_two_bytes[0] & 0x03;

    match low_bits {
        0b00 | 0b01 | 0b10 => 2, // Compressed (16-bit)
        0b11 => {
            // 32-bit or longer
            let bits_4_2 = (first_two_bytes[0] >> 2) & 0x07;
            if bits_4_2 != 0b111 {
                4 // 32-bit
            } else {
                // Check for longer instructions (48, 64, etc.)
                // For now, assume 32-bit
                4
            }
        }
        _ => 4,
    }
}

/// Extract opcode from 32-bit instruction.
pub fn get_opcode(instr: u32) -> u8 {
    (instr & 0x7F) as u8
}

/// Extract funct3 field.
pub fn get_funct3(instr: u32) -> u8 {
    ((instr >> 12) & 0x7) as u8
}

/// Extract funct7 field.
pub fn get_funct7(instr: u32) -> u8 {
    ((instr >> 25) & 0x7F) as u8
}

/// Extract rd (destination register).
pub fn get_rd(instr: u32) -> u8 {
    ((instr >> 7) & 0x1F) as u8
}

/// Extract rs1 (source register 1).
pub fn get_rs1(instr: u32) -> u8 {
    ((instr >> 15) & 0x1F) as u8
}

/// Extract rs2 (source register 2).
pub fn get_rs2(instr: u32) -> u8 {
    ((instr >> 20) & 0x1F) as u8
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    get_opcode(instr) == opcode::BRANCH
}

/// Check if instruction is JAL.
pub fn is_jal(instr: u32) -> bool {
    get_opcode(instr) == opcode::JAL
}

/// Check if instruction is JALR.
pub fn is_jalr(instr: u32) -> bool {
    get_opcode(instr) == opcode::JALR
}

/// Check if instruction is a return.
pub fn is_ret(instr: u32) -> bool {
    // jalr x0, ra, 0
    instr == patterns::RET
}

/// Check if instruction uses M extension.
pub fn uses_m_extension(instr: u32) -> bool {
    let op = get_opcode(instr);
    let funct7 = get_funct7(instr);
    (op == opcode::OP || op == opcode::OP_32) && funct7 == 0x01
}

/// Check if instruction uses A extension.
pub fn uses_a_extension(instr: u32) -> bool {
    get_opcode(instr) == opcode::AMO
}

/// Check if instruction uses F/D extension.
pub fn uses_fd_extension(instr: u32) -> bool {
    let op = get_opcode(instr);
    matches!(
        op,
        opcode::LOAD_FP
            | opcode::STORE_FP
            | opcode::OP_FP
            | opcode::MADD
            | opcode::MSUB
            | opcode::NMSUB
            | opcode::NMADD
    )
}

/// Check if instruction uses V extension.
pub fn uses_v_extension(instr: u32) -> bool {
    get_opcode(instr) == opcode::OP_V
}

/// Score likelihood of RISC-V code.
///
/// Analyzes raw bytes for patterns characteristic of RISC-V:
/// - Instruction length encoding (bits [1:0])
/// - Standard opcodes
/// - Compressed instructions
pub fn score(data: &[u8], bits: u8) -> i64 {
    let mut score: i64 = 0;
    let is_64 = bits == 64;
    let mut i = 0;

    while i < data.len() {
        let instr_len = instruction_length(&data[i..]);

        if instr_len == 2 {
            // Compressed instruction (16-bit)
            if i + 2 > data.len() {
                break;
            }

            let half = u16::from_le_bytes([data[i], data[i + 1]]);

            // C.NOP
            if half == patterns::C_NOP {
                score += 20;
            }

            // C.RET
            if half == patterns::C_RET {
                score += 25;
            }

            // C.EBREAK
            if half == patterns::C_EBREAK {
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
            let op = get_opcode(word);

            // NOP
            if word == patterns::NOP {
                score += 25;
            }

            // RET
            if word == patterns::RET {
                score += 30;
            }

            // ECALL
            if word == patterns::ECALL {
                score += 20;
            }

            // EBREAK
            if word == patterns::EBREAK {
                score += 15;
            }

            // Check for valid standard opcodes
            match op {
                o if o == opcode::LOAD => score += 5,
                o if o == opcode::OP_IMM => score += 5,
                o if o == opcode::AUIPC => score += 5,
                o if o == opcode::STORE => score += 5,
                o if o == opcode::OP => score += 5,
                o if o == opcode::LUI => score += 5,
                o if o == opcode::BRANCH => score += 5,
                o if o == opcode::JALR => score += 5,
                o if o == opcode::JAL => score += 5,
                o if o == opcode::SYSTEM => score += 5,
                // 64-bit specific
                o if o == opcode::OP_IMM_32 && is_64 => score += 5,
                o if o == opcode::OP_32 && is_64 => score += 5,
                // Extensions
                o if o == opcode::LOAD_FP => score += 3,
                o if o == opcode::STORE_FP => score += 3,
                o if o == opcode::AMO => score += 3,
                o if o == opcode::OP_FP => score += 3,
                o if o == opcode::OP_V => score += 3,
                _ => {}
            }

            // Check for M extension
            if uses_m_extension(word) {
                score += 5;
            }

            i += 4;
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_length() {
        assert_eq!(instruction_length(&[0x01, 0x00]), 2); // Compressed
        assert_eq!(instruction_length(&[0x13, 0x00]), 4); // 32-bit
    }

    #[test]
    fn test_opcode_extraction() {
        assert_eq!(get_opcode(patterns::NOP), opcode::OP_IMM);
        assert_eq!(get_opcode(patterns::RET), opcode::JALR);
    }

    #[test]
    fn test_ret_detection() {
        assert!(is_ret(patterns::RET));
        assert!(!is_ret(patterns::NOP));
    }

    #[test]
    fn test_score() {
        // RISC-V NOP
        let nop = patterns::NOP.to_le_bytes();
        assert!(score(&nop, 64) > 0);
        // RET
        let ret = patterns::RET.to_le_bytes();
        assert!(score(&ret, 64) > 0);
    }
}
