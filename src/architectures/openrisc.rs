//! OpenRISC architecture support.
//!
//! OpenRISC is an open-source RISC processor architecture.
//! It uses big-endian 32-bit fixed-width instructions.

/// l.nop instruction mask/pattern
pub const MASK_NOP: u32 = 0xFFFF_0000;
pub const PATTERN_NOP: u32 = 0x1500_0000;

/// l.jr r9 - standard return (jump to link register)
pub const OPENRISC_RET: u32 = 0x4400_4800;

/// l.jr instruction mask/pattern
pub const MASK_JR: u32 = 0xFFFF_07FF;
pub const PATTERN_JR: u32 = 0x4400_0000;

/// l.jalr instruction mask/pattern
pub const MASK_JALR: u32 = 0xFFFF_07FF;
pub const PATTERN_JALR: u32 = 0x4800_0000;

/// l.jal opcode - jump and link
pub const OP_JAL: u32 = 0x01;

/// l.j opcode - unconditional jump
pub const OP_J: u32 = 0x00;

/// l.bf opcode - branch if flag
pub const OP_BF: u32 = 0x04;

/// l.bnf opcode - branch if not flag
pub const OP_BNF: u32 = 0x03;

/// ALU register operations opcode
pub const OP_ALU: u32 = 0x38;

/// Immediate arithmetic opcodes
pub const OP_ADDI: u32 = 0x27;
pub const OP_ANDI: u32 = 0x29;
pub const OP_ORI: u32 = 0x2A;
pub const OP_XORI: u32 = 0x2B;

/// Load opcodes
pub const OP_LWZ: u32 = 0x21;
pub const OP_LWS: u32 = 0x22;
pub const OP_LBZ: u32 = 0x23;
pub const OP_LBS: u32 = 0x24;
pub const OP_LHZ: u32 = 0x25;
pub const OP_LHS: u32 = 0x26;

/// Store opcodes
pub const OP_SW: u32 = 0x35;
pub const OP_SB: u32 = 0x36;
pub const OP_SH: u32 = 0x37;

/// l.movhi opcode - move high immediate
pub const OP_MOVHI: u32 = 0x06;

/// l.sys instruction mask/pattern
pub const MASK_SYS: u32 = 0xFFFF_0000;
pub const PATTERN_SYS: u32 = 0x2000_0000;

/// l.trap instruction mask/pattern
pub const MASK_TRAP: u32 = 0xFFFF_0000;
pub const PATTERN_TRAP: u32 = 0x2100_0000;

/// Score likelihood of OpenRISC code.
///
/// OpenRISC uses big-endian 32-bit instructions with a 6-bit opcode
/// field in bits 26-31.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        if (word & MASK_NOP) == PATTERN_NOP {
            score += 20; // l.nop
        }
        if word == OPENRISC_RET {
            score += 30; // l.jr r9
        }
        if (word & MASK_JR) == PATTERN_JR {
            score += 15; // l.jr
        }
        if (word & MASK_JALR) == PATTERN_JALR {
            score += 12; // l.jalr
        }
        if opcode == OP_JAL {
            score += 10; // l.jal
        }
        if opcode == OP_J {
            score += 8; // l.j
        }
        if opcode == OP_BF || opcode == OP_BNF {
            score += 5; // l.bf/l.bnf
        }
        if opcode == OP_ALU {
            score += 3; // l.add/l.sub/l.and/l.or/l.xor
        }
        if opcode == OP_ADDI || opcode == OP_ANDI || opcode == OP_ORI || opcode == OP_XORI {
            score += 3; // l.addi/l.andi/l.ori/l.xori
        }
        if opcode == OP_LWZ
            || opcode == OP_LWS
            || opcode == OP_LBZ
            || opcode == OP_LBS
            || opcode == OP_LHZ
            || opcode == OP_LHS
        {
            score += 4; // loads
        }
        if opcode == OP_SW || opcode == OP_SB || opcode == OP_SH {
            score += 4; // stores
        }
        if opcode == OP_MOVHI {
            score += 5; // l.movhi
        }
        if (word & MASK_SYS) == PATTERN_SYS {
            score += 15; // l.sys
        }
        if (word & MASK_TRAP) == PATTERN_TRAP {
            score += 10; // l.trap
        }
        if word == 0x0000_0000 || word == 0xFFFF_FFFF {
            score -= 5;
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openrisc_nop() {
        // l.nop 0
        let code = 0x1500_0000u32.to_be_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_openrisc_ret() {
        let code = OPENRISC_RET.to_be_bytes();
        assert!(score(&code) > 0);
    }

    #[test]
    fn test_openrisc_sequence() {
        // l.nop + l.jr r9
        let mut code = Vec::new();
        code.extend_from_slice(&0x1500_0000u32.to_be_bytes());
        code.extend_from_slice(&OPENRISC_RET.to_be_bytes());
        assert!(score(&code) >= 50); // 20 + 30
    }
}
