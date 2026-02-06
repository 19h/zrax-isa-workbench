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
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut branch_count = 0u32;

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        // Invalid/padding
        if word == 0x0000_0000 || word == 0xFFFF_FFFF {
            score -= 5;
            continue;
        }

        // --- Cross-architecture penalties (BE ISAs) ---
        // PPC
        if word == 0x60000000 { score -= 12; continue; }  // NOP
        if word == 0x4E800020 { score -= 15; continue; }  // BLR
        if (word >> 26) == 18 { score -= 5; }             // B/BL
        // SPARC
        if word == 0x01000000 { score -= 10; continue; }  // NOP
        if word == 0x81C7E008 { score -= 15; continue; }  // RET
        // MIPS BE
        if word == 0x03E00008 { score -= 12; continue; }  // JR $ra
        // S390x
        if (word >> 16) == 0x07FE { score -= 12; continue; }  // BR %r14

        // --- Cross-architecture penalties (16-bit LE ISAs) ---
        // OpenRISC is 32-bit BE; when 16-bit LE data (Thumb, AVR, MSP430) is read
        // as 32-bit BE, distinctive patterns appear in the halfwords.
        {
            let hw0 = (word >> 16) as u16;  // first halfword (BE byte order)
            let hw0_le = hw0.swap_bytes();  // convert to LE interpretation
            let hw1 = (word & 0xFFFF) as u16;
            let hw1_le = hw1.swap_bytes();
            // Thumb
            if hw0_le == 0x4770 || hw1_le == 0x4770 { score -= 12; } // BX LR
            if hw0_le == 0xBF00 || hw1_le == 0xBF00 { score -= 8; }  // NOP
            if (hw0_le & 0xFF00) == 0xB500 || (hw1_le & 0xFF00) == 0xB500 { score -= 6; } // PUSH {..,LR}
            if (hw0_le & 0xFF00) == 0xBD00 || (hw1_le & 0xFF00) == 0xBD00 { score -= 6; } // POP {..,PC}
            // AVR
            if hw0_le == 0x9508 || hw1_le == 0x9508 { score -= 10; } // RET
            if hw0_le == 0x9518 || hw1_le == 0x9518 { score -= 10; } // RETI
            // MSP430
            if hw0_le == 0x4130 || hw1_le == 0x4130 { score -= 10; } // RET
            if hw0_le == 0x4303 || hw1_le == 0x4303 { score -= 8; }  // NOP
        }

        // Exact matches (high confidence)
        if (word & MASK_NOP) == PATTERN_NOP {
            score += 20;
            continue;
        }
        if word == OPENRISC_RET {
            score += 30;
            ret_count += 1;
            continue;
        }
        if (word & MASK_SYS) == PATTERN_SYS {
            score += 15;
            continue;
        }
        if (word & MASK_TRAP) == PATTERN_TRAP {
            score += 10;
            continue;
        }

        // Control flow
        if (word & MASK_JR) == PATTERN_JR {
            score += 12;
            ret_count += 1;
            continue;
        }
        if (word & MASK_JALR) == PATTERN_JALR {
            score += 10;
            call_count += 1;
            continue;
        }
        if opcode == OP_JAL {
            score += 5;
            call_count += 1;
            continue;
        }
        if opcode == OP_J {
            score += 4;
            branch_count += 1;
            continue;
        }
        if opcode == OP_BF || opcode == OP_BNF {
            score += 3;
            branch_count += 1;
            continue;
        }

        // ALU/immediate
        if opcode == OP_ALU {
            score += 2;
            continue;
        }
        if opcode == OP_ADDI || opcode == OP_ANDI || opcode == OP_ORI || opcode == OP_XORI {
            score += 2;
            continue;
        }

        // Load/store
        if opcode == OP_LWZ || opcode == OP_LWS || opcode == OP_LBZ
            || opcode == OP_LBS || opcode == OP_LHZ || opcode == OP_LHS
        {
            score += 2;
            continue;
        }
        if opcode == OP_SW || opcode == OP_SB || opcode == OP_SH {
            score += 2;
            continue;
        }
        if opcode == OP_MOVHI {
            score += 3;
            continue;
        }

        // Unrecognized opcode
        score -= 2;
    }

    // Structural requirement
    let num_words = data.len() / 4;
    if num_words > 20 {
        let distinctive = ret_count + call_count;
        if distinctive == 0 && branch_count == 0 {
            score = (score as f64 * 0.10) as i64;
        } else if distinctive == 0 {
            score = (score as f64 * 0.25) as i64;
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
