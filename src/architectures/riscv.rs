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
/// - Standard opcodes with funct3/funct7 validation
/// - Compressed instructions with specific pattern checks
pub fn score(data: &[u8], bits: u8) -> i64 {
    let mut score: i64 = 0;
    let is_64 = bits == 64;
    let mut i = 0;
    let mut ret_count = 0u32;
    let mut jal_jalr_count = 0u32;
    let mut branch_count = 0u32;

    // Cross-architecture penalties for 16-bit LE patterns
    // Applied up-front to penalize data from 16-bit ISAs that would otherwise
    // score well via compressed instruction matches (~75% of halfword space)
    {
        let mut j = 0;
        while j + 1 < data.len() {
            let hw = u16::from_le_bytes([data[j], data[j + 1]]);
            // MSP430
            if hw == 0x4130 { score -= 15; } // MSP430 RET
            if hw == 0x4303 { score -= 8; }  // MSP430 NOP
            if hw == 0x1300 { score -= 10; } // MSP430 RETI
            // AVR
            if hw == 0x9508 { score -= 12; } // AVR RET
            if hw == 0x9518 { score -= 10; } // AVR RETI
            if hw == 0x9588 { score -= 8; }  // AVR SLEEP
            if hw == 0x9598 { score -= 8; }  // AVR BREAK
            // Thumb
            if hw == 0x4770 { score -= 12; } // Thumb BX LR
            if hw == 0xBF00 { score -= 8; }  // Thumb NOP
            if (hw & 0xFF00) == 0xB500 { score -= 5; } // Thumb PUSH {.., LR}
            if (hw & 0xFF00) == 0xBD00 { score -= 5; } // Thumb POP {.., PC}
            // SH (SuperH)
            if hw == 0x000B { score -= 12; } // SH RTS
            if hw == 0x0009 { score -= 8; }  // SH NOP
            // MIPS LE compound register patterns (upper halfword of MIPS instructions)
            if hw == 0x27BD { score -= 10; } // MIPS ADDIU $sp,$sp,N
            if hw == 0xAFBF { score -= 10; } // MIPS SW $ra,N($sp)
            if hw == 0x8FBF { score -= 10; } // MIPS LW $ra,N($sp)
            if hw == 0xAFBE { score -= 6; }  // MIPS SW $fp,N($sp)
            if hw == 0x8FBE { score -= 6; }  // MIPS LW $fp,N($sp)
            // MIPS SW/LW callee-saved regs to/from stack
            if (hw & 0xFFF8) == 0xAFA0 || (hw & 0xFFF8) == 0xAFB0 { score -= 4; }
            if (hw & 0xFFF8) == 0x8FA0 || (hw & 0xFFF8) == 0x8FB0 { score -= 4; }
            // MIPS LUI (opcode 0x0F, rs=0, upper hw = 0x3C00-0x3C1F)
            if (hw & 0xFFE0) == 0x3C00 { score -= 5; }
            j += 2;
        }
    }

    // Cross-architecture penalties for 32-bit BE patterns (read as LE)
    {
        let mut j = 0;
        while j + 3 < data.len() {
            let le32 = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            // SPARC (BE encoded, read as LE — byte-swap)
            // SPARC NOP (BE 0x01000000 → LE 0x00000001) — but that's low bits = 01 = compressed
            // SPARC RET (BE 0x81C7E008 → LE 0x08E0C781)
            if le32 == 0x08E0C781 { score -= 15; } // SPARC RET as LE
            // SPARC RETL (BE 0x81C3E008 → LE 0x08E0C381)
            if le32 == 0x08E0C381 { score -= 15; } // SPARC RETL as LE
            // PPC BLR (BE 0x4E800020 → LE 0x2000804E)
            if le32 == 0x2000804E { score -= 15; } // PPC BLR as LE
            // PPC NOP (BE 0x60000000 → LE 0x00000060)
            if le32 == 0x00000060 { score -= 10; } // PPC NOP as LE
            // PPC MFLR r0 (BE 0x7C0802A6 → LE 0xA602087C)
            if le32 == 0xA602087C { score -= 10; }
            // SPARC exact patterns (BE values swapped to LE for comparison)
            {
                let be32 = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
                // SPARC NOP (0x01000000)
                if be32 == 0x01000000 { score -= 10; }
                // SPARC RESTORE %g0,%g0,%g0 (0x81E80000)
                if be32 == 0x81E80000 { score -= 12; }
                // SPARC SAVE with %sp as source (common: save %sp, -N, %sp)
                // Format: 10 rd 111100 rs1 1 imm13 — rs1=%sp(14)=%o6
                if (be32 >> 30) == 2 {
                    let op3 = ((be32 >> 19) & 0x3F) as u8;
                    let rs1 = ((be32 >> 14) & 0x1F) as u8;
                    if op3 == 0x3C && rs1 == 14 { score -= 12; } // SAVE %sp,...
                    if op3 == 0x3D { score -= 8; } // any RESTORE
                }
            }
            j += 4;
        }
    }

    while i < data.len() {
        let instr_len = instruction_length(&data[i..]);

        if instr_len == 2 {
            // Compressed instruction (16-bit)
            if i + 2 > data.len() {
                break;
            }

            let half = u16::from_le_bytes([data[i], data[i + 1]]);
            let quadrant = half & 0x03;

            // Exact matches (high confidence)
            if half == patterns::C_NOP {
                score += 20;
                i += 2;
                continue;
            }
            if half == patterns::C_RET {
                score += 25;
                ret_count += 1;
                i += 2;
                continue;
            }
            if half == patterns::C_EBREAK {
                score += 15;
                i += 2;
                continue;
            }

            // C.ADDI16SP (distinctive stack adjust)
            if (half & 0xEF83) == 0x6101 {
                score += 10;
                i += 2;
                continue;
            }

            // Score specific compressed instruction patterns
            let funct3 = (half >> 13) & 0x07;
            match quadrant {
                0 => {
                    // Quadrant 0: C.ADDI4SPN, C.FLD, C.LW, C.FLW/C.LD, C.FSD, C.SW, C.FSW/C.SD
                    match funct3 {
                        0 => {
                            // C.ADDI4SPN - nzuimm must be non-zero
                            if (half >> 5) != 0 { score += 3; } else { score -= 1; }
                        }
                        1 | 2 | 3 | 5 | 6 | 7 => score += 2, // Valid C load/store
                        _ => score -= 1,
                    }
                }
                1 => {
                    // Quadrant 1: C.NOP/C.ADDI, C.JAL/C.ADDIW, C.LI, C.ADDI16SP/C.LUI, C.MISC-ALU, C.J, C.BEQZ, C.BNEZ
                    match funct3 {
                        0 | 1 | 2 | 3 => score += 2,
                        4 => score += 2, // C.MISC-ALU (SRLI, SRAI, ANDI, SUB, XOR, OR, AND)
                        5 => { score += 3; jal_jalr_count += 1; } // C.J - very common
                        6 | 7 => { score += 2; branch_count += 1; } // C.BEQZ, C.BNEZ
                        _ => score -= 1,
                    }
                }
                2 => {
                    // Quadrant 2: C.SLLI, C.FLDSP, C.LWSP, C.FLWSP/C.LDSP, C.JR/C.MV/C.EBREAK/C.JALR/C.ADD, C.FSDSP, C.SWSP, C.FSWSP/C.SDSP
                    match funct3 {
                        0 => score += 2, // C.SLLI
                        1 | 2 | 3 => score += 2, // C.xLSP (stack loads)
                        4 => score += 3, // C.JR/C.MV/C.JALR/C.ADD - very common
                        5 | 6 | 7 => score += 2, // C.xSSP (stack stores)
                        _ => score -= 1,
                    }
                }
                _ => {
                    // quadrant 3 = 32-bit instruction, shouldn't be here
                    score -= 2;
                }
            }

            i += 2;
        } else {
            // 32-bit instruction
            if i + 4 > data.len() {
                break;
            }

            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            let op = get_opcode(word);

            // Cross-architecture penalties: MIPS LE patterns
            // MIPS LE stores words in LE; upper 16 bits (opcode+rs+rt) = (word >> 16)
            {
                let mips_upper16 = (word >> 16) as u16;
                // MIPS JR $ra (0x03E00008) in LE
                if word == 0x03E00008 {
                    score -= 15;
                    i += 4;
                    continue;
                }
                // MIPS SYSCALL (0x0000000C)
                if word == 0x0000000C {
                    score -= 10;
                    i += 4;
                    continue;
                }
                // MIPS compound register patterns
                if mips_upper16 == 0x27BD    // ADDIU $sp,$sp,N
                    || mips_upper16 == 0xAFBF // SW $ra,N($sp)
                    || mips_upper16 == 0x8FBF // LW $ra,N($sp)
                    || mips_upper16 == 0x67BD // DADDIU $sp,$sp,N (MIPS64)
                    || mips_upper16 == 0xFFBF // SD $ra,N($sp) (MIPS64)
                    || mips_upper16 == 0xDFBF // LD $ra,N($sp) (MIPS64)
                {
                    score -= 8;
                    i += 4;
                    continue;
                }
                // Common MIPS LE opcodes that overlap with valid RISC-V
                let mips_op = (word >> 26) & 0x3F;
                if mips_op == 0x09 { // ADDIU
                    let mips_rs = (word >> 21) & 0x1F;
                    if matches!(mips_rs as u8, 28 | 29 | 30 | 31) {
                        score -= 3; // ADDIU with $sp/$gp/$ra
                    }
                }
                // MIPS R-type ADDU with common register combos
                if mips_op == 0 {
                    let funct = (word & 0x3F) as u8;
                    if funct == 0x21 { // ADDU
                        let rd = ((word >> 11) & 0x1F) as u8;
                        if matches!(rd, 2 | 4 | 5 | 6 | 7) { score -= 3; } // result in $v0/$a0-$a3
                    }
                }
            }

            // Exact matches (high confidence)
            if word == patterns::NOP {
                score += 25;
                i += 4;
                continue;
            }
            if word == patterns::RET {
                score += 30;
                ret_count += 1;
                i += 4;
                continue;
            }
            if word == patterns::ECALL {
                score += 20;
                i += 4;
                continue;
            }
            if word == patterns::EBREAK {
                score += 15;
                i += 4;
                continue;
            }

            // Validate opcodes with funct3/funct7 where possible
            let f3 = get_funct3(word);
            let f7 = get_funct7(word);

            match op {
                o if o == opcode::LOAD => {
                    // funct3: 0=LB, 1=LH, 2=LW, 3=LD, 4=LBU, 5=LHU, 6=LWU
                    if f3 <= 6 { score += 4; } else { score -= 1; }
                }
                o if o == opcode::OP_IMM => {
                    // funct3: 0=ADDI, 1=SLLI, 2=SLTI, 3=SLTIU, 4=XORI, 5=SRLI/SRAI, 6=ORI, 7=ANDI
                    score += 4;
                }
                o if o == opcode::AUIPC => score += 5,
                o if o == opcode::STORE => {
                    // funct3: 0=SB, 1=SH, 2=SW, 3=SD
                    if f3 <= 3 { score += 4; } else { score -= 1; }
                }
                o if o == opcode::OP => {
                    // funct7: 0x00=base, 0x01=M extension, 0x20=SUB/SRA
                    if matches!(f7, 0x00 | 0x01 | 0x20) { score += 5; } else { score -= 1; }
                }
                o if o == opcode::LUI => score += 5,
                o if o == opcode::BRANCH => {
                    // funct3: 0=BEQ, 1=BNE, 4=BLT, 5=BGE, 6=BLTU, 7=BGEU
                    if matches!(f3, 0 | 1 | 4 | 5 | 6 | 7) { score += 4; branch_count += 1; } else { score -= 1; }
                }
                o if o == opcode::JALR => {
                    // funct3 must be 0
                    if f3 == 0 { score += 5; jal_jalr_count += 1; } else { score -= 2; }
                }
                o if o == opcode::JAL => { score += 5; jal_jalr_count += 1; }
                o if o == opcode::SYSTEM => score += 4,
                // 64-bit specific
                o if o == opcode::OP_IMM_32 && is_64 => score += 5,
                o if o == opcode::OP_32 && is_64 => {
                    if matches!(f7, 0x00 | 0x01 | 0x20) { score += 5; } else { score -= 1; }
                }
                // Extensions
                o if o == opcode::LOAD_FP => score += 3,
                o if o == opcode::STORE_FP => score += 3,
                o if o == opcode::AMO => score += 3,
                o if o == opcode::OP_FP => score += 3,
                o if o == opcode::OP_V => score += 3,
                o if o == opcode::MISC_MEM => score += 3, // FENCE
                // Unrecognized 32-bit opcode
                _ => { score -= 2; }
            }

            i += 4;
        }
    }

    // Structural requirement: real RISC-V code must have branches, returns, or calls
    // Without this, random data from other ISAs scores well because ~75% of halfwords
    // have bits[1:0] != 11 (interpreted as compressed instructions scoring +2 each)
    let num_instrs = data.len() / 2; // rough estimate of instruction count
    if num_instrs > 20 {
        let distinctive = ret_count + jal_jalr_count;
        if distinctive == 0 && branch_count == 0 {
            score = (score as f64 * 0.15) as i64;
        } else if distinctive == 0 {
            // Has branches but no returns or calls
            score = (score as f64 * 0.35) as i64;
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
