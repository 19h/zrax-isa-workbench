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
    pub const LWU: u8 = 0x27; // MIPS64
    pub const SB: u8 = 0x28;
    pub const SH: u8 = 0x29;
    pub const SWL: u8 = 0x2A;
    pub const SW: u8 = 0x2B;
    pub const SWR: u8 = 0x2E;
    pub const LL: u8 = 0x30;
    pub const LLD: u8 = 0x34; // MIPS64
    pub const LD: u8 = 0x37; // MIPS64
    pub const SC: u8 = 0x38;
    pub const SCD: u8 = 0x3C; // MIPS64
    pub const SD: u8 = 0x3F; // MIPS64
    pub const DADDI: u8 = 0x18; // MIPS64
    pub const DADDIU: u8 = 0x19; // MIPS64
    pub const LDL: u8 = 0x1A; // MIPS64
    pub const LDR: u8 = 0x1B; // MIPS64
    pub const SDL: u8 = 0x2C; // MIPS64
    pub const SDR: u8 = 0x2D; // MIPS64
    pub const LWC1: u8 = 0x31; // FP load single
    pub const LDC1: u8 = 0x35; // FP load double
    pub const SWC1: u8 = 0x39; // FP store single
    pub const SDC1: u8 = 0x3D; // FP store double
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

/// Score a single MIPS word, with optional 64-bit mode.
fn score_word(word: u32, is_64: bool) -> i64 {
    let mut score: i64 = 0;
    let op = get_opcode(word);

    // NOP (sll $0, $0, 0)
    if word == patterns::NOP {
        return 15;
    }

    // JR $ra (return)
    if is_ret(word) {
        return 30;
    }

    // SYSCALL
    if is_syscall(word) {
        return 20;
    }

    // Invalid
    if word == 0xFFFFFFFF {
        return -10;
    }

    // SPECIAL: validate funct code
    if op == opcode::SPECIAL {
        let fn_code = get_funct(word);
        if matches!(
            fn_code,
            funct::SLL | funct::SRL | funct::SRA | funct::SLLV | funct::SRLV | funct::SRAV |
            funct::JR | funct::JALR | funct::SYSCALL | funct::BREAK | funct::SYNC |
            funct::MFHI | funct::MTHI | funct::MFLO | funct::MTLO |
            funct::MULT | funct::MULTU | funct::DIV | funct::DIVU |
            funct::ADD | funct::ADDU | funct::SUB | funct::SUBU |
            funct::AND | funct::OR | funct::XOR | funct::NOR |
            funct::SLT | funct::SLTU |
            0x14 | 0x16 | 0x17 | // DSLLV, DSRLV, DSRAV (MIPS64)
            0x1C | 0x1D | 0x1E | 0x1F | // DMULT, DMULTU, DDIV, DDIVU (MIPS64)
            0x2C | 0x2D | 0x2E | 0x2F | // DADD, DADDU, DSUB, DSUBU (MIPS64)
            0x38 | 0x3A | 0x3B | 0x3C | 0x3E | 0x3F // DSLL, DSRL, DSRA, DSLL32, DSRL32, DSRA32
        ) {
            score += 4;
            // Extra for BREAK
            if fn_code == funct::BREAK {
                score += 8;
            }
        } else {
            // Unknown SPECIAL funct
            score -= 1;
        }
        return score;
    }

    // Check common opcodes
    match op {
        o if o == opcode::REGIMM => score += 4,
        o if o == opcode::J => score += 6,
        o if o == opcode::JAL => score += 6,
        o if o == opcode::BEQ => score += 5,
        o if o == opcode::BNE => score += 5,
        o if o == opcode::BLEZ => score += 4,
        o if o == opcode::BGTZ => score += 4,
        o if o == opcode::ADDI => score += 4,
        o if o == opcode::ADDIU => score += 4,
        o if o == opcode::SLTI => score += 4,
        o if o == opcode::SLTIU => score += 4,
        o if o == opcode::ANDI => score += 4,
        o if o == opcode::ORI => score += 4,
        o if o == opcode::XORI => score += 4,
        o if o == opcode::LUI => score += 6,
        o if o == opcode::COP0 => score += 3,
        o if o == opcode::COP1 => score += 5,
        o if o == opcode::COP2 => score += 3,
        o if o == opcode::COP1X => score += 4,
        o if o == opcode::SPECIAL2 => score += 3,
        o if o == opcode::SPECIAL3 => score += 3,
        o if o == opcode::LB => score += 5,
        o if o == opcode::LH => score += 5,
        o if o == opcode::LW => score += 5,
        o if o == opcode::LBU => score += 5,
        o if o == opcode::LHU => score += 5,
        o if o == opcode::LWL => score += 4,
        o if o == opcode::LWR => score += 4,
        o if o == opcode::SB => score += 5,
        o if o == opcode::SH => score += 5,
        o if o == opcode::SW => score += 5,
        o if o == opcode::SWL => score += 4,
        o if o == opcode::SWR => score += 4,
        o if o == opcode::LL => score += 4,
        o if o == opcode::SC => score += 4,
        // FP load/store
        o if o == opcode::LWC1 => score += 6,
        o if o == opcode::LDC1 => score += 6,
        o if o == opcode::SWC1 => score += 6,
        o if o == opcode::SDC1 => score += 6,
        // MIPS64-specific opcodes
        o if o == opcode::LWU => {
            if is_64 {
                score += 6;
            } else {
                score += 2;
            }
        }
        o if o == opcode::LD => {
            if is_64 {
                score += 7;
            } else {
                score += 1;
            }
        }
        o if o == opcode::SD => {
            if is_64 {
                score += 7;
            } else {
                score += 1;
            }
        }
        o if o == opcode::LLD => {
            if is_64 {
                score += 5;
            }
        }
        o if o == opcode::SCD => {
            if is_64 {
                score += 5;
            }
        }
        o if o == opcode::DADDI => {
            if is_64 {
                score += 5;
            } else {
                score += 1;
            }
        }
        o if o == opcode::DADDIU => {
            if is_64 {
                score += 6;
            } else {
                score += 1;
            }
        }
        o if o == opcode::LDL => {
            if is_64 {
                score += 5;
            }
        }
        o if o == opcode::LDR => {
            if is_64 {
                score += 5;
            }
        }
        o if o == opcode::SDL => {
            if is_64 {
                score += 4;
            }
        }
        o if o == opcode::SDR => {
            if is_64 {
                score += 4;
            }
        }
        _ => {
            // Unknown primary opcode - penalty
            score -= 2;
        }
    }

    // Prologue/epilogue pattern bonuses (on top of generic opcode scores).
    // These require specific register fields, making them very distinctive.
    let rs = get_rs(word);
    let rt = get_rt(word);
    if op == opcode::ADDIU && rs == 29 && rt == 29 {
        score += 6;
    } // ADDIU $sp,$sp,N
    if op == opcode::SW && rt == 31 && rs == 29 {
        score += 6;
    } // SW $ra,N($sp)
    if op == opcode::LW && rt == 31 && rs == 29 {
        score += 6;
    } // LW $ra,N($sp)
    if is_64 {
        if op == opcode::DADDIU && rs == 29 && rt == 29 {
            score += 6;
        }
        if op == opcode::SD && rt == 31 && rs == 29 {
            score += 6;
        }
        if op == opcode::LD && rt == 31 && rs == 29 {
            score += 6;
        }
    }

    score
}

/// Score likelihood of MIPS code.
///
/// Returns (big_endian_score, little_endian_score)
pub fn score(data: &[u8], is_64: bool) -> (i64, i64) {
    let mut score_be: i64 = 0;
    let mut score_le: i64 = 0;
    let mut zero_run = 0u32;
    let mut last_word = 0u32;
    let mut repeat_count = 0u32;
    let mut distinctive_be = 0u32;
    let mut distinctive_le = 0u32;

    // Cross-architecture penalties for 16-bit LE ISA patterns
    // MIPS is 32-bit; when reading 16-bit ISA data as 32-bit words, halfword patterns
    // from MSP430/AVR/Thumb should reduce confidence
    {
        let mut j = 0;
        while j + 1 < data.len() {
            let hw = u16::from_le_bytes([data[j], data[j + 1]]);
            // MSP430 - penalize both BE and LE since the data could be either
            if hw == 0x4130 {
                score_be -= 12;
                score_le -= 12;
            } // MSP430 RET
            if hw == 0x4303 {
                score_be -= 6;
                score_le -= 6;
            } // MSP430 NOP
            if hw == 0x1300 {
                score_be -= 8;
                score_le -= 8;
            } // MSP430 RETI
              // AVR
            if hw == 0x9508 {
                score_be -= 10;
                score_le -= 10;
            } // AVR RET
            if hw == 0x9518 {
                score_be -= 8;
                score_le -= 8;
            } // AVR RETI
              // Thumb
            if hw == 0x4770 {
                score_be -= 10;
                score_le -= 10;
            } // Thumb BX LR
            j += 2;
        }
    }

    // MIPS instructions are 4 bytes, aligned
    let num_words = data.len() / 4;
    for idx in 0..num_words {
        let i = idx * 4;
        // Big-endian
        let word_be = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        // Little-endian
        let word_le = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Handle zero padding - while 0x00000000 is MIPS NOP, long runs suggest padding
        if word_be == 0x00000000 {
            zero_run += 1;
            if zero_run <= 2 {
                score_be += 10;
                score_le += 10;
            } else if zero_run > 4 {
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
                continue;
            }
        } else {
            repeat_count = 0;
        }
        last_word = word_be;

        // Track distinctive MIPS patterns using compound register checks.
        // Simple opcode checks (J/JAL/REGIMM) produce false positives from MSP430
        // data because MSP430 register-direct ops targeting R0-R3 produce bytes
        // 0x00-0x03 in the low byte. Instead, check for patterns requiring BOTH
        // specific opcodes AND specific register fields (probability ~1/65536 per
        // word for random data, vs near-certain for real MIPS code).
        //
        // NOTE: SYSCALL (0x0000000C) and BREAK (0x0000000D) are excluded because
        // they collide with SuperH data: a zero SH halfword (0x0000) followed by
        // SH MOV.B @(R0,Rm),Rn (0x000C) or MOV.W @(R0,Rm),Rn (0x000D) forms an
        // exact SYSCALL/BREAK pattern, causing false distinctive counts on SH firmware.
        {
            // Check for distinctive MIPS patterns in BE direction
            let upper_be = (word_be >> 16) as u16;
            let lower_be = (word_be & 0xFFFF) as u16;
            if word_be == patterns::JR_RA          // JR $ra (exact match)
                || upper_be == 0x27BD               // ADDIU $sp, $sp, N (stack frame)
                || upper_be == 0xAFBF               // SW $ra, N($sp) (save return addr)
                || upper_be == 0x8FBF               // LW $ra, N($sp) (restore return addr)
                || upper_be == 0x67BD
            // DADDIU $sp, $sp, N (MIPS64)
            {
                distinctive_be += 1;
            }
            // NOTE: SD $ra (0xFFBF) and LD $ra (0xDFBF) are intentionally excluded
            // from MIPS64 distinctive patterns. The upper byte 0xFF collides with
            // erased NOR flash, and SH BSR instructions (0xBFxx) combined with
            // preceding MOV #imm instructions produce perfect 0xFFBFxxxx false
            // positives when read as LE 32-bit words. DADDIU $sp (0x67BD) is
            // sufficient for MIPS64 distinctiveness.

            // Check for distinctive MIPS patterns in LE direction
            let upper_le = (word_le >> 16) as u16;
            if word_le == patterns::JR_RA
                || upper_le == 0x27BD
                || upper_le == 0xAFBF
                || upper_le == 0x8FBF
                || upper_le == 0x67BD
            {
                distinctive_le += 1;
            }
        }

        // Cross-architecture penalties

        // ARM32 patterns (LE data) - ARM cond field 0xE in bits 31:28
        // When read as MIPS LE, ARM condition is in the upper nibble
        {
            let arm_le = word_le; // ARM is LE, same as MIPS LE
            let arm_cond = (arm_le >> 28) & 0xF;
            if arm_cond == 0xE {
                // ARM condition "always" - check for common ARM opcodes
                let arm_type = (arm_le >> 25) & 0x7;
                match arm_type {
                    0b000 | 0b001 => score_le -= 4, // Data processing
                    0b010 | 0b011 => score_le -= 4, // Load/Store
                    0b100 => score_le -= 5,         // Block transfer (PUSH/POP)
                    0b101 => score_le -= 5,         // Branch (BL)
                    _ => score_le -= 2,
                }
            }
            // ARM NOP (0xE1A00000)
            if arm_le == 0xE1A00000 || arm_le == 0xE320F000 {
                score_le -= 10;
            }
            // ARM BX LR (0xE12FFF1E)
            if arm_le == 0xE12FFF1E {
                score_le -= 15;
            }

            // For BE: ARM data byte-reversed looks like ARM
            let arm_be = word_be; // When reading ARM (LE) as BE, bytes are swapped
                                  // ARM stored LE: [b0, b1, b2, b3], BE reads: b0<<24|b1<<16|b2<<8|b3
                                  // So we need to swap to get the ARM word: word_le = word_be.swap_bytes()
            let arm_from_be = word_be.swap_bytes();
            let arm_cond_be = (arm_from_be >> 28) & 0xF;
            if arm_cond_be == 0xE {
                let arm_type = (arm_from_be >> 25) & 0x7;
                match arm_type {
                    0b000 | 0b001 => score_be -= 4,
                    0b010 | 0b011 => score_be -= 4,
                    0b100 => score_be -= 5,
                    0b101 => score_be -= 5,
                    _ => score_be -= 2,
                }
            }
            if arm_from_be == 0xE1A00000 || arm_from_be == 0xE320F000 {
                score_be -= 10;
            }
            if arm_from_be == 0xE12FFF1E {
                score_be -= 15;
            }
        }

        // SPARC patterns (BE) - penalize BE score
        if word_be == 0x01000000 {
            score_be -= 10;
        }
        // SPARC NOP
        else if word_be == 0x81C3E008 {
            score_be -= 15;
        }
        // SPARC RETL
        else if word_be == 0x81C7E008 {
            score_be -= 15;
        }
        // SPARC RET
        else {
            let sparc_fmt = (word_be >> 30) & 0x03;
            if sparc_fmt == 2 {
                let op3 = ((word_be >> 19) & 0x3F) as u8;
                if op3 == 0x3C || op3 == 0x3D {
                    score_be -= 5;
                } // SPARC SAVE/RESTORE
            }
        }

        // PPC patterns (BE) - penalize BE score
        if word_be == 0x60000000 {
            score_be -= 10;
        }
        // PPC NOP
        else if word_be == 0x4E800020 {
            score_be -= 15;
        }
        // PPC BLR
        else if word_be == 0x7C0802A6 {
            score_be -= 12;
        } // PPC MFLR

        // RISC-V patterns (LE) - penalize LE score
        if word_le == 0x00000013 {
            score_le -= 10;
        }
        // RISC-V NOP
        else if word_le == 0x00008067 {
            score_le -= 15;
        } // RISC-V RET

        // s390x patterns (BE) - s390x starts with specific byte patterns
        {
            // s390x RR instructions (2-byte, len=00): 0x07FE (BCR 15,rn = return)
            if (word_be >> 16) == 0x07FE {
                score_be -= 12;
            }
            // s390x BASR (0x0D)
            let b0 = (word_be >> 24) as u8;
            if b0 == 0x0D {
                score_be -= 3;
            }
            // s390x BALR (0x05)
            if b0 == 0x05 {
                score_be -= 3;
            }
            // s390x STM/LM (0x90, 0x98) - very common prologue/epilogue
            if b0 == 0x90 || b0 == 0x98 {
                score_be -= 4;
            }
            // s390x STMG/LMG (0xEB) - 6-byte instruction, very common in 64-bit
            if b0 == 0xEB {
                score_be -= 3;
            }
            // s390x LARL (0xC0 0x00) - very common
            if (word_be >> 16) == 0xC000 {
                score_be -= 5;
            }
        }

        // MSP430 patterns (LE 16-bit) - detect MSP430 halfwords in the data
        {
            let hw0 = (word_le & 0xFFFF) as u16;
            let hw1 = (word_le >> 16) as u16;

            // MSP430 RET (0x4130) - strong indicator
            if hw0 == 0x4130 || hw1 == 0x4130 {
                score_le -= 12;
            }
            // MSP430 NOP (0x4303)
            if hw0 == 0x4303 || hw1 == 0x4303 {
                score_le -= 8;
            }
            // MSP430 RETI (0x1300)
            if hw0 == 0x1300 || hw1 == 0x1300 {
                score_le -= 8;
            }
            // MSP430 jump format: bits 15:13 = 001
            if (hw0 & 0xE000) == 0x2000 || (hw1 & 0xE000) == 0x2000 {
                score_le -= 2;
            }
            // MSP430 CALL format (0x12xx)
            if (hw0 & 0xFF80) == 0x1280 || (hw1 & 0xFF80) == 0x1280 {
                score_le -= 5;
            }
            // Also penalize BE for MSP430 patterns (less common but possible)
            if hw0 == 0x4130 || hw1 == 0x4130 {
                score_be -= 6;
            }
        }

        // LoongArch patterns (LE 32-bit)
        {
            // LoongArch NOP = 0x03400000
            if word_le == 0x03400000 {
                score_le -= 12;
            }
            // LoongArch RET = 0x4C000020
            if word_le == 0x4C000020 {
                score_le -= 15;
            }
            // LoongArch JIRL base (0x4C000000) - common branch instruction
            if (word_le & 0xFC000000) == 0x4C000000 {
                score_le -= 3;
            }
            // LoongArch BL (0x54000000)
            if (word_le & 0xFC000000) == 0x54000000 {
                score_le -= 3;
            }
            // LoongArch B (0x50000000)
            if (word_le & 0xFC000000) == 0x50000000 {
                score_le -= 3;
            }
        }

        // SuperH compound patterns (two 16-bit halfwords forming one 32-bit word)
        // SH code has very distinctive instruction pairs, especially around control flow:
        // - RTS; NOP (return with delay slot): 0x000B0009
        // - BSR disp; NOP: 0xBxxx0009
        // - JSR @Rm; NOP: 0x4n0B0009
        // - JMP @Rm; NOP: 0x4n2B0009
        // These compound patterns are extremely unlikely in real MIPS code.
        {
            // SH BE compound patterns (reading BE 32-bit words)
            // RTS; NOP = 0x000B_0009
            if word_be == 0x000B0009 {
                score_be -= 20;
            }
            // NOP; RTS = 0x0009_000B (less common but possible)
            if word_be == 0x0009000B {
                score_be -= 15;
            }
            // JSR @Rm; NOP = 0x4n0B_0009
            if (word_be & 0xF0FF_FFFF) == 0x400B0009 {
                score_be -= 15;
            }
            // JMP @Rm; NOP = 0x4n2B_0009
            if (word_be & 0xF0FF_FFFF) == 0x402B0009 {
                score_be -= 12;
            }
            // RTE; NOP = 0x002B_0009
            if word_be == 0x002B0009 {
                score_be -= 15;
            }

            // SH LE compound patterns (reading LE 32-bit words of SH LE code)
            // RTS; NOP = bytes 0B 00 09 00 → LE 32-bit = 0x0009000B
            if word_le == 0x0009000B {
                score_le -= 20;
            }
            // NOP; RTS = bytes 09 00 0B 00 → LE 32-bit = 0x000B0009
            if word_le == 0x000B0009 {
                score_le -= 15;
            }
            // JSR @Rm; NOP = bytes 0B 4n 09 00 → LE 32-bit = 0x0009_4n0B
            if (word_le & 0xFFFF_F0FF) == 0x0009400B {
                score_le -= 15;
            }
            // JMP @Rm; NOP = bytes 2B 4n 09 00 → LE 32-bit = 0x0009_4n2B
            if (word_le & 0xFFFF_F0FF) == 0x0009402B {
                score_le -= 12;
            }
        }

        // x86/x86_64 patterns (LE byte-oriented) - penalize LE score
        {
            let b0 = (word_le & 0xFF) as u8;
            let b1 = ((word_le >> 8) & 0xFF) as u8;
            let b01 = (word_le & 0xFFFF) as u16;
            // REX.W (0x48) + common x86-64 opcode = very distinctive
            if b0 == 0x48 {
                match b1 {
                    0x89 | 0x8B => score_le -= 8,               // MOV r64
                    0x83 | 0x8D => score_le -= 6,               // arith imm8, LEA
                    0x01 | 0x03 | 0x29 | 0x2B => score_le -= 6, // ADD/SUB
                    0x31 | 0x33 | 0x39 | 0x3B => score_le -= 6, // XOR/CMP
                    0x85 | 0xC7 | 0xFF | 0x63 => score_le -= 5, // TEST/MOV/CALL/MOVSXD
                    _ => {}
                }
            }
            // x86-64 prologue: PUSH RBP; MOV RBP,RSP (55 48 89 E5)
            if word_le == 0xE5894855 {
                score_le -= 15;
            }
            // ENDBR64 (F3 0F 1E FA)
            if word_le == 0xFA1E0FF3 {
                score_le -= 12;
            }
            // Multi-byte NOP (0F 1F xx xx)
            if b01 == 0x1F0F {
                score_le -= 8;
            }
            // SYSCALL (0F 05)
            if b01 == 0x050F {
                score_le -= 10;
            }
        }

        score_be += score_word(word_be, is_64);
        score_le += score_word(word_le, is_64);
    }

    // Structural requirement: MIPS code should contain distinctive patterns
    // like JR $ra, ADDIU $sp, SW/LW $ra, etc. Without enough of these, the data
    // is likely from another ISA (MSP430, AVR, SuperH) that happens to map to
    // valid MIPS opcodes. The threshold scales with data size because in large
    // files, even random data can produce a few accidental matches.
    if num_words > 20 {
        // For large files, require proportionally more distinctive patterns.
        // Real MIPS code has ~1 distinctive pattern per 50-100 instructions.
        // A minimum of 1 per 10,000 words catches accidental matches.
        let min_distinctive = ((num_words as u64 / 10_000).max(1)) as u32;
        if distinctive_be < min_distinctive {
            score_be = (score_be as f64 * 0.15) as i64;
        }
        if distinctive_le < min_distinctive {
            score_le = (score_le as f64 * 0.15) as i64;
        }
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
        let (be, _le) = score(&nop, false);
        assert!(be > 0);
    }
}
