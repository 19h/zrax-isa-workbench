//! SPARC architecture analysis.
//!
//! SPARC uses fixed 32-bit instructions with big-endian encoding.
//! The format field (bits 31:30) determines instruction type.

/// Instruction format (bits 31:30).
pub mod format {
    pub const BRANCH_SETHI: u8 = 0b00; // Branches and SETHI
    pub const CALL: u8 = 0b01; // CALL instruction
    pub const ARITHMETIC: u8 = 0b10; // Arithmetic/logic
    pub const LOAD_STORE: u8 = 0b11; // Load/Store
}

/// op2 field for format 0 instructions (bits 24:22).
pub mod op2 {
    pub const UNIMP: u8 = 0; // Unimplemented (trap)
    pub const BICC: u8 = 2; // Branch on integer condition
    pub const SETHI: u8 = 4; // Set high 22 bits
    pub const FBFCC: u8 = 6; // Branch on FP condition
    pub const CBCCC: u8 = 7; // Branch on coprocessor condition
                             // SPARC V9 additions
    pub const BPR: u8 = 3; // Branch on register
    pub const BPCC: u8 = 1; // Branch on condition with prediction
    pub const FBPFCC: u8 = 5; // FP branch with prediction
}

/// op3 field for format 2 (arithmetic) instructions (bits 24:19).
pub mod op3_arith {
    pub const ADD: u8 = 0x00;
    pub const AND: u8 = 0x01;
    pub const OR: u8 = 0x02;
    pub const XOR: u8 = 0x03;
    pub const SUB: u8 = 0x04;
    pub const ANDN: u8 = 0x05;
    pub const ORN: u8 = 0x06;
    pub const XNOR: u8 = 0x07;
    pub const ADDX: u8 = 0x08; // Add with carry (ADDcc in V9)
    pub const MULX: u8 = 0x09; // Multiply 64-bit (V9)
    pub const UMUL: u8 = 0x0A;
    pub const SMUL: u8 = 0x0B;
    pub const SUBX: u8 = 0x0C; // Subtract with carry
    pub const UDIVX: u8 = 0x0D; // Unsigned divide 64-bit (V9)
    pub const UDIV: u8 = 0x0E;
    pub const SDIV: u8 = 0x0F;
    pub const ADDCC: u8 = 0x10;
    pub const ANDCC: u8 = 0x11;
    pub const ORCC: u8 = 0x12;
    pub const XORCC: u8 = 0x13;
    pub const SUBCC: u8 = 0x14;
    pub const ANDNCC: u8 = 0x15;
    pub const ORNCC: u8 = 0x16;
    pub const XNORCC: u8 = 0x17;
    pub const ADDXCC: u8 = 0x18;
    pub const UMULCC: u8 = 0x1A;
    pub const SMULCC: u8 = 0x1B;
    pub const SUBXCC: u8 = 0x1C;
    pub const UDIVCC: u8 = 0x1E;
    pub const SDIVCC: u8 = 0x1F;
    pub const TADDCC: u8 = 0x20;
    pub const TSUBCC: u8 = 0x21;
    pub const TADDCCTV: u8 = 0x22;
    pub const TSUBCCTV: u8 = 0x23;
    pub const MULSCC: u8 = 0x24;
    pub const SLL: u8 = 0x25; // Shift left logical
    pub const SRL: u8 = 0x26; // Shift right logical
    pub const SRA: u8 = 0x27; // Shift right arithmetic
    pub const RDY: u8 = 0x28; // Read Y register
    pub const RDPSR: u8 = 0x29; // Read PSR
    pub const RDWIM: u8 = 0x2A; // Read WIM
    pub const RDTBR: u8 = 0x2B; // Read TBR
    pub const MOVCC: u8 = 0x2C; // Conditional move (V9)
    pub const SDIVX: u8 = 0x2D; // Signed divide 64-bit (V9)
    pub const POPC: u8 = 0x2E; // Population count (V9)
    pub const MOVR: u8 = 0x2F; // Move on register condition (V9)
    pub const WRY: u8 = 0x30; // Write Y register
    pub const WRPSR: u8 = 0x31; // Write PSR (V8), SAVED/RESTORED (V9)
    pub const WRWIM: u8 = 0x32; // Write WIM (V8), WRPR (V9)
    pub const WRTBR: u8 = 0x33; // Write TBR
    pub const FPOP1: u8 = 0x34; // FP operate type 1
    pub const FPOP2: u8 = 0x35; // FP operate type 2
    pub const JMPL: u8 = 0x38; // Jump and link
    pub const RETT: u8 = 0x39; // Return from trap (V8), RETURN (V9)
    pub const TICC: u8 = 0x3A; // Trap on condition
    pub const FLUSH: u8 = 0x3B; // Flush instruction memory
    pub const SAVE: u8 = 0x3C; // Save register window
    pub const RESTORE: u8 = 0x3D; // Restore register window
    pub const DONE: u8 = 0x3E; // Done (V9)
    pub const RETRY: u8 = 0x3F; // Retry (V9)
}

/// op3 field for format 3 (load/store) instructions.
pub mod op3_mem {
    pub const LD: u8 = 0x00; // Load word
    pub const LDUB: u8 = 0x01; // Load unsigned byte
    pub const LDUH: u8 = 0x02; // Load unsigned halfword
    pub const LDD: u8 = 0x03; // Load doubleword
    pub const ST: u8 = 0x04; // Store word
    pub const STB: u8 = 0x05; // Store byte
    pub const STH: u8 = 0x06; // Store halfword
    pub const STD: u8 = 0x07; // Store doubleword
    pub const LDSB: u8 = 0x09; // Load signed byte
    pub const LDSH: u8 = 0x0A; // Load signed halfword
    pub const LDSTUB: u8 = 0x0D; // Load-store unsigned byte (atomic)
    pub const SWAP: u8 = 0x0F; // Swap word
    pub const LDA: u8 = 0x10; // Load from alternate space
    pub const LDUBA: u8 = 0x11;
    pub const LDUHA: u8 = 0x12;
    pub const LDDA: u8 = 0x13;
    pub const STA: u8 = 0x14; // Store to alternate space
    pub const STBA: u8 = 0x15;
    pub const STHA: u8 = 0x16;
    pub const STDA: u8 = 0x17;
    pub const LDSBA: u8 = 0x19;
    pub const LDSHA: u8 = 0x1A;
    pub const LDSTUBA: u8 = 0x1D;
    pub const SWAPA: u8 = 0x1F;
    pub const LDF: u8 = 0x20; // Load FP
    pub const LDFSR: u8 = 0x21; // Load FP state register
    pub const LDDF: u8 = 0x23; // Load double FP
    pub const STF: u8 = 0x24; // Store FP
    pub const STFSR: u8 = 0x25; // Store FP state register
    pub const STDFQ: u8 = 0x26; // Store double FP queue
    pub const STDF: u8 = 0x27; // Store double FP
                               // V9 64-bit loads/stores
    pub const LDX: u8 = 0x0B; // Load extended word
    pub const STX: u8 = 0x0E; // Store extended word
    pub const LDXA: u8 = 0x1B; // Load extended from alternate space
    pub const STXA: u8 = 0x1E; // Store extended to alternate space
    pub const PREFETCH: u8 = 0x2D; // Prefetch (V9)
    pub const CAS: u8 = 0x3C; // Compare and swap (V9)
    pub const CASX: u8 = 0x3E; // Compare and swap extended (V9)
}

/// Condition codes for branches.
pub mod cond {
    pub const NEVER: u8 = 0; // Never (N)
    pub const EQUAL: u8 = 1; // Equal (E/Z)
    pub const LE: u8 = 2; // Less or equal (LE)
    pub const LESS: u8 = 3; // Less (L)
    pub const LEU: u8 = 4; // Less or equal unsigned (LEU)
    pub const CS: u8 = 5; // Carry set (CS/LU)
    pub const NEG: u8 = 6; // Negative (N)
    pub const VS: u8 = 7; // Overflow set (VS)
    pub const ALWAYS: u8 = 8; // Always (A)
    pub const NE: u8 = 9; // Not equal (NE/NZ)
    pub const GT: u8 = 10; // Greater (G)
    pub const GE: u8 = 11; // Greater or equal (GE)
    pub const GTU: u8 = 12; // Greater unsigned (GU)
    pub const CC: u8 = 13; // Carry clear (CC/GEU)
    pub const POS: u8 = 14; // Positive (P)
    pub const VC: u8 = 15; // Overflow clear (VC)
}

/// Common SPARC instruction patterns.
pub mod patterns {
    /// NOP (sethi 0, %g0).
    pub const NOP: u32 = 0x01000000;

    /// RETL (jmpl %o7+8, %g0) - Return from leaf function.
    pub const RETL: u32 = 0x81C3E008;

    /// RET (jmpl %i7+8, %g0) - Return from non-leaf function.
    pub const RET: u32 = 0x81C7E008;

    /// RESTORE %g0, %g0, %g0 - Common after RET.
    pub const RESTORE: u32 = 0x81E80000;

    /// SAVE %sp, -N, %sp pattern (high bits).
    pub const SAVE_MASK: u32 = 0x81E02000;

    /// TA 0 - Trap always (syscall on some systems).
    pub const TA_0: u32 = 0x91D02000;

    /// ILLTRAP - Illegal instruction trap.
    pub const ILLTRAP: u32 = 0x00000000;

    /// UNIMP - Unimplemented instruction.
    pub const UNIMP_MASK: u32 = 0x00000000;
}

/// Extract format field (bits 31:30).
pub fn get_format(instr: u32) -> u8 {
    ((instr >> 30) & 0x03) as u8
}

/// Extract op2 field for format 0 (bits 24:22).
pub fn get_op2(instr: u32) -> u8 {
    ((instr >> 22) & 0x07) as u8
}

/// Extract op3 field for format 2/3 (bits 24:19).
pub fn get_op3(instr: u32) -> u8 {
    ((instr >> 19) & 0x3F) as u8
}

/// Extract rd field (bits 29:25).
pub fn get_rd(instr: u32) -> u8 {
    ((instr >> 25) & 0x1F) as u8
}

/// Extract rs1 field (bits 18:14).
pub fn get_rs1(instr: u32) -> u8 {
    ((instr >> 14) & 0x1F) as u8
}

/// Extract rs2 field (bits 4:0).
pub fn get_rs2(instr: u32) -> u8 {
    (instr & 0x1F) as u8
}

/// Extract i bit (bit 13) - immediate flag.
pub fn get_i_bit(instr: u32) -> bool {
    (instr & 0x2000) != 0
}

/// Extract simm13 field (bits 12:0).
pub fn get_simm13(instr: u32) -> i16 {
    let val = (instr & 0x1FFF) as i16;
    // Sign extend from 13 bits
    if val & 0x1000 != 0 {
        val | !0x1FFF
    } else {
        val
    }
}

/// Extract condition code field for branches (bits 28:25).
pub fn get_cond(instr: u32) -> u8 {
    ((instr >> 25) & 0x0F) as u8
}

/// Extract annul bit (bit 29).
pub fn get_annul(instr: u32) -> bool {
    (instr & 0x20000000) != 0
}

/// Extract branch displacement (22 bits, sign-extended).
pub fn get_disp22(instr: u32) -> i32 {
    let val = (instr & 0x3FFFFF) as i32;
    // Sign extend from 22 bits
    if val & 0x200000 != 0 {
        val | !0x3FFFFF
    } else {
        val
    }
}

/// Extract CALL displacement (30 bits).
pub fn get_disp30(instr: u32) -> i32 {
    let val = (instr & 0x3FFFFFFF) as i32;
    // Sign extend from 30 bits
    if val & 0x20000000 != 0 {
        val | !0x3FFFFFFF
    } else {
        val
    }
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u32) -> bool {
    instr == patterns::NOP
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    let fmt = get_format(instr);
    if fmt != format::BRANCH_SETHI {
        return false;
    }
    let op2 = get_op2(instr);
    matches!(
        op2,
        op2::BICC | op2::FBFCC | op2::CBCCC | op2::BPR | op2::BPCC | op2::FBPFCC
    )
}

/// Check if instruction is unconditional branch (BA).
pub fn is_ba(instr: u32) -> bool {
    is_branch(instr) && get_cond(instr) == cond::ALWAYS
}

/// Check if instruction is CALL.
pub fn is_call(instr: u32) -> bool {
    get_format(instr) == format::CALL
}

/// Check if instruction is JMPL.
pub fn is_jmpl(instr: u32) -> bool {
    get_format(instr) == format::ARITHMETIC && get_op3(instr) == op3_arith::JMPL
}

/// Check if instruction is RET or RETL.
pub fn is_return(instr: u32) -> bool {
    instr == patterns::RET || instr == patterns::RETL
}

/// Check if instruction is SAVE.
pub fn is_save(instr: u32) -> bool {
    get_format(instr) == format::ARITHMETIC && get_op3(instr) == op3_arith::SAVE
}

/// Check if instruction is RESTORE.
pub fn is_restore(instr: u32) -> bool {
    get_format(instr) == format::ARITHMETIC && get_op3(instr) == op3_arith::RESTORE
}

/// Check if instruction is a load.
pub fn is_load(instr: u32) -> bool {
    let fmt = get_format(instr);
    if fmt != format::LOAD_STORE {
        return false;
    }
    let op3 = get_op3(instr);
    matches!(
        op3,
        op3_mem::LD
            | op3_mem::LDUB
            | op3_mem::LDUH
            | op3_mem::LDD
            | op3_mem::LDSB
            | op3_mem::LDSH
            | op3_mem::LDA
            | op3_mem::LDUBA
            | op3_mem::LDUHA
            | op3_mem::LDDA
            | op3_mem::LDF
            | op3_mem::LDDF
            | op3_mem::LDX
            | op3_mem::LDXA
    )
}

/// Check if instruction is a store.
pub fn is_store(instr: u32) -> bool {
    let fmt = get_format(instr);
    if fmt != format::LOAD_STORE {
        return false;
    }
    let op3 = get_op3(instr);
    matches!(
        op3,
        op3_mem::ST
            | op3_mem::STB
            | op3_mem::STH
            | op3_mem::STD
            | op3_mem::STA
            | op3_mem::STBA
            | op3_mem::STHA
            | op3_mem::STDA
            | op3_mem::STF
            | op3_mem::STDF
            | op3_mem::STX
            | op3_mem::STXA
    )
}

/// Check if instruction is a trap.
pub fn is_trap(instr: u32) -> bool {
    get_format(instr) == format::ARITHMETIC && get_op3(instr) == op3_arith::TICC
}

/// Check if instruction is SETHI.
pub fn is_sethi(instr: u32) -> bool {
    get_format(instr) == format::BRANCH_SETHI && get_op2(instr) == op2::SETHI
}

/// Valid op3 values for arithmetic format (for heuristics).
pub const VALID_ARITH_OP3: &[u8] = &[
    op3_arith::ADD,
    op3_arith::AND,
    op3_arith::OR,
    op3_arith::XOR,
    op3_arith::SUB,
    op3_arith::ANDN,
    op3_arith::ORN,
    op3_arith::XNOR,
    op3_arith::ADDCC,
    op3_arith::ANDCC,
    op3_arith::ORCC,
    op3_arith::XORCC,
    op3_arith::SUBCC,
    op3_arith::SLL,
    op3_arith::SRL,
    op3_arith::SRA,
    op3_arith::JMPL,
    op3_arith::SAVE,
    op3_arith::RESTORE,
];

/// Valid op3 values for load/store format (for heuristics).
pub const VALID_MEM_OP3: &[u8] = &[
    op3_mem::LD,
    op3_mem::LDUB,
    op3_mem::LDUH,
    op3_mem::LDD,
    op3_mem::ST,
    op3_mem::STB,
    op3_mem::STH,
    op3_mem::STD,
    op3_mem::LDSB,
    op3_mem::LDSH,
    op3_mem::LDF,
    op3_mem::LDDF,
    op3_mem::STF,
    op3_mem::STDF,
];

/// Score likelihood of SPARC code.
///
/// Analyzes raw bytes for patterns characteristic of SPARC.
pub fn score(data: &[u8]) -> i64 {
    let mut total_score: i64 = 0;
    let mut valid_count = 0u32;
    let mut save_count = 0u32;
    let mut restore_count = 0u32;
    let mut ret_count = 0u32;
    let mut call_count = 0u32;

    // SPARC is big-endian, 4-byte aligned
    let num_words = data.len() / 4;
    for idx in 0..num_words {
        let i = idx * 4;
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let fmt = get_format(word);

        // Invalid/padding
        if word == 0x00000000 || word == 0xFFFFFFFF {
            total_score -= 3;
            continue;
        }

        // Cross-architecture penalties for other big-endian 32-bit ISAs

        // PPC patterns (BE)
        if word == 0x60000000 {
            total_score -= 15;
            continue;
        } // PPC NOP
        if word == 0x4E800020 {
            total_score -= 20;
            continue;
        } // PPC BLR
        if word == 0x7C0802A6 {
            total_score -= 15;
            continue;
        } // PPC MFLR r0
        if word == 0x7C0803A6 {
            total_score -= 15;
            continue;
        } // PPC MTLR r0
          // PPC primary opcode check
        {
            let ppc_op = (word >> 26) & 0x3F;
            // PPC STWU (0x25) - very common prologue
            if ppc_op == 0x25 {
                total_score -= 3;
            }
        }

        // Cross-architecture penalties for LE ISAs (data read as BE gives byte-swapped)
        // Interpret same bytes as LE to detect LE patterns
        {
            let le_word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            // ARM32 NOP
            if le_word == 0xE1A00000 || le_word == 0xE320F000 {
                total_score -= 12;
                continue;
            }
            // ARM32 BX LR
            if le_word == 0xE12FFF1E {
                total_score -= 15;
                continue;
            }
            // RISC-V NOP
            if le_word == 0x00000013 {
                total_score -= 10;
                continue;
            }
            // RISC-V RET
            if le_word == 0x00008067 {
                total_score -= 15;
                continue;
            }
            // LoongArch NOP
            if le_word == 0x03400000 {
                total_score -= 10;
                continue;
            }
            // LoongArch RET
            if le_word == 0x4C000020 {
                total_score -= 15;
                continue;
            }
        }

        // Detect 16-bit LE instruction pairs (Thumb, MSP430, AVR)
        {
            let hw0 = u16::from_le_bytes([data[i], data[i + 1]]);
            let hw1 = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            // Thumb BX LR
            if hw0 == 0x4770 || hw1 == 0x4770 {
                total_score -= 8;
                continue;
            }
            // Thumb NOP
            if hw0 == 0xBF00 || hw1 == 0xBF00 {
                total_score -= 5;
            }
            // Thumb PUSH/POP
            if (hw0 & 0xFE00) == 0xB400
                || (hw0 & 0xFE00) == 0xBC00
                || (hw1 & 0xFE00) == 0xB400
                || (hw1 & 0xFE00) == 0xBC00
            {
                total_score -= 4;
            }
            // MSP430 RET (0x4130)
            if hw0 == 0x4130 || hw1 == 0x4130 {
                total_score -= 10;
                continue;
            }
            // MSP430 NOP (0x4303)
            if hw0 == 0x4303 || hw1 == 0x4303 {
                total_score -= 8;
            }
            // AVR RET (0x9508)
            if hw0 == 0x9508 || hw1 == 0x9508 {
                total_score -= 10;
                continue;
            }
            // AVR RETI (0x9518)
            if hw0 == 0x9518 || hw1 == 0x9518 {
                total_score -= 8;
                continue;
            }
            // AVR SLEEP
            if hw0 == 0x9588 || hw1 == 0x9588 {
                total_score -= 8;
            }
            // AVR SEI / CLI
            if hw0 == 0x9478 || hw1 == 0x9478 {
                total_score -= 6;
            }
            if hw0 == 0x94F8 || hw1 == 0x94F8 {
                total_score -= 6;
            }
            // AVR IJMP / ICALL
            if hw0 == 0x9409 || hw1 == 0x9409 {
                total_score -= 6;
            }
            if hw0 == 0x9509 || hw1 == 0x9509 {
                total_score -= 6;
            }
            // AVR PUSH (mask 0xFE0F = 0x920F)
            if (hw0 & 0xFE0F) == 0x920F || (hw1 & 0xFE0F) == 0x920F {
                total_score -= 4;
            }
            // AVR POP (mask 0xFE0F = 0x900F)
            if (hw0 & 0xFE0F) == 0x900F || (hw1 & 0xFE0F) == 0x900F {
                total_score -= 4;
            }
        }

        // NOP (exact match) - very strong indicator
        if is_nop(word) {
            total_score += 25;
            valid_count += 1;
            continue;
        }

        // RETL/RET (exact match) - very strong indicator
        if is_return(word) {
            total_score += 30;
            ret_count += 1;
            valid_count += 1;
            continue;
        }

        // RESTORE %g0, %g0, %g0 (exact match)
        if word == patterns::RESTORE {
            total_score += 20;
            restore_count += 1;
            valid_count += 1;
            continue;
        }

        // TA 0 (trap always syscall)
        if word == patterns::TA_0 {
            total_score += 15;
            valid_count += 1;
            continue;
        }

        // CALL (format 01 - covers 25% of space!)
        // Since 25% of random words match CALL format, score very conservatively
        if fmt == format::CALL {
            call_count += 1;
            valid_count += 1;
            total_score += 1;
            continue;
        }

        // Branch/SETHI (format 00)
        if fmt == format::BRANCH_SETHI {
            let op2_val = get_op2(word);
            match op2_val {
                op2::SETHI => {
                    // SETHI is very common; check rd != 0 for more confidence
                    let rd = get_rd(word);
                    if rd != 0 {
                        total_score += 5;
                    } else {
                        total_score += 2;
                    }
                    valid_count += 1;
                }
                op2::BICC => {
                    let cc = get_cond(word);
                    // All condition codes are valid
                    if cc == cond::NEVER {
                        total_score += 2;
                    } else if cc == cond::ALWAYS {
                        total_score += 5;
                    } else {
                        total_score += 4;
                    }
                    valid_count += 1;
                }
                op2::BPCC => {
                    // V9 branch with prediction - strong indicator
                    total_score += 6;
                    valid_count += 1;
                }
                op2::FBFCC | op2::FBPFCC => {
                    total_score += 5;
                    valid_count += 1;
                }
                op2::BPR => {
                    // V9 branch on register
                    total_score += 6;
                    valid_count += 1;
                }
                op2::CBCCC => {
                    total_score += 4;
                    valid_count += 1;
                }
                op2::UNIMP => {
                    // UNIMP/ILLTRAP - can appear as padding
                    total_score += 1;
                    valid_count += 1;
                }
                _ => {
                    // Invalid op2
                    total_score -= 2;
                }
            }
            continue;
        }

        // Arithmetic (format 10) - validate op3
        if fmt == format::ARITHMETIC {
            let op3 = get_op3(word);

            // SAVE/RESTORE are very distinctive
            if op3 == op3_arith::SAVE {
                total_score += 15;
                save_count += 1;
                valid_count += 1;
                continue;
            }
            if op3 == op3_arith::RESTORE {
                total_score += 15;
                restore_count += 1;
                valid_count += 1;
                continue;
            }
            // JMPL is strong
            if op3 == op3_arith::JMPL {
                total_score += 8;
                valid_count += 1;
                continue;
            }
            // RETT/RETURN
            if op3 == op3_arith::RETT {
                total_score += 10;
                ret_count += 1;
                valid_count += 1;
                continue;
            }
            // TICC (trap)
            if op3 == op3_arith::TICC {
                total_score += 6;
                valid_count += 1;
                continue;
            }
            // FP operations - distinctive
            if op3 == op3_arith::FPOP1 || op3 == op3_arith::FPOP2 {
                total_score += 5;
                valid_count += 1;
                continue;
            }

            // Common ALU operations
            if matches!(
                op3,
                0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | // ADD, AND, OR, XOR, SUB, ANDN, ORN, XNOR
                0x08 | 0x0A | 0x0B | 0x0C | 0x0E | 0x0F |  // ADDX, UMUL, SMUL, SUBX, UDIV, SDIV
                0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | // cc variants
                0x18 | 0x1A | 0x1B | 0x1C | 0x1E | 0x1F |  // cc variants
                0x25 | 0x26 | 0x27 | // SLL, SRL, SRA
                0x28 | 0x29 | 0x2A | 0x2B | // RDY, RDPSR, RDWIM, RDTBR
                0x30 | 0x31 | 0x32 | 0x33 | // WRY, WRPSR, WRWIM, WRTBR
                0x09 | 0x0D | // MULX, UDIVX (V9)
                0x2C | 0x2D | 0x2E | 0x2F | // MOVCC, SDIVX, POPC, MOVR (V9)
                0x20 | 0x21 | 0x22 | 0x23 | 0x24 | // TADDCC, TSUBCC, etc.
                0x3B // FLUSH
            ) {
                total_score += 3;
                valid_count += 1;
            } else if op3 == 0x3E || op3 == 0x3F {
                // DONE/RETRY (V9) - distinctive
                total_score += 8;
                valid_count += 1;
            } else {
                // Unknown op3 in arithmetic format - mild penalty
                total_score -= 1;
            }
            continue;
        }

        // Load/Store (format 11) - validate op3
        if fmt == format::LOAD_STORE {
            let op3 = get_op3(word);
            if matches!(
                op3,
                0x00 | 0x01 | 0x02 | 0x03 | // LD, LDUB, LDUH, LDD
                0x04 | 0x05 | 0x06 | 0x07 | // ST, STB, STH, STD
                0x09 | 0x0A | 0x0B |         // LDSB, LDSH, LDX (V9)
                0x0D | 0x0E | 0x0F |         // LDSTUB, STX (V9), SWAP
                0x10 | 0x11 | 0x12 | 0x13 |  // LDA, LDUBA, LDUHA, LDDA
                0x14 | 0x15 | 0x16 | 0x17 |  // STA, STBA, STHA, STDA
                0x19 | 0x1A | 0x1B |          // LDSBA, LDSHA, LDXA (V9)
                0x1D | 0x1E | 0x1F |          // LDSTUBA, STXA (V9), SWAPA
                0x20 | 0x21 | 0x23 |          // LDF, LDFSR, LDDF
                0x24 | 0x25 | 0x26 | 0x27 |  // STF, STFSR, STDFQ, STDF
                0x2D |                         // PREFETCH (V9)
                0x3C | 0x3E // CAS, CASX (V9)
            ) {
                total_score += 4;
                valid_count += 1;
            } else {
                // Unknown op3 in load/store format
                total_score -= 1;
            }
            continue;
        }
    }

    // SAVE/RESTORE pairing is a very strong SPARC indicator
    if save_count > 0 && restore_count > 0 {
        total_score += (save_count.min(restore_count) * 10) as i64;
    }

    // Structural bonus: SPARC code with calls + returns is very reliable
    if ret_count > 0 && call_count > 0 {
        total_score += 10;
    }

    // Structural requirement: SPARC format bits cover ALL 4 values (00,01,10,11),
    // meaning 100% of random words match some format. CALL alone is 25% of space.
    // SAVE/RESTORE format matches ~1/128 of random words, so a single match is
    // insufficient evidence. Require multiple distinctive patterns.
    if num_words > 20 {
        let distinctive = save_count + restore_count + ret_count;
        if distinctive == 0 {
            total_score = (total_score as f64 * 0.10) as i64;
        } else if distinctive == 1 {
            // Single SAVE or RESTORE could be a random format match (1/128 per word)
            total_score = (total_score as f64 * 0.25) as i64;
        } else if ret_count == 0 && save_count > 0 && restore_count > 0 {
            // SAVE+RESTORE but no returns - mild penalty
            total_score = (total_score as f64 * 0.60) as i64;
        }
    }

    total_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_extraction() {
        assert_eq!(get_format(patterns::NOP), format::BRANCH_SETHI);
        assert_eq!(get_format(patterns::RETL), format::ARITHMETIC);
    }

    #[test]
    fn test_nop_detection() {
        assert!(is_nop(patterns::NOP));
        assert!(!is_nop(patterns::RETL));
    }

    #[test]
    fn test_return_detection() {
        assert!(is_return(patterns::RETL));
        assert!(is_return(patterns::RET));
        assert!(!is_return(patterns::NOP));
    }

    #[test]
    fn test_call_detection() {
        // CALL with arbitrary displacement: op=01, disp30=anything
        let call_instr: u32 = 0x40000100; // CALL .+0x400
        assert!(is_call(call_instr));
        assert!(!is_call(patterns::NOP));
    }

    #[test]
    fn test_branch_detection() {
        // BA (branch always): format=00, op2=010, cond=1000
        let ba_instr: u32 = 0x10800001; // BA .+4
        assert!(is_branch(ba_instr));
        assert!(is_ba(ba_instr));
    }

    #[test]
    fn test_save_restore() {
        // SAVE %sp, -96, %sp
        let save_instr: u32 = 0x9DE3BFA0;
        assert!(is_save(save_instr));

        assert!(is_restore(patterns::RESTORE));
    }

    #[test]
    fn test_field_extraction() {
        // ADD %g1, %g2, %g3: format=10, rd=3, op3=0, rs1=1, i=0, rs2=2
        let add_instr: u32 = 0x86004002;
        assert_eq!(get_format(add_instr), format::ARITHMETIC);
        assert_eq!(get_rd(add_instr), 3);
        assert_eq!(get_op3(add_instr), op3_arith::ADD);
        assert_eq!(get_rs1(add_instr), 1);
        assert!(!get_i_bit(add_instr));
        assert_eq!(get_rs2(add_instr), 2);
    }

    #[test]
    fn test_simm13_extraction() {
        // ADD %g1, -1, %g2: format=10, rd=2, op3=0, rs1=1, i=1, simm13=-1
        // Calculated: 0x80000000 | (2<<25) | (0<<19) | (1<<14) | (1<<13) | 0x1FFF = 0x84007FFF
        let add_imm: u32 = 0x84007FFF;
        assert!(get_i_bit(add_imm));
        assert_eq!(get_simm13(add_imm), -1);
    }

    #[test]
    fn test_score() {
        // SPARC NOP (big-endian)
        let nop = patterns::NOP.to_be_bytes();
        assert!(score(&nop) > 0);
    }
}
