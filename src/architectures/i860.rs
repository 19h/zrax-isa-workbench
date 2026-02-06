//! Intel i860 architecture analysis.
//!
//! The i860 uses a fixed 32-bit instruction format with dual-instruction mode,
//! allowing simultaneous execution of one core instruction and one FPU/graphics instruction.
//! Little-endian byte order.

/// Intel i860 opcode constants.
pub mod opcode {
    // Primary opcode groups (bits 31-26)
    /// Load/store integer (0x00-0x0F).
    pub const LOAD_STORE_INT_START: u8 = 0x00;
    pub const LOAD_STORE_INT_END: u8 = 0x0F;
    /// Core arithmetic (0x10-0x17).
    pub const CORE_ARITH_START: u8 = 0x10;
    pub const CORE_ARITH_END: u8 = 0x17;
    /// Control transfer (0x18-0x1F).
    pub const CONTROL_START: u8 = 0x18;
    pub const CONTROL_END: u8 = 0x1F;
    /// Load/store floating-point (0x20-0x27).
    pub const LOAD_STORE_FP_START: u8 = 0x20;
    pub const LOAD_STORE_FP_END: u8 = 0x27;
    /// Load FP pipelined (0x28-0x2F).
    pub const LOAD_FP_PIPE_START: u8 = 0x28;
    pub const LOAD_FP_PIPE_END: u8 = 0x2F;
    /// FPU instructions (0x30-0x37).
    pub const FPU_START: u8 = 0x30;
    pub const FPU_END: u8 = 0x37;
    /// Graphics/extended (0x38-0x3F).
    pub const GRAPHICS_START: u8 = 0x38;
    pub const GRAPHICS_END: u8 = 0x3F;

    // Specific opcodes
    /// Load byte.
    pub const LD_B: u8 = 0x00;
    /// Load byte unsigned.
    pub const LD_BU: u8 = 0x01;
    /// Load short.
    pub const LD_S: u8 = 0x02;
    /// Load short unsigned.
    pub const LD_SU: u8 = 0x03;
    /// Load word.
    pub const LD_W: u8 = 0x04;
    /// Store byte.
    pub const ST_B: u8 = 0x08;
    /// Store short.
    pub const ST_S: u8 = 0x0A;
    /// Store word.
    pub const ST_W: u8 = 0x0C;

    // Core ALU opcodes
    /// Add.
    pub const ADD: u8 = 0x10;
    /// Add unsigned.
    pub const ADDU: u8 = 0x11;
    /// Subtract.
    pub const SUB: u8 = 0x12;
    /// Subtract unsigned.
    pub const SUBU: u8 = 0x13;
    /// Shift left logical.
    pub const SHL: u8 = 0x14;
    /// Shift right logical.
    pub const SHR: u8 = 0x15;
    /// Shift right arithmetic.
    pub const SHRA: u8 = 0x16;
    /// AND.
    pub const AND: u8 = 0x17;

    // Control transfer
    /// Branch indirect.
    pub const BR: u8 = 0x18;
    /// Call.
    pub const CALL: u8 = 0x1A;
    /// Branch conditional.
    pub const BC: u8 = 0x1C;
    /// Branch not conditional.
    pub const BNC: u8 = 0x1D;
    /// Branch on CC.
    pub const BC_T: u8 = 0x1E;
    /// Branch not CC.
    pub const BNC_T: u8 = 0x1F;

    // FP load/store
    /// FP load single.
    pub const FLD_S: u8 = 0x20;
    /// FP load double.
    pub const FLD_D: u8 = 0x21;
    /// FP store single.
    pub const FST_S: u8 = 0x28;
    /// FP store double.
    pub const FST_D: u8 = 0x29;

    // FPU operations (6 bits: 31-26)
    /// Floating add.
    pub const FADD: u8 = 0x30;
    /// Floating subtract.
    pub const FSUB: u8 = 0x31;
    /// Floating multiply.
    pub const FMUL: u8 = 0x32;
    /// Floating multiply low.
    pub const FMLOW: u8 = 0x33;
    /// Floating reciprocal.
    pub const FRCP: u8 = 0x34;
    /// Floating reciprocal sqrt.
    pub const FRSQR: u8 = 0x35;
    /// Pipelined FP add.
    pub const PFADD: u8 = 0x36;
    /// Pipelined FP subtract.
    pub const PFSUB: u8 = 0x37;
    /// Pipelined FP multiply.
    pub const PFMUL: u8 = 0x38;

    // Graphics operations
    /// Z-buffer check less.
    pub const FZCHKL: u8 = 0x3C;
    /// Z-buffer check less/same.
    pub const FZCHKS: u8 = 0x3D;
    /// Pixel operations.
    pub const PIXEL_OP: u8 = 0x3E;

    // Special patterns
    /// NOP encoding (trap never).
    pub const NOP: u32 = 0xA0000000;
}

/// Instruction format types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Register-Register (R-type).
    RType,
    /// Register-Immediate (I-type).
    IType,
    /// Control Transfer.
    Control,
    /// FPU instruction.
    Fpu,
    /// Invalid/unknown format.
    Unknown,
}

/// Extract the primary opcode (bits 31-26).
pub fn extract_opcode(instr: u32) -> u8 {
    ((instr >> 26) & 0x3F) as u8
}

/// Extract source register 1 (bits 15-11).
pub fn extract_src1(instr: u32) -> u8 {
    ((instr >> 11) & 0x1F) as u8
}

/// Extract source register 2 (bits 25-21).
pub fn extract_src2(instr: u32) -> u8 {
    ((instr >> 21) & 0x1F) as u8
}

/// Extract destination register (bits 20-16).
pub fn extract_dest(instr: u32) -> u8 {
    ((instr >> 16) & 0x1F) as u8
}

/// Extract immediate value (bits 15-0).
pub fn extract_imm16(instr: u32) -> u16 {
    (instr & 0xFFFF) as u16
}

/// Extract function code for R-type (bits 10-0).
pub fn extract_func(instr: u32) -> u16 {
    (instr & 0x7FF) as u16
}

/// Extract the D-bit (bit 9) for dual-mode toggle.
pub fn extract_d_bit(instr: u32) -> bool {
    (instr >> 9) & 1 == 1
}

/// Extract the P-bit (bit 10) for pipeline mode.
pub fn extract_p_bit(instr: u32) -> bool {
    (instr >> 10) & 1 == 1
}

/// Extract source precision bits (bits 8-7).
pub fn extract_src_precision(instr: u32) -> u8 {
    ((instr >> 7) & 0x3) as u8
}

/// Determine instruction format from opcode.
pub fn instruction_format(op: u8) -> Format {
    match op {
        opcode::LOAD_STORE_INT_START..=opcode::LOAD_STORE_INT_END => Format::IType,
        opcode::CORE_ARITH_START..=opcode::CORE_ARITH_END => Format::RType,
        opcode::CONTROL_START..=opcode::CONTROL_END => Format::Control,
        opcode::LOAD_STORE_FP_START..=opcode::LOAD_FP_PIPE_END => Format::IType,
        opcode::FPU_START..=opcode::GRAPHICS_END => Format::Fpu,
        _ => Format::Unknown,
    }
}

/// Check if instruction is a load.
pub fn is_load(op: u8) -> bool {
    matches!(
        op,
        opcode::LD_B
            | opcode::LD_BU
            | opcode::LD_S
            | opcode::LD_SU
            | opcode::LD_W
            | opcode::FLD_S
            | opcode::FLD_D
    )
}

/// Check if instruction is a store.
pub fn is_store(op: u8) -> bool {
    matches!(
        op,
        opcode::ST_B | opcode::ST_S | opcode::ST_W | opcode::FST_S | opcode::FST_D
    )
}

/// Check if instruction is a branch.
pub fn is_branch(op: u8) -> bool {
    matches!(
        op,
        opcode::BR | opcode::CALL | opcode::BC | opcode::BNC | opcode::BC_T | opcode::BNC_T
    )
}

/// Check if instruction is a return (indirect branch through r1/link).
pub fn is_return(instr: u32) -> bool {
    let op = extract_opcode(instr);
    // Return is typically "br r1" or similar indirect branch through link register
    if op == opcode::BR {
        let src1 = extract_src1(instr);
        // r1 is the link register
        return src1 == 1;
    }
    false
}

/// Check if instruction is an FPU operation.
pub fn is_fpu(op: u8) -> bool {
    matches!(op, opcode::FPU_START..=opcode::GRAPHICS_END)
}

/// Check if instruction is a NOP.
pub fn is_nop(instr: u32) -> bool {
    // NOP is the exact trap-never encoding: 0xA0000000
    // The broad mask check was wrong - it matched all FST_S instructions
    instr == opcode::NOP
}

/// Check if instruction enables dual-mode.
pub fn toggles_dual_mode(instr: u32) -> bool {
    let op = extract_opcode(instr);
    if is_fpu(op) {
        extract_d_bit(instr)
    } else {
        false
    }
}

/// Check if instruction is pipelined FPU.
pub fn is_pipelined_fpu(instr: u32) -> bool {
    let op = extract_opcode(instr);
    if is_fpu(op) {
        extract_p_bit(instr)
    } else {
        false
    }
}

/// Check if instruction is a graphics operation.
pub fn is_graphics(op: u8) -> bool {
    matches!(op, opcode::GRAPHICS_START..=opcode::GRAPHICS_END)
}

/// Check if instruction is an ALU operation.
pub fn is_alu(op: u8) -> bool {
    matches!(op, opcode::CORE_ARITH_START..=opcode::CORE_ARITH_END)
}

/// Score likelihood of i860 code.
///
/// Analyzes raw bytes for patterns characteristic of i860:
/// - Fixed 32-bit instruction encoding
/// - Valid opcode ranges
/// - FPU/dual-mode patterns
/// - Register usage patterns
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 4 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;
    let mut zero_run: u32 = 0;
    let mut arm_al_count = 0u32;
    let mut arm_total_count = 0u32;

    // i860 is little-endian, 4-byte aligned
    let mut i = 0;
    while i + 3 < data.len() {
        let instr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Handle all-zero pattern specially - likely padding, not real LD_B
        if instr == 0x00000000 {
            zero_run += 1;
            if zero_run > 2 {
                // Long runs of zeros are padding, penalize
                total_score -= 1;
            }
            i += 4;
            continue;
        } else {
            zero_run = 0;
        }

        // Also handle all-ones (0xFFFFFFFF) as likely invalid
        if instr == 0xFFFFFFFF {
            invalid_count += 1;
            total_score -= 2;
            i += 4;
            continue;
        }

        // Common padding patterns
        if instr == 0x5A5A5A5A || instr == 0xDEADBEEF || instr == 0xCAFEBABE || instr == 0xFEEDFACE
        {
            total_score -= 3;
            i += 4;
            continue;
        }

        // ARM32 cross-architecture detection
        // ARM32 with condition 0xE (Always) maps to i860 graphics opcodes (0x38-0x3B)
        {
            let arm_cond = (instr >> 28) & 0xF;
            if arm_cond <= 0xE {
                arm_total_count += 1;
                if arm_cond == 0xE {
                    arm_al_count += 1;
                }
            }
            // Exact ARM32 patterns
            if instr == 0xE1A00000 || instr == 0xE320F000 {
                // ARM NOP
                total_score -= 15;
                i += 4;
                continue;
            }
            if instr == 0xE12FFF1E {
                // ARM BX LR
                total_score -= 20;
                i += 4;
                continue;
            }
            if (instr & 0xFFFF0000) == 0xE92D0000 || (instr & 0xFFFF0000) == 0xE8BD0000 {
                // ARM PUSH/POP
                total_score -= 15;
                i += 4;
                continue;
            }
            if arm_cond <= 0xE && (instr & 0x0F000000) == 0x0B000000 {
                // ARM BL (branch with link)
                total_score -= 10;
                i += 4;
                continue;
            }
            if arm_cond <= 0xE && (instr & 0x0FFFFFF0) == 0x012FFF10 {
                // ARM BX Rn
                total_score -= 12;
                i += 4;
                continue;
            }
        }

        // Detect Thumb-2 instruction patterns that could false-positive as i860
        // Thumb-2 BL: first halfword F000-F7FF, second halfword D000-DFFF or F800-FFFF
        // When read as little-endian 32-bit: 0xDxxxFxxx or 0xFxxxFxxx
        // Also detect Thumb-2 32-bit prefixes in general
        {
            let hw1 = (instr >> 16) as u16; // Second halfword (in memory order)
            let hw0 = (instr & 0xFFFF) as u16; // First halfword
            let hw0_prefix = (hw0 >> 11) & 0x1F;
            let hw1_prefix = (hw1 >> 11) & 0x1F;

            // Check if both halfwords look like Thumb-2 32-bit instruction halves
            // First half: 0b11101xx, 0b11110xx, 0b11111xx (0x1D, 0x1E, 0x1F)
            let is_thumb2_prefix = matches!(hw0_prefix, 0x1D | 0x1E | 0x1F);

            // Common Thumb-2 32-bit patterns:
            // BL/BLX: hw0 = F000-F7FF, hw1 = C000-DFFF (BL) or E000-EFFF (BLX)
            if is_thumb2_prefix {
                // BL instruction: F0xx Dxxx or F0xx Fxxx patterns
                if (hw0 & 0xF800) == 0xF000
                    && ((hw1 & 0xD000) == 0xD000 || (hw1 & 0xD000) == 0x9000)
                {
                    // Strong Thumb-2 BL pattern
                    total_score -= 8;
                    i += 4;
                    continue;
                }

                // Thumb-2 LDR.W / STR.W: F8xx xxxx or F85x, F84x patterns
                if (hw0 & 0xFF00) == 0xF800 || (hw0 & 0xFFF0) == 0xF8D0 || (hw0 & 0xFFF0) == 0xF8C0
                {
                    total_score -= 6;
                    i += 4;
                    continue;
                }

                // Generic 32-bit Thumb-2 - mild penalty
                total_score -= 3;
            }

            // Thumb-2 PUSH.W/POP.W: E92Dxxxx / E8BDxxxx
            if (instr & 0xFFFFE000) == 0xE92D0000 || (instr & 0xFFFFE000) == 0xE8BD0000 {
                total_score -= 10;
                i += 4;
                continue;
            }

            // Detect 16-bit Thumb pairs that look like valid i860
            // BX LR (4770) paired with something
            if hw0 == 0x4770 || hw1 == 0x4770 {
                total_score -= 5;
            }

            // PUSH/POP 16-bit: B4xx/BCxx, B5xx/BDxx
            if (hw0 & 0xFE00) == 0xB400
                || (hw0 & 0xFE00) == 0xBC00
                || (hw1 & 0xFE00) == 0xB400
                || (hw1 & 0xFE00) == 0xBC00
            {
                total_score -= 4;
            }

            // NOP.N (BF00) - very common Thumb marker
            if hw0 == 0xBF00 || hw1 == 0xBF00 {
                total_score -= 4;
            }

            // LDR Rt, [PC, #imm] - PC-relative load (48xx-4Fxx)
            if (hw0 & 0xF800) == 0x4800 || (hw1 & 0xF800) == 0x4800 {
                total_score -= 3;
            }

            // CBZ/CBNZ (B1xx, B3xx, B9xx, BBxx)
            if (hw0 & 0xF500) == 0xB100
                || (hw0 & 0xF500) == 0xB900
                || (hw1 & 0xF500) == 0xB100
                || (hw1 & 0xF500) == 0xB900
            {
                total_score -= 4;
            }

            // Thumb LDR.W/STR.W patterns that don't have Thumb-2 prefix
            // 5Fxx patterns are common in Thumb code
            if (hw0 & 0xFF00) == 0x5F00 || (hw1 & 0xFF00) == 0x5F00 {
                total_score -= 3;
            }

            // Conditional branch B<cond> (Dxxx except DE/DF)
            if ((hw0 & 0xF000) == 0xD000 && (hw0 & 0x0F00) < 0x0E00)
                || ((hw1 & 0xF000) == 0xD000 && (hw1 & 0x0F00) < 0x0E00)
            {
                total_score -= 3;
            }

            // Unconditional branch B (E0xx-E7FF - 16-bit)
            // Note: E8xx-EFFF are 32-bit Thumb-2 instructions
            if ((hw0 & 0xF800) == 0xE000 && (hw0 & 0x0800) == 0x0000)
                || ((hw1 & 0xF800) == 0xE000 && (hw1 & 0x0800) == 0x0000)
            {
                total_score -= 3;
            }
        }

        let op = extract_opcode(instr);
        let format = instruction_format(op);

        // --- Cross-architecture penalties ---
        // Penalize patterns that look like other common architectures

        // MIPS patterns (big-endian 32-bit, opcode in bits 31:26)
        // When read as LE, MIPS opcodes appear in low byte positions
        {
            let be_word = u32::from_be_bytes(instr.to_le_bytes());
            let mips_op = (be_word >> 26) & 0x3F;
            // Common MIPS: ADDIU(0x09), LUI(0x0F), LW(0x23), SW(0x2B), JAL(0x03), BEQ(0x04), BNE(0x05)
            if mips_op == 0x09 || mips_op == 0x0F || mips_op == 0x23 || mips_op == 0x2B {
                total_score -= 3;
            }
            // MIPS JR $ra (0x03E00008)
            if be_word == 0x03E00008 {
                total_score -= 15;
            }
            // MIPS NOP
            if be_word == 0x00000000 {
                // Already handled above
            }
        }

        // PowerPC patterns (big-endian, opcode in bits 31:26)
        {
            let be_word = u32::from_be_bytes(instr.to_le_bytes());
            // PPC NOP (ori 0,0,0 = 0x60000000)
            if be_word == 0x60000000 {
                total_score -= 12;
            }
            // PPC BLR (0x4E800020)
            if be_word == 0x4E800020 {
                total_score -= 15;
            }
            // PPC MFLR r0 (0x7C0802A6)
            if be_word == 0x7C0802A6 {
                total_score -= 15;
            }
        }

        // PowerPC LE patterns (when PPC LE data is read as LE, values are direct)
        {
            // PPC NOP (ori 0,0,0 = 0x60000000)
            if instr == 0x60000000 {
                total_score -= 12;
                i += 4;
                continue;
            }
            // PPC BLR (0x4E800020)
            if instr == 0x4E800020 {
                total_score -= 15;
                i += 4;
                continue;
            }
            // PPC MFLR r0 (0x7C0802A6)
            if instr == 0x7C0802A6 {
                total_score -= 15;
                i += 4;
                continue;
            }
            // PPC MTLR r0 (0x7C0803A6)
            if instr == 0x7C0803A6 {
                total_score -= 12;
                i += 4;
                continue;
            }
            // PPC STWU r1, -N(r1) = 0x9421xxxx (stack frame setup)
            if (instr & 0xFFFF0000) == 0x94210000 {
                total_score -= 10;
                i += 4;
                continue;
            }
            // PPC STDU r1, -N(r1) = 0xF821xxxx (64-bit stack frame setup)
            if (instr & 0xFFFF0000) == 0xF8210000 {
                total_score -= 10;
                i += 4;
                continue;
            }
            // PPC ADDI (li) r3-r12 = 0x38xxxxxx, very common
            let ppc_op = (instr >> 26) & 0x3F;
            if ppc_op == 14 { // ADDI
                total_score -= 2;
            }
        }

        // SPARC patterns (big-endian)
        {
            let be_word = u32::from_be_bytes(instr.to_le_bytes());
            // SPARC NOP (sethi 0, %g0 = 0x01000000)
            if be_word == 0x01000000 {
                total_score -= 12;
                i += 4;
                continue;
            }
            // SPARC RETL (0x81C3E008)
            if be_word == 0x81C3E008 {
                total_score -= 15;
                i += 4;
                continue;
            }
            // SPARC RET (0x81C7E008)
            if be_word == 0x81C7E008 {
                total_score -= 15;
                i += 4;
                continue;
            }
            // SPARC SAVE: format 10, op3=111100 (0x3C) - function prologue
            if (be_word >> 30) == 2 && ((be_word >> 19) & 0x3F) == 0x3C {
                total_score -= 10;
                i += 4;
                continue;
            }
            // SPARC RESTORE: format 10, op3=111101 (0x3D) - function epilogue
            if (be_word >> 30) == 2 && ((be_word >> 19) & 0x3F) == 0x3D {
                total_score -= 10;
                i += 4;
                continue;
            }
            // SPARC CALL: format bits 31:30 = 01
            if (be_word >> 30) == 1 {
                total_score -= 3;
            }
        }

        // RISC-V patterns (little-endian, opcode in bits 6:0)
        {
            let rv_op = instr & 0x7F;
            // RISC-V NOP (addi x0, x0, 0 = 0x00000013)
            if instr == 0x00000013 {
                total_score -= 12;
            }
            // RISC-V RET (jalr x0, ra, 0 = 0x00008067)
            if instr == 0x00008067 {
                total_score -= 15;
            }
            // Common RISC-V opcodes: 0x03(LOAD), 0x13(OP-IMM), 0x23(STORE), 0x33(OP),
            //                        0x37(LUI), 0x63(BRANCH), 0x67(JALR), 0x6F(JAL)
            if matches!(rv_op, 0x03 | 0x13 | 0x23 | 0x33 | 0x37 | 0x63 | 0x67 | 0x6F) {
                total_score -= 2;
            }
        }

        // x86-64 patterns: REX prefix bytes followed by common opcodes
        {
            let b0 = (instr & 0xFF) as u8;
            let b1 = ((instr >> 8) & 0xFF) as u8;
            let b2 = ((instr >> 16) & 0xFF) as u8;
            let b3 = ((instr >> 24) & 0xFF) as u8;
            // REX + MOV/ADD/SUB/CMP patterns
            if (0x40..=0x4F).contains(&b0) && matches!(b1, 0x89 | 0x8B | 0x01 | 0x29 | 0x83 | 0x3B | 0x85 | 0x31 | 0x33 | 0x39 | 0x8D | 0x63)
            {
                total_score -= 5;
            }
            // PUSH rbp (0x55) + MOV rbp,rsp (0x48 0x89 0xE5): common prologue
            if b0 == 0x55 && b1 == 0x48 && b2 == 0x89 && b3 == 0xE5 {
                total_score -= 15;
                i += 4;
                continue;
            }
            // x86 CALL rel32 (0xE8)
            if b0 == 0xE8 {
                total_score -= 4;
            }
            // x86 RET (0xC3), INT3 (0xCC), NOP (0x90)
            if b0 == 0xC3 || b0 == 0xCC {
                total_score -= 4;
            }
            if b0 == 0x90 {
                total_score -= 2;
            }
            // x86 PUSH reg (0x50-0x57)
            if (0x50..=0x57).contains(&b0) {
                total_score -= 2;
            }
            // x86 LEAVE+RET (0xC9 0xC3)
            if b0 == 0xC9 && b1 == 0xC3 {
                total_score -= 8;
            }
        }

        // LoongArch patterns (little-endian, fixed 32-bit)
        {
            // LoongArch NOP = 0x03400000
            if instr == 0x03400000 {
                total_score -= 12;
            }
            // LoongArch RET = 0x4C000020
            if instr == 0x4C000020 {
                total_score -= 15;
            }
        }

        if format == Format::Unknown {
            // Check for NOP pattern
            if is_nop(instr) {
                valid_count += 1;
                total_score += 8;
            } else {
                invalid_count += 1;
            }
            i += 4;
            continue;
        }

        valid_count += 1;

        // Score based on instruction type - reduced scores to prevent false positives
        // i860 opcodes cover the full 6-bit space, so we need to be selective
        match format {
            Format::RType => {
                // ALU operations - only score specific known opcodes
                if matches!(
                    op,
                    opcode::ADD | opcode::ADDU | opcode::SUB | opcode::SUBU
                        | opcode::AND | opcode::SHL | opcode::SHR | opcode::SHRA
                ) {
                    total_score += 3;
                    // Validate register fields make sense
                    let src1 = extract_src1(instr);
                    let src2 = extract_src2(instr);
                    let dest = extract_dest(instr);
                    // Lots of zeros in register fields is suspicious
                    if src1 == 0 && src2 == 0 && dest == 0 {
                        total_score -= 2;
                    }
                }
            }
            Format::IType => {
                // Load/store - only give points for actual load/store opcodes
                if is_load(op) || is_store(op) {
                    total_score += 3;
                }
                // Other I-type: FP load/store range has lots of unused opcodes
                // Only give small score for known FP load/store
                else if matches!(op, opcode::FLD_S | opcode::FLD_D | opcode::FST_S | opcode::FST_D) {
                    total_score += 3;
                }
                // Unknown I-type in load/store ranges - no score
            }
            Format::Control => {
                // Branches and calls - distinctive
                if is_return(instr) {
                    total_score += 12;
                } else if op == opcode::CALL {
                    total_score += 8;
                } else if is_branch(op) {
                    total_score += 4;
                }
            }
            Format::Fpu => {
                // Check for patterns that look like AArch64 system instructions
                let top12 = instr >> 20;
                if top12 == 0xD53 || top12 == 0xD51 || top12 == 0xD50 {
                    total_score -= 8;
                    i += 4;
                    continue;
                }

                if (instr & 0xFFFF0000) == 0xD65F0000 || (instr & 0xFFFF0000) == 0xD69F0000 {
                    total_score -= 8;
                    i += 4;
                    continue;
                }

                // Only score highly specific FPU patterns
                // Pipelined FPU is very i860-specific
                if is_pipelined_fpu(instr) {
                    total_score += 8;
                }

                // Dual-mode toggle is distinctive
                if toggles_dual_mode(instr) {
                    total_score += 10;
                }

                // Graphics ops are very specific
                if is_graphics(op) {
                    total_score += 8;
                }

                // Common FP operations - small bonus only
                if matches!(op, opcode::FADD | opcode::FSUB | opcode::FMUL) {
                    total_score += 3;
                }

                // Reciprocal instructions are distinctive
                if matches!(op, opcode::FRCP | opcode::FRSQR) {
                    total_score += 5;
                }

                // Generic FPU: only +1 instead of +8
                if !is_pipelined_fpu(instr)
                    && !toggles_dual_mode(instr)
                    && !is_graphics(op)
                    && !matches!(
                        op,
                        opcode::FADD | opcode::FSUB | opcode::FMUL | opcode::FRCP | opcode::FRSQR
                    )
                {
                    total_score += 1;
                }
            }
            Format::Unknown => {}
        }

        i += 4;
    }

    // i860 opcode space covers ALL 64 possible 6-bit values, so every 32-bit word
    // is "valid". We must require structural evidence to confirm it's actually i860.
    // Without distinctive patterns (return, call, dual-mode, pipelined FPU),
    // the data is probably something else.
    {
        let total_instrs = valid_count + invalid_count;
        if total_instrs > 10 {
            // Look through data for truly i860-specific patterns.
            // Only count patterns that are VERY rare in random data:
            // - Returns (opcode 0x18 + src1=1): ~0.05% of random words
            // - Exact NOP (0xA0000000): ~0.00000002% of random words
            // - Dual-mode toggle (D-bit) on FPU WITHOUT P-bit: more specific
            // Do NOT count generic calls (1/64 too common) or pipelined FPU
            // (D-bit or P-bit covers ~18% of random words in FPU range)
            let mut distinctive_count = 0u32;
            let mut j = 0;
            while j + 3 < data.len() {
                let w = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
                if w != 0 && w != 0xFFFFFFFF {
                    let o = extract_opcode(w);
                    // i860 return: opcode 0x18, src1=r1 (very specific)
                    if is_return(w) { distinctive_count += 1; }
                    // Exact NOP
                    else if w == opcode::NOP { distinctive_count += 1; }
                    // Dual-mode toggle without pipeline (D=1, P=0) on specific FPU ops
                    else if matches!(o, opcode::FADD | opcode::FSUB | opcode::FMUL
                        | opcode::PFADD | opcode::PFSUB | opcode::PFMUL) {
                        if extract_d_bit(w) && !extract_p_bit(w) { distinctive_count += 1; }
                    }
                }
                j += 4;
            }
            if distinctive_count == 0 {
                // No truly i860-specific patterns at all
                total_score = (total_score as f64 * 0.08) as i64;
            }
        }
    }

    // Statistical ARM32 penalty: ARM code typically has >50% condition 0xE
    if arm_total_count > 10 {
        let al_ratio = arm_al_count as f64 / arm_total_count as f64;
        if al_ratio > 0.50 {
            total_score = (total_score as f64 * 0.15) as i64;
        } else if al_ratio > 0.30 {
            total_score = (total_score as f64 * 0.5) as i64;
        }
    }

    // Note: No validity ratio bonus. Since i860 opcodes cover ALL 64 possible
    // 6-bit values, the validity ratio is always ~100% and would give false bonuses.

    total_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_opcode() {
        // Opcode in bits 31-26
        let instr: u32 = 0x30 << 26; // FADD opcode
        assert_eq!(extract_opcode(instr), opcode::FADD);
    }

    #[test]
    fn test_instruction_format() {
        assert_eq!(instruction_format(opcode::ADD), Format::RType);
        assert_eq!(instruction_format(opcode::LD_W), Format::IType);
        assert_eq!(instruction_format(opcode::BR), Format::Control);
        assert_eq!(instruction_format(opcode::FADD), Format::Fpu);
    }

    #[test]
    fn test_is_branch() {
        assert!(is_branch(opcode::BR));
        assert!(is_branch(opcode::CALL));
        assert!(is_branch(opcode::BC));
        assert!(!is_branch(opcode::ADD));
    }

    #[test]
    fn test_is_nop() {
        assert!(is_nop(opcode::NOP));
        assert!(is_nop(0xA0000000));
        assert!(!is_nop(0x00000000));
    }

    #[test]
    fn test_score_basic() {
        // Simple sequence: ADD r1,r2,r3 pattern
        let mut code = Vec::new();
        // ADD opcode (0x10) in bits 31-26
        let add_instr: u32 = (opcode::ADD as u32) << 26 | (1 << 11) | (2 << 21) | (3 << 16);
        code.extend_from_slice(&add_instr.to_le_bytes());
        // NOP
        code.extend_from_slice(&opcode::NOP.to_le_bytes());

        let s = score(&code);
        assert!(s > 0, "Valid i860 code should score positive");
    }

    #[test]
    fn test_score_fpu() {
        // FPU instruction
        let mut code = Vec::new();
        let fadd: u32 = (opcode::FADD as u32) << 26;
        code.extend_from_slice(&fadd.to_le_bytes());

        let s = score(&code);
        assert!(s > 0, "FPU instruction should score positive");
    }

    #[test]
    fn test_score_return() {
        // Return pattern: BR r1 (indirect branch through link register)
        let mut code = Vec::new();
        let ret: u32 = (opcode::BR as u32) << 26 | (1 << 11); // src1 = r1
        code.extend_from_slice(&ret.to_le_bytes());

        let s = score(&code);
        assert!(s > 10, "Return instruction should score well");
    }
}
