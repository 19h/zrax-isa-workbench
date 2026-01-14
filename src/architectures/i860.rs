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
    // NOP is encoded as specific trap-never pattern
    instr == opcode::NOP || (instr & 0xFC000000) == 0xA0000000
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

    // i860 is little-endian, 4-byte aligned
    let mut i = 0;
    while i + 3 < data.len() {
        let instr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let op = extract_opcode(instr);
        let format = instruction_format(op);

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

        // Score based on instruction type
        match format {
            Format::RType => {
                // ALU operations
                if is_alu(op) {
                    total_score += 5;
                    // Common ALU ops score higher
                    if matches!(
                        op,
                        opcode::ADD | opcode::ADDU | opcode::SUB | opcode::AND | opcode::SHL
                    ) {
                        total_score += 3;
                    }
                }
            }
            Format::IType => {
                // Load/store
                if is_load(op) {
                    total_score += 6;
                } else if is_store(op) {
                    total_score += 6;
                } else {
                    total_score += 4;
                }
            }
            Format::Control => {
                // Branches and calls
                if is_return(instr) {
                    total_score += 15; // Strong indicator
                } else if op == opcode::CALL {
                    total_score += 10;
                } else if is_branch(op) {
                    total_score += 6;
                }
            }
            Format::Fpu => {
                // FPU operations - distinctive for i860
                total_score += 8;

                // Pipelined FPU is very i860-specific
                if is_pipelined_fpu(instr) {
                    total_score += 5;
                }

                // Dual-mode toggle is distinctive
                if toggles_dual_mode(instr) {
                    total_score += 8;
                }

                // Graphics ops are very specific
                if is_graphics(op) {
                    total_score += 10;
                }

                // Common FP operations
                if matches!(op, opcode::FADD | opcode::FSUB | opcode::FMUL) {
                    total_score += 3;
                }

                // Reciprocal instructions are distinctive
                if matches!(op, opcode::FRCP | opcode::FRSQR) {
                    total_score += 5;
                }
            }
            Format::Unknown => {}
        }

        // Check for r0 usage (always zero, common pattern)
        let src1 = extract_src1(instr);
        let src2 = extract_src2(instr);
        let dest = extract_dest(instr);

        if src1 == 0 || src2 == 0 {
            total_score += 1; // Common to use r0 as zero source
        }
        if dest == 0 && !is_branch(op) {
            // Writing to r0 is unusual (discards result)
            total_score -= 2;
        }

        i += 4;
    }

    // Adjust based on validity ratio
    if valid_count + invalid_count > 0 {
        let validity_ratio = valid_count as f64 / (valid_count + invalid_count) as f64;
        total_score = (total_score as f64 * validity_ratio) as i64;

        // Bonus for high validity
        if validity_ratio > 0.80 && valid_count > 10 {
            total_score += 15;
        }
    }

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
        assert!(s > 5, "FPU instruction should score well");
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
