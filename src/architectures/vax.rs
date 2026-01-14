//! VAX (DEC) architecture analysis.
//!
//! VAX uses variable-length CISC instructions from 1 to 37 bytes.
//! Features orthogonal addressing modes encoded consistently across instructions.
//! Big-endian byte order for multi-byte values.

/// VAX opcode constants.
pub mod opcode {
    // System/Control (0x00-0x0F)
    /// Halt processor.
    pub const HALT: u8 = 0x00;
    /// No operation.
    pub const NOP: u8 = 0x01;
    /// Return from exception/interrupt.
    pub const REI: u8 = 0x02;
    /// Breakpoint.
    pub const BPT: u8 = 0x03;
    /// Return from procedure.
    pub const RET: u8 = 0x04;
    /// Return from subroutine.
    pub const RSB: u8 = 0x05;
    /// Load process context.
    pub const LDPCTX: u8 = 0x06;
    /// Save process context.
    pub const SVPCTX: u8 = 0x07;
    /// Convert packed to string.
    pub const CVTPS: u8 = 0x08;
    /// Convert string to packed.
    pub const CVTSP: u8 = 0x09;
    /// Index calculation.
    pub const INDEX: u8 = 0x0A;
    /// CRC calculation.
    pub const CRC: u8 = 0x0B;
    /// Probe read access.
    pub const PROBER: u8 = 0x0C;
    /// Probe write access.
    pub const PROBEW: u8 = 0x0D;
    /// Insert into queue.
    pub const INSQUE: u8 = 0x0E;
    /// Remove from queue.
    pub const REMQUE: u8 = 0x0F;

    // Branches byte displacement (0x10-0x1F)
    /// Branch to subroutine (byte).
    pub const BSBB: u8 = 0x10;
    /// Branch (byte).
    pub const BRB: u8 = 0x11;
    /// Branch not equal.
    pub const BNEQ: u8 = 0x12;
    /// Branch equal.
    pub const BEQL: u8 = 0x13;
    /// Branch greater.
    pub const BGTR: u8 = 0x14;
    /// Branch less or equal.
    pub const BLEQ: u8 = 0x15;
    /// Jump to subroutine.
    pub const JSB: u8 = 0x16;
    /// Jump.
    pub const JMP: u8 = 0x17;
    /// Branch greater or equal.
    pub const BGEQ: u8 = 0x18;
    /// Branch less.
    pub const BLSS: u8 = 0x19;
    /// Branch greater unsigned.
    pub const BGTRU: u8 = 0x1A;
    /// Branch less or equal unsigned.
    pub const BLEQU: u8 = 0x1B;
    /// Branch overflow clear.
    pub const BVC: u8 = 0x1C;
    /// Branch overflow set.
    pub const BVS: u8 = 0x1D;
    /// Branch carry clear.
    pub const BCC: u8 = 0x1E;
    /// Branch carry set.
    pub const BCS: u8 = 0x1F;

    // Word branches (0x30-0x3F)
    /// Branch word.
    pub const BRW: u8 = 0x31;
    /// Branch to subroutine word.
    pub const BSBW: u8 = 0x30;

    // Byte operations (0x80-0x9F)
    /// Add byte 2-operand.
    pub const ADDB2: u8 = 0x80;
    /// Add byte 3-operand.
    pub const ADDB3: u8 = 0x81;
    /// Subtract byte 2-operand.
    pub const SUBB2: u8 = 0x82;
    /// Subtract byte 3-operand.
    pub const SUBB3: u8 = 0x83;
    /// Multiply byte 2-operand.
    pub const MULB2: u8 = 0x84;
    /// Multiply byte 3-operand.
    pub const MULB3: u8 = 0x85;
    /// Divide byte 2-operand.
    pub const DIVB2: u8 = 0x86;
    /// Divide byte 3-operand.
    pub const DIVB3: u8 = 0x87;
    /// Bit set byte 2-operand.
    pub const BISB2: u8 = 0x88;
    /// Bit set byte 3-operand.
    pub const BISB3: u8 = 0x89;
    /// Bit clear byte 2-operand.
    pub const BICB2: u8 = 0x8A;
    /// Bit clear byte 3-operand.
    pub const BICB3: u8 = 0x8B;
    /// XOR byte 2-operand.
    pub const XORB2: u8 = 0x8C;
    /// XOR byte 3-operand.
    pub const XORB3: u8 = 0x8D;
    /// Move negated byte.
    pub const MNEGB: u8 = 0x8E;
    /// Case byte.
    pub const CASEB: u8 = 0x8F;
    /// Move byte.
    pub const MOVB: u8 = 0x90;
    /// Compare byte.
    pub const CMPB: u8 = 0x91;
    /// Move complemented byte.
    pub const MCOMB: u8 = 0x92;
    /// Bit test byte.
    pub const BITB: u8 = 0x93;
    /// Clear byte.
    pub const CLRB: u8 = 0x94;
    /// Test byte.
    pub const TSTB: u8 = 0x95;
    /// Increment byte.
    pub const INCB: u8 = 0x96;
    /// Decrement byte.
    pub const DECB: u8 = 0x97;

    // Word operations (0xA0-0xBF)
    /// Add word 2-operand.
    pub const ADDW2: u8 = 0xA0;
    /// Move word.
    pub const MOVW: u8 = 0xB0;
    /// Compare word.
    pub const CMPW: u8 = 0xB1;
    /// Clear word.
    pub const CLRW: u8 = 0xB4;
    /// Test word.
    pub const TSTW: u8 = 0xB5;

    // Longword operations (0xC0-0xDF)
    /// Add longword 2-operand.
    pub const ADDL2: u8 = 0xC0;
    /// Add longword 3-operand.
    pub const ADDL3: u8 = 0xC1;
    /// Subtract longword 2-operand.
    pub const SUBL2: u8 = 0xC2;
    /// Subtract longword 3-operand.
    pub const SUBL3: u8 = 0xC3;
    /// Multiply longword 2-operand.
    pub const MULL2: u8 = 0xC4;
    /// Multiply longword 3-operand.
    pub const MULL3: u8 = 0xC5;
    /// Divide longword 2-operand.
    pub const DIVL2: u8 = 0xC6;
    /// Divide longword 3-operand.
    pub const DIVL3: u8 = 0xC7;
    /// Move longword.
    pub const MOVL: u8 = 0xD0;
    /// Compare longword.
    pub const CMPL: u8 = 0xD1;
    /// Clear longword.
    pub const CLRL: u8 = 0xD4;
    /// Test longword.
    pub const TSTL: u8 = 0xD5;
    /// Push longword.
    pub const PUSHL: u8 = 0xDD;

    // Bit field/branches (0xE0-0xF9)
    /// Branch on bit set.
    pub const BBS: u8 = 0xE0;
    /// Branch on bit clear.
    pub const BBC: u8 = 0xE1;
    /// Find first set bit.
    pub const FFS: u8 = 0xEA;
    /// Find first clear bit.
    pub const FFC: u8 = 0xEB;
    /// Compare field.
    pub const CMPV: u8 = 0xEC;
    /// Compare zero-extended field.
    pub const CMPZV: u8 = 0xED;
    /// Extract field.
    pub const EXTV: u8 = 0xEE;
    /// Extract zero-extended field.
    pub const EXTZV: u8 = 0xEF;
    /// Insert field.
    pub const INSV: u8 = 0xF0;
    /// Add compare and branch longword.
    pub const ACBL: u8 = 0xF1;
    /// Add one and branch less.
    pub const AOBLSS: u8 = 0xF2;
    /// Add one and branch less or equal.
    pub const AOBLEQ: u8 = 0xF3;
    /// Subtract one and branch greater or equal.
    pub const SOBGEQ: u8 = 0xF4;
    /// Subtract one and branch greater.
    pub const SOBGTR: u8 = 0xF5;

    // Escape prefixes (0xFC-0xFF)
    /// Extended function call.
    pub const XFC: u8 = 0xFC;
    /// G/H floating-point extended prefix.
    pub const ESCAPE_FD: u8 = 0xFD;
    /// Reserved prefix.
    pub const ESCAPE_FE: u8 = 0xFE;
    /// Customer-defined prefix.
    pub const ESCAPE_FF: u8 = 0xFF;

    // Addressing modes (high nibble of operand specifier)
    /// Literal mode (0-3).
    pub const MODE_LITERAL: u8 = 0x00;
    /// Indexed mode.
    pub const MODE_INDEXED: u8 = 0x40;
    /// Register mode.
    pub const MODE_REGISTER: u8 = 0x50;
    /// Register deferred.
    pub const MODE_REG_DEFERRED: u8 = 0x60;
    /// Autodecrement.
    pub const MODE_AUTODEC: u8 = 0x70;
    /// Autoincrement.
    pub const MODE_AUTOINC: u8 = 0x80;
    /// Autoincrement deferred.
    pub const MODE_AUTOINC_DEF: u8 = 0x90;
    /// Byte displacement.
    pub const MODE_BYTE_DISP: u8 = 0xA0;
    /// Byte displacement deferred.
    pub const MODE_BYTE_DISP_DEF: u8 = 0xB0;
    /// Word displacement.
    pub const MODE_WORD_DISP: u8 = 0xC0;
    /// Word displacement deferred.
    pub const MODE_WORD_DISP_DEF: u8 = 0xD0;
    /// Long displacement.
    pub const MODE_LONG_DISP: u8 = 0xE0;
    /// Long displacement deferred.
    pub const MODE_LONG_DISP_DEF: u8 = 0xF0;
}

/// Get the number of operands for an opcode.
pub fn operand_count(op: u8) -> usize {
    match op {
        // No operands
        opcode::HALT | opcode::NOP | opcode::REI | opcode::BPT | opcode::RET | opcode::RSB => 0,

        // One operand
        opcode::JMP
        | opcode::CLRB
        | opcode::CLRW
        | opcode::CLRL
        | opcode::TSTB
        | opcode::TSTW
        | opcode::TSTL
        | opcode::INCB
        | opcode::DECB
        | opcode::PUSHL => 1,

        // Branches with one byte displacement
        opcode::BSBB
        | opcode::BRB
        | opcode::BNEQ
        | opcode::BEQL
        | opcode::BGTR
        | opcode::BLEQ
        | opcode::BGEQ
        | opcode::BLSS
        | opcode::BGTRU
        | opcode::BLEQU
        | opcode::BVC
        | opcode::BVS
        | opcode::BCC
        | opcode::BCS => 0, // Displacement is inline, not an operand specifier

        // Word branch
        opcode::BRW | opcode::BSBW => 0, // Word displacement inline

        // Two operands
        opcode::MOVB
        | opcode::MOVW
        | opcode::MOVL
        | opcode::CMPB
        | opcode::CMPW
        | opcode::CMPL
        | opcode::ADDB2
        | opcode::ADDW2
        | opcode::ADDL2
        | opcode::SUBB2
        | opcode::SUBL2
        | opcode::MULB2
        | opcode::MULL2
        | opcode::DIVB2
        | opcode::DIVL2
        | opcode::BISB2
        | opcode::BICB2
        | opcode::XORB2
        | opcode::BITB
        | opcode::MCOMB
        | opcode::MNEGB
        | opcode::JSB => 2,

        // Three operands
        opcode::ADDB3
        | opcode::ADDL3
        | opcode::SUBB3
        | opcode::SUBL3
        | opcode::MULB3
        | opcode::MULL3
        | opcode::DIVB3
        | opcode::DIVL3
        | opcode::BISB3
        | opcode::BICB3
        | opcode::XORB3
        | opcode::CASEB => 3,

        // Escape prefix - depends on second byte
        opcode::ESCAPE_FD | opcode::ESCAPE_FE | opcode::ESCAPE_FF => 0,

        // Default: assume 2 operands for unknown
        _ => 2,
    }
}

/// Get the size of an operand specifier in bytes.
///
/// Returns (specifier_size, extension_size).
pub fn operand_size(specifier: u8) -> usize {
    let mode = specifier & 0xF0;
    let reg = specifier & 0x0F;

    match mode {
        // Literal (0x00-0x3F) - 6-bit literal, no extension
        0x00 | 0x10 | 0x20 | 0x30 => 1,

        // Indexed - need another specifier
        opcode::MODE_INDEXED => 1, // Plus recursive base specifier

        // Register, Register Deferred, Autodecrement, Autoincrement - no extension
        opcode::MODE_REGISTER
        | opcode::MODE_REG_DEFERRED
        | opcode::MODE_AUTODEC
        | opcode::MODE_AUTOINC => 1,

        // Autoincrement with PC (0x8F) = Immediate
        // Size depends on data type, assume 4 for longword
        _ if specifier == 0x8F => 5, // specifier + 4 bytes

        // Autoincrement deferred with PC (0x9F) = Absolute
        _ if specifier == 0x9F => 5, // specifier + 4 bytes address

        // Byte displacement (with PC = byte relative)
        opcode::MODE_BYTE_DISP | opcode::MODE_BYTE_DISP_DEF => 2, // specifier + 1 byte

        // Word displacement
        opcode::MODE_WORD_DISP | opcode::MODE_WORD_DISP_DEF => 3, // specifier + 2 bytes

        // Long displacement
        opcode::MODE_LONG_DISP | opcode::MODE_LONG_DISP_DEF => 5, // specifier + 4 bytes

        // Default
        _ => 1,
    }
}

/// Check if opcode is a return instruction.
pub fn is_return(op: u8) -> bool {
    matches!(op, opcode::RET | opcode::RSB | opcode::REI)
}

/// Check if opcode is a branch instruction.
pub fn is_branch(op: u8) -> bool {
    matches!(
        op,
        opcode::BSBB
            | opcode::BRB
            | opcode::BRW
            | opcode::BSBW
            | opcode::BNEQ
            | opcode::BEQL
            | opcode::BGTR
            | opcode::BLEQ
            | opcode::BGEQ
            | opcode::BLSS
            | opcode::BGTRU
            | opcode::BLEQU
            | opcode::BVC
            | opcode::BVS
            | opcode::BCC
            | opcode::BCS
            | opcode::JMP
            | opcode::JSB
    )
}

/// Check if opcode is an ALU operation.
pub fn is_alu(op: u8) -> bool {
    matches!(
        op,
        opcode::ADDB2..=opcode::XORB3
            | opcode::ADDW2
            | opcode::ADDL2..=opcode::DIVL3
    )
}

/// Check if opcode is a move operation.
pub fn is_move(op: u8) -> bool {
    matches!(op, opcode::MOVB | opcode::MOVW | opcode::MOVL)
}

/// Check if opcode is a compare operation.
pub fn is_compare(op: u8) -> bool {
    matches!(op, opcode::CMPB | opcode::CMPW | opcode::CMPL)
}

/// Check if opcode is a test operation.
pub fn is_test(op: u8) -> bool {
    matches!(op, opcode::TSTB | opcode::TSTW | opcode::TSTL)
}

/// Check if opcode is an escape prefix.
pub fn is_escape(op: u8) -> bool {
    matches!(
        op,
        opcode::ESCAPE_FD | opcode::ESCAPE_FE | opcode::ESCAPE_FF | opcode::XFC
    )
}

/// Estimate instruction length.
///
/// This is a heuristic estimate based on opcode and operand count.
pub fn estimate_instruction_length(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }

    let op = data[0];

    // Handle escape prefixes
    if is_escape(op) {
        if data.len() < 2 {
            return 0;
        }
        // Extended opcode - assume similar to base opcode
        return 2 + operand_count(data[1]) * 2;
    }

    // Simple branches (inline displacement)
    match op {
        opcode::BSBB
        | opcode::BRB
        | opcode::BNEQ
        | opcode::BEQL
        | opcode::BGTR
        | opcode::BLEQ
        | opcode::BGEQ
        | opcode::BLSS
        | opcode::BGTRU
        | opcode::BLEQU
        | opcode::BVC
        | opcode::BVS
        | opcode::BCC
        | opcode::BCS => return 2, // opcode + byte displacement

        opcode::BRW | opcode::BSBW => return 3, // opcode + word displacement

        opcode::HALT | opcode::NOP | opcode::REI | opcode::BPT | opcode::RET | opcode::RSB => {
            return 1
        }

        _ => {}
    }

    // Calculate based on operand count
    let num_ops = operand_count(op);
    if num_ops == 0 {
        return 1;
    }

    // Estimate: opcode + operands
    // Average operand is ~2 bytes
    let mut len = 1;
    let mut pos = 1;

    for _ in 0..num_ops {
        if pos >= data.len() {
            break;
        }
        let spec_size = operand_size(data[pos]);
        len += spec_size;
        pos += spec_size;
    }

    len.min(37) // VAX max instruction length
}

/// Score likelihood of VAX code.
///
/// Analyzes raw bytes for patterns characteristic of VAX:
/// - Valid opcode sequences
/// - Consistent operand specifier patterns
/// - Common instruction sequences
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 2 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut i = 0;
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;

    while i < data.len() {
        let op = data[i];
        let len = estimate_instruction_length(&data[i..]);

        if len == 0 {
            invalid_count += 1;
            i += 1;
            continue;
        }

        if i + len > data.len() {
            break;
        }

        valid_count += 1;

        // Score based on instruction type
        match op {
            // Very strong indicators
            opcode::RET | opcode::RSB => total_score += 15,
            opcode::NOP => total_score += 8,
            opcode::HALT => total_score += 5, // Less common but distinctive

            // Common branches
            opcode::BNEQ | opcode::BEQL => total_score += 8,
            opcode::BGTR | opcode::BLEQ | opcode::BGEQ | opcode::BLSS => total_score += 6,
            opcode::BRB | opcode::BRW => total_score += 5,
            opcode::JSB | opcode::BSBB | opcode::BSBW => total_score += 7,

            // Common data movement
            opcode::MOVL => total_score += 8,
            opcode::MOVB | opcode::MOVW => total_score += 6,
            opcode::PUSHL => total_score += 7,

            // Common ALU
            opcode::ADDL2 | opcode::ADDL3 => total_score += 6,
            opcode::SUBL2 | opcode::SUBL3 => total_score += 6,
            opcode::CMPL => total_score += 7,

            // Test operations
            opcode::TSTL | opcode::TSTB | opcode::TSTW => total_score += 5,

            // Clear operations
            opcode::CLRL | opcode::CLRB | opcode::CLRW => total_score += 4,

            // Loop constructs (very VAX-specific)
            opcode::SOBGEQ | opcode::SOBGTR => total_score += 10,
            opcode::AOBLSS | opcode::AOBLEQ | opcode::ACBL => total_score += 10,

            // Bit field operations (distinctive)
            opcode::BBS | opcode::BBC => total_score += 8,
            opcode::EXTV | opcode::EXTZV | opcode::INSV => total_score += 9,

            // Extended opcodes
            opcode::ESCAPE_FD => {
                // G/H floating point - strong indicator
                total_score += 12;
            }

            // Byte/word operations (common in real code)
            op if (0x80..=0x9F).contains(&op) => total_score += 4,
            op if (0xA0..=0xBF).contains(&op) => total_score += 4,
            op if (0xC0..=0xDF).contains(&op) => total_score += 5,

            _ => {
                // Unknown but might be valid
                total_score += 1;
            }
        }

        i += len;
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
    fn test_operand_count() {
        assert_eq!(operand_count(opcode::NOP), 0);
        assert_eq!(operand_count(opcode::RET), 0);
        assert_eq!(operand_count(opcode::RSB), 0);
        assert_eq!(operand_count(opcode::CLRL), 1);
        assert_eq!(operand_count(opcode::MOVL), 2);
        assert_eq!(operand_count(opcode::ADDL3), 3);
    }

    #[test]
    fn test_is_return() {
        assert!(is_return(opcode::RET));
        assert!(is_return(opcode::RSB));
        assert!(is_return(opcode::REI));
        assert!(!is_return(opcode::NOP));
    }

    #[test]
    fn test_is_branch() {
        assert!(is_branch(opcode::BNEQ));
        assert!(is_branch(opcode::BRB));
        assert!(is_branch(opcode::JSB));
        assert!(is_branch(opcode::JMP));
        assert!(!is_branch(opcode::NOP));
    }

    #[test]
    fn test_estimate_instruction_length() {
        // NOP
        let nop = [opcode::NOP];
        assert_eq!(estimate_instruction_length(&nop), 1);

        // RSB
        let rsb = [opcode::RSB];
        assert_eq!(estimate_instruction_length(&rsb), 1);

        // BRB with displacement
        let brb = [opcode::BRB, 0x10];
        assert_eq!(estimate_instruction_length(&brb), 2);

        // BRW with word displacement
        let brw = [opcode::BRW, 0x00, 0x10];
        assert_eq!(estimate_instruction_length(&brw), 3);
    }

    #[test]
    fn test_score_basic() {
        // Simple sequence: NOP, NOP, RSB
        let code = [opcode::NOP, opcode::NOP, opcode::RSB];
        let s = score(&code);
        assert!(s > 0, "Valid VAX code should score positive");
    }

    #[test]
    fn test_score_branch_pattern() {
        // BRB +4, NOP, NOP, RSB
        let code = [opcode::BRB, 0x03, opcode::NOP, opcode::NOP, opcode::RSB];
        let s = score(&code);
        assert!(s > 10, "Branch + return should score well");
    }

    #[test]
    fn test_score_mov_pattern() {
        // MOVL with register mode
        let code = [
            opcode::MOVL,
            0x50, // Register R0
            0x51, // Register R1
            opcode::RSB,
        ];
        let s = score(&code);
        assert!(s > 15, "MOVL + RSB should score well");
    }
}
