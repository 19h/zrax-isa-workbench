//! Blackfin DSP architecture analysis (Analog Devices).
//!
//! Blackfin uses variable-length instructions (16, 32, or 64 bits).
//! 64-bit format enables multi-issue execution of up to three operations.
//! Little-endian byte order within each word.

/// Blackfin opcode constants and ranges.
pub mod opcode {
    // 16-bit opcode ranges (upper nibble)
    /// System control, NOP, returns (0x0xxx).
    pub const SYSTEM_CONTROL_MASK: u16 = 0xF000;
    /// System control range.
    pub const SYSTEM_CONTROL: u16 = 0x0000;
    /// Conditional branches (0x1xxx).
    pub const COND_BRANCH: u16 = 0x1000;
    /// Short jumps JUMP.S (0x2xxx).
    pub const SHORT_JUMP: u16 = 0x2000;
    /// Short calls CALL.S (0x3xxx).
    pub const SHORT_CALL: u16 = 0x3000;
    /// ALU operations (0x4xxx).
    pub const ALU_OPS: u16 = 0x4000;
    /// Pointer/register arithmetic (0x5xxx).
    pub const PTR_ARITH: u16 = 0x5000;
    /// Load/store with Preg/Ireg (0x9xxx).
    pub const LOAD_STORE_16: u16 = 0x9000;

    // 32-bit opcode prefixes (high byte)
    /// MAC/DSP multiply-accumulate (0xC0).
    pub const MAC_DSP: u8 = 0xC0;
    /// Dual MAC operations (0xC1).
    pub const DUAL_MAC: u8 = 0xC1;
    /// Vector ALU (0xC2).
    pub const VECTOR_ALU: u8 = 0xC2;
    /// Bit manipulation (0xC6).
    pub const BIT_MANIP: u8 = 0xC6;
    /// Video pixel operations (0xC8).
    pub const VIDEO_PIXEL: u8 = 0xC8;
    /// SAA operations (0xC9).
    pub const SAA_OPS: u8 = 0xC9;
    /// Load/store with large offset (0xE0).
    pub const LOAD_STORE_32: u8 = 0xE0;
    /// Long jump JUMP.L (0xE2).
    pub const LONG_JUMP: u8 = 0xE2;
    /// Long call CALL.L (0xE3).
    pub const LONG_CALL: u8 = 0xE3;

    // Common 16-bit instructions
    /// NOP (no operation).
    pub const NOP: u16 = 0x0000;
    /// RTS (return from subroutine).
    pub const RTS: u16 = 0x0010;
    /// RTI (return from interrupt).
    pub const RTI: u16 = 0x0011;
    /// RTX (return from exception).
    pub const RTX: u16 = 0x0012;
    /// RTN (return from NMI).
    pub const RTN: u16 = 0x0013;
    /// RTE (return from emulation).
    pub const RTE: u16 = 0x0014;
    /// IDLE instruction.
    pub const IDLE: u16 = 0x0020;
    /// CSYNC (core synchronize).
    pub const CSYNC: u16 = 0x0023;
    /// SSYNC (system synchronize).
    pub const SSYNC: u16 = 0x0024;
    /// EMUEXCPT (emulator exception).
    pub const EMUEXCPT: u16 = 0x0025;

    // Register encodings
    /// Data registers R0-R7 (3-bit: 000-111).
    pub const REG_R0: u8 = 0;
    pub const REG_R7: u8 = 7;
    /// Pointer registers P0-P5, SP, FP (3-bit).
    pub const REG_P0: u8 = 0;
    pub const REG_P5: u8 = 5;
    pub const REG_SP: u8 = 6;
    pub const REG_FP: u8 = 7;
}

/// Determine if a 16-bit word is a 32-bit instruction prefix.
///
/// 32-bit instructions have specific high-byte patterns.
fn is_32bit_prefix(high_byte: u8) -> bool {
    matches!(
        high_byte,
        0xC0..=0xCF | 0xE0..=0xE7
    )
}

/// Determine if this starts a 64-bit parallel packet.
///
/// 64-bit packets combine a 32-bit DSP instruction with two 16-bit loads.
fn is_64bit_packet_start(word: u16) -> bool {
    // 64-bit packets are indicated by specific bit patterns
    // that mark parallel issue slots
    let high = (word >> 8) as u8;
    // Multi-issue packets typically start with MAC/DSP ops
    matches!(high, 0xC0..=0xC3)
}

/// Estimate instruction length in bytes.
///
/// Returns 2, 4, or 8 based on the instruction word.
pub fn instruction_length(data: &[u8]) -> usize {
    if data.len() < 2 {
        return 0;
    }

    let word = u16::from_le_bytes([data[0], data[1]]);
    let high_byte = (word >> 8) as u8;

    // Check for 32-bit instruction
    if is_32bit_prefix(high_byte) {
        if data.len() < 4 {
            return 0;
        }
        // Check if this is a 64-bit packet (32-bit + 16-bit + 16-bit)
        if is_64bit_packet_start(word) && data.len() >= 8 {
            // 64-bit multi-issue packet
            return 8;
        }
        return 4;
    }

    // 16-bit instruction
    2
}

/// Check if instruction is a return.
pub fn is_return(word: u16) -> bool {
    matches!(
        word,
        opcode::RTS | opcode::RTI | opcode::RTX | opcode::RTN | opcode::RTE
    )
}

/// Check if instruction is a branch/jump.
pub fn is_branch(word: u16) -> bool {
    let range = word & opcode::SYSTEM_CONTROL_MASK;
    matches!(
        range,
        opcode::COND_BRANCH | opcode::SHORT_JUMP | opcode::SHORT_CALL
    )
}

/// Check if instruction is a NOP or sync.
pub fn is_nop_or_sync(word: u16) -> bool {
    matches!(
        word,
        opcode::NOP | opcode::IDLE | opcode::CSYNC | opcode::SSYNC
    )
}

/// Check if 32-bit instruction is a MAC operation.
pub fn is_mac_instruction(high_byte: u8) -> bool {
    matches!(high_byte, opcode::MAC_DSP | opcode::DUAL_MAC)
}

/// Check if 32-bit instruction is a load/store.
pub fn is_load_store_32(high_byte: u8) -> bool {
    high_byte == opcode::LOAD_STORE_32
}

/// Check if 32-bit instruction is a long branch.
pub fn is_long_branch(high_byte: u8) -> bool {
    matches!(high_byte, opcode::LONG_JUMP | opcode::LONG_CALL)
}

/// Check if 16-bit instruction is a load/store.
pub fn is_load_store_16(word: u16) -> bool {
    (word & opcode::SYSTEM_CONTROL_MASK) == opcode::LOAD_STORE_16
}

/// Check if instruction is ALU operation.
pub fn is_alu_16(word: u16) -> bool {
    (word & opcode::SYSTEM_CONTROL_MASK) == opcode::ALU_OPS
}

/// Check if instruction is pointer arithmetic.
pub fn is_ptr_arith(word: u16) -> bool {
    (word & opcode::SYSTEM_CONTROL_MASK) == opcode::PTR_ARITH
}

/// Score likelihood of Blackfin code.
///
/// Analyzes raw bytes for patterns characteristic of Blackfin:
/// - Variable-length instruction encoding
/// - DSP-specific MAC instructions
/// - Register-based operations
/// - Parallel execution packets
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 4 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut i = 0;
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;
    let mut zero_run: u32 = 0;

    // Cross-architecture penalties for 32-bit BE patterns
    // Blackfin is LE; data from BE 32-bit ISAs should be penalized
    {
        let mut j = 0;
        while j + 3 < data.len() {
            let be32 = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            // MIPS
            if be32 == 0x03E00008 { total_score -= 20; } // MIPS JR $ra
            if be32 == 0x00000000 { total_score -= 3; }   // MIPS NOP (also all-zero)
            if (be32 & 0xFFFF0000) == 0x27BD0000 { total_score -= 10; } // MIPS ADDIU $sp
            if (be32 & 0xFC000000) == 0x0C000000 { total_score -= 5; }  // MIPS JAL
            // SPARC
            if be32 == 0x81C7E008 { total_score -= 15; } // SPARC RET
            if be32 == 0x01000000 { total_score -= 12; } // SPARC NOP
            // PPC
            if be32 == 0x4E800020 { total_score -= 15; } // PPC BLR
            if be32 == 0x60000000 { total_score -= 12; } // PPC NOP
            j += 4;
        }
    }

    // Cross-architecture penalties for 32-bit LE patterns
    {
        let mut j = 0;
        while j + 3 < data.len() {
            let le32 = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            // Hexagon duplex patterns
            if (le32 & 0x0000C000) == 0x0000C000 && (le32 & 0xF0000000) != 0 {
                // End-of-packet marker + non-zero iclass — common Hexagon
                // Only penalize if it looks like a valid Hexagon instruction class
                let iclass = (le32 >> 28) as u8;
                if iclass <= 0xB { total_score -= 2; }
            }
            // LoongArch
            if le32 == 0x4C000020 { total_score -= 12; } // LoongArch JIRL ra (RET)
            if le32 == 0x03400000 { total_score -= 10; } // LoongArch NOP
            // LoongArch BL (top6 = 0x15 = 010101)
            if (le32 >> 26) == 0x15 { total_score -= 5; }
            // LoongArch PCADDU12I (top7 = 0x0E)
            if (le32 >> 25) == 0x0E { total_score -= 3; }
            // LoongArch B (branch, top6 = 0x14)
            if (le32 >> 26) == 0x14 { total_score -= 3; }
            // LoongArch ADDI.D (top10 = 0x00B) - very common in prologues
            if (le32 >> 22) & 0x3FF == 0x00B { total_score -= 3; }
            // LoongArch ST.D (top10 = 0x0A7) - store in prologue
            if (le32 >> 22) & 0x3FF == 0x0A7 { total_score -= 3; }
            // LoongArch LD.D (top10 = 0x0A3) - load in epilogue
            if (le32 >> 22) & 0x3FF == 0x0A3 { total_score -= 3; }
            // RISC-V
            if le32 == 0x00000013 { total_score -= 10; } // RISC-V NOP
            if le32 == 0x00008067 { total_score -= 12; } // RISC-V RET

            // AArch64 patterns (LE)
            if le32 == 0xD65F03C0 { total_score -= 12; } // AArch64 RET
            if le32 == 0xD503201F { total_score -= 10; } // AArch64 NOP

            j += 4;
        }
    }

    while i + 1 < data.len() {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);

        // Handle zero words - NOP/padding, don't reward
        if word == 0x0000 {
            zero_run += 1;
            if zero_run > 4 {
                total_score -= 2; // Penalize long zero runs (padding)
            }
            i += 2;
            continue;
        } else {
            zero_run = 0;
        }

        let high_byte = (word >> 8) as u8;
        let instr_len = instruction_length(&data[i..]);

        if instr_len == 0 {
            invalid_count += 1;
            i += 2;
            continue;
        }

        if i + instr_len > data.len() {
            break;
        }

        valid_count += 1;

        // Score based on instruction type
        if instr_len == 2 {
            // 16-bit instructions
            if is_return(word) {
                total_score += 15; // Returns are strong indicators
            } else if word == opcode::NOP {
                // NOP is 0x0000 which we handle above
                total_score += 5;
            } else if is_nop_or_sync(word) {
                total_score += 8; // Sync instructions are DSP-specific
            } else if is_branch(word) {
                total_score += 2; // Broad: 18.75% of space
            } else if is_load_store_16(word) {
                total_score += 1; // Broad: 6.25% of space
            } else if is_alu_16(word) {
                total_score += 1; // Broad: 6.25% of space
            } else if is_ptr_arith(word) {
                total_score += 2; // Broad: 6.25% of space
            } else {
                // Unrecognized 16-bit halfword
                total_score -= 1;
            }
        } else if instr_len == 4 {
            // 32-bit instructions - only score specific known patterns
            if high_byte == opcode::DUAL_MAC {
                total_score += 15; // Dual MAC is very specific
            } else if is_mac_instruction(high_byte) {
                total_score += 10; // MAC ops are DSP-specific
            } else if high_byte == opcode::VECTOR_ALU {
                total_score += 8;
            } else if high_byte == opcode::VIDEO_PIXEL {
                total_score += 12; // Video ops are specific
            } else if high_byte == opcode::SAA_OPS {
                total_score += 12; // SAA is specific
            } else if is_long_branch(high_byte) {
                total_score += 5;
            } else if is_load_store_32(high_byte) {
                total_score += 3;
            } else if high_byte == opcode::BIT_MANIP {
                total_score += 5;
            } else if matches!(high_byte, 0xC0..=0xCF) {
                total_score += 1; // Other DSP ops - minimal score
            } else if matches!(high_byte, 0xE0..=0xE7) {
                total_score += 1; // Other 32-bit ops - minimal score
            }
        } else if instr_len == 8 {
            // 64-bit parallel packet - very strong indicator
            total_score += 20;
        }

        i += instr_len;
    }

    // Structural requirement: real Blackfin code must have distinctive patterns
    // Scan for returns, sync instructions, and DSP-specific ops
    let mut has_returns = false;
    let mut has_sync = false;
    let mut has_dsp = false;
    {
        let mut j = 0;
        while j + 1 < data.len() {
            let w = u16::from_le_bytes([data[j], data[j + 1]]);
            if is_return(w) { has_returns = true; }
            if matches!(w, opcode::CSYNC | opcode::SSYNC | opcode::EMUEXCPT) { has_sync = true; }
            // Check for 32-bit DSP instructions
            let hb = (w >> 8) as u8;
            if j + 3 < data.len() && is_32bit_prefix(hb) {
                if is_mac_instruction(hb) || hb == opcode::DUAL_MAC
                    || hb == opcode::VIDEO_PIXEL || hb == opcode::SAA_OPS
                {
                    has_dsp = true;
                }
                j += 4;
            } else {
                j += 2;
            }
        }
    }

    let mut structural_penalty = false;
    if valid_count > 20 && !has_returns && !has_sync && !has_dsp {
        total_score = (total_score as f64 * 0.15) as i64;
        structural_penalty = true;
    }

    // Adjust based on validity ratio
    if valid_count + invalid_count > 0 {
        let validity_ratio = valid_count as f64 / (valid_count + invalid_count) as f64;
        total_score = (total_score as f64 * validity_ratio) as i64;

        // Bonus for high validity — only when structural requirement passed
        if !structural_penalty && validity_ratio > 0.80 && valid_count > 10 {
            total_score += 15;
        }
    }

    total_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_length() {
        // 16-bit NOP
        let nop = [0x00, 0x00];
        assert_eq!(instruction_length(&nop), 2);

        // 32-bit MAC instruction (starts with 0xC0)
        let mac = [0x00, 0xC0, 0x00, 0x00];
        assert_eq!(instruction_length(&mac), 4);

        // 32-bit long jump (starts with 0xE2)
        let jump_l = [0x00, 0xE2, 0x00, 0x00];
        assert_eq!(instruction_length(&jump_l), 4);
    }

    #[test]
    fn test_is_return() {
        assert!(is_return(opcode::RTS));
        assert!(is_return(opcode::RTI));
        assert!(!is_return(opcode::NOP));
    }

    #[test]
    fn test_is_nop_or_sync() {
        assert!(is_nop_or_sync(opcode::NOP));
        assert!(is_nop_or_sync(opcode::CSYNC));
        assert!(is_nop_or_sync(opcode::SSYNC));
        assert!(!is_nop_or_sync(opcode::RTS));
    }

    #[test]
    fn test_score_basic() {
        // Simple sequence: NOP, NOP, RTS
        let code = [
            0x00, 0x00, // NOP
            0x00, 0x00, // NOP
            0x10, 0x00, // RTS
        ];
        let s = score(&code);
        assert!(s > 0, "Valid Blackfin code should score positive");
    }

    #[test]
    fn test_score_mac() {
        // MAC instruction (32-bit, high byte 0xC0)
        let code = [
            0x00, 0xC0, 0x00, 0x00, // MAC op
            0x10, 0x00, // RTS
        ];
        let s = score(&code);
        assert!(s > 10, "MAC instruction should score well");
    }

    #[test]
    fn test_score_invalid() {
        // All 0xFF bytes don't form valid Blackfin patterns
        let code = [0xFF, 0xFF, 0xFF, 0xFF];
        let s = score(&code);
        // May still score some if interpreted as 16-bit, but low
        assert!(s < 20, "Random data should score low");
    }
}
