//! IA-64 / Itanium architecture analysis.
//!
//! Itanium uses VLIW-style EPIC architecture with 128-bit instruction bundles.
//! Each bundle contains three 41-bit instruction slots plus a 5-bit template.
//! Bundles are 16-byte aligned.

/// IA-64 template and opcode constants.
pub mod opcode {
    // Template encodings (5 bits, bits 0-4 of bundle)
    /// MII template (Memory, Integer, Integer).
    pub const TEMPLATE_MII: u8 = 0x00;
    /// MII with stop after slot 2.
    pub const TEMPLATE_MII_S: u8 = 0x01;
    /// MII with stop after slot 1.
    pub const TEMPLATE_MII_S1: u8 = 0x02;
    /// MII with stops after slot 1 and 2.
    pub const TEMPLATE_MII_S12: u8 = 0x03;
    /// MLX template (Memory, Long immediate).
    pub const TEMPLATE_MLX: u8 = 0x04;
    /// MLX with stop.
    pub const TEMPLATE_MLX_S: u8 = 0x05;
    /// MMI template.
    pub const TEMPLATE_MMI: u8 = 0x08;
    /// MMI with stop after slot 2.
    pub const TEMPLATE_MMI_S: u8 = 0x09;
    /// MMI with stop after slot 0.
    pub const TEMPLATE_MMI_S0: u8 = 0x0A;
    /// MMI with stops after slot 0 and 2.
    pub const TEMPLATE_MMI_S02: u8 = 0x0B;
    /// MFI template (Memory, Float, Integer).
    pub const TEMPLATE_MFI: u8 = 0x0C;
    /// MFI with stop.
    pub const TEMPLATE_MFI_S: u8 = 0x0D;
    /// MMF template.
    pub const TEMPLATE_MMF: u8 = 0x0E;
    /// MMF with stop.
    pub const TEMPLATE_MMF_S: u8 = 0x0F;
    /// MIB template (Memory, Integer, Branch).
    pub const TEMPLATE_MIB: u8 = 0x10;
    /// MIB with stop.
    pub const TEMPLATE_MIB_S: u8 = 0x11;
    /// MBB template.
    pub const TEMPLATE_MBB: u8 = 0x12;
    /// MBB with stop.
    pub const TEMPLATE_MBB_S: u8 = 0x13;
    /// BBB template (all branches).
    pub const TEMPLATE_BBB: u8 = 0x16;
    /// BBB with stop.
    pub const TEMPLATE_BBB_S: u8 = 0x17;
    /// MMB template.
    pub const TEMPLATE_MMB: u8 = 0x18;
    /// MMB with stop.
    pub const TEMPLATE_MMB_S: u8 = 0x19;
    /// MFB template.
    pub const TEMPLATE_MFB: u8 = 0x1C;
    /// MFB with stop.
    pub const TEMPLATE_MFB_S: u8 = 0x1D;

    // Major opcodes (4 bits, bits 40-37 of each slot)
    /// System/memory management.
    pub const OP_SYSTEM: u8 = 0x0;
    /// System variant 1.
    pub const OP_SYSTEM1: u8 = 0x1;
    /// Load/store operations.
    pub const OP_LOAD_STORE: u8 = 0x4;
    /// Load/store variant / deposit/shift.
    pub const OP_LOAD_STORE2: u8 = 0x5;
    /// Variable / multimedia.
    pub const OP_VARIABLE: u8 = 0x7;
    /// Integer ALU / FP mult-add.
    pub const OP_ALU: u8 = 0x8;
    /// Integer ALU variant / FP mult-sub.
    pub const OP_ALU2: u8 = 0x9;
    /// ALU/MM / FP neg mult.
    pub const OP_ALU_MM: u8 = 0xA;
    /// Integer compare.
    pub const OP_CMP: u8 = 0xC;
    /// Integer compare variant.
    pub const OP_CMP2: u8 = 0xD;
    /// FP compare.
    pub const OP_FCMP: u8 = 0xE;

    // Branch opcodes (for B-unit slots)
    /// IP-relative branch.
    pub const BR_IP_REL: u8 = 0x0;
    /// IP-relative branch variant.
    pub const BR_IP_REL2: u8 = 0x1;
    /// Indirect branch.
    pub const BR_INDIRECT: u8 = 0x4;
    /// Indirect call.
    pub const BR_CALL: u8 = 0x5;
    /// NOP/hint in branch slot.
    pub const BR_NOP: u8 = 0x7;

    // Special instruction patterns
    /// NOP instruction (all zeros in slot with qp=0).
    pub const SLOT_NOP: u64 = 0x0000_0000_0000;
    /// Break instruction pattern.
    pub const SLOT_BREAK: u64 = 0x0000_0000_0000; // Major op 0, specific encoding
}

/// Bundle size in bytes (128 bits = 16 bytes).
pub const BUNDLE_SIZE: usize = 16;

/// Slot size in bits.
pub const SLOT_BITS: u32 = 41;

/// Template bits.
pub const TEMPLATE_BITS: u32 = 5;

/// Check if a template value is valid.
pub fn is_valid_template(template: u8) -> bool {
    matches!(
        template,
        opcode::TEMPLATE_MII
            | opcode::TEMPLATE_MII_S
            | opcode::TEMPLATE_MII_S1
            | opcode::TEMPLATE_MII_S12
            | opcode::TEMPLATE_MLX
            | opcode::TEMPLATE_MLX_S
            | opcode::TEMPLATE_MMI
            | opcode::TEMPLATE_MMI_S
            | opcode::TEMPLATE_MMI_S0
            | opcode::TEMPLATE_MMI_S02
            | opcode::TEMPLATE_MFI
            | opcode::TEMPLATE_MFI_S
            | opcode::TEMPLATE_MMF
            | opcode::TEMPLATE_MMF_S
            | opcode::TEMPLATE_MIB
            | opcode::TEMPLATE_MIB_S
            | opcode::TEMPLATE_MBB
            | opcode::TEMPLATE_MBB_S
            | opcode::TEMPLATE_BBB
            | opcode::TEMPLATE_BBB_S
            | opcode::TEMPLATE_MMB
            | opcode::TEMPLATE_MMB_S
            | opcode::TEMPLATE_MFB
            | opcode::TEMPLATE_MFB_S
    )
}

/// Extract template from a 128-bit bundle.
pub fn extract_template(bundle: &[u8; 16]) -> u8 {
    bundle[0] & 0x1F
}

/// Extract a 41-bit instruction slot from a bundle.
///
/// Slots are numbered 0, 1, 2 from LSB to MSB:
/// - Slot 0: bits 5-45
/// - Slot 1: bits 46-86
/// - Slot 2: bits 87-127
pub fn extract_slot(bundle: &[u8; 16], slot: usize) -> u64 {
    if slot > 2 {
        return 0;
    }

    // Convert bundle to u128 (little-endian)
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(bundle);
    let bundle_val = u128::from_le_bytes(bytes);

    // Extract slot
    let shift = TEMPLATE_BITS + (slot as u32 * SLOT_BITS);
    let mask = (1u128 << SLOT_BITS) - 1;
    ((bundle_val >> shift) & mask) as u64
}

/// Extract major opcode from a 41-bit slot value.
pub fn slot_major_opcode(slot: u64) -> u8 {
    ((slot >> 37) & 0xF) as u8
}

/// Extract qualifying predicate from a 41-bit slot value.
pub fn slot_predicate(slot: u64) -> u8 {
    (slot & 0x3F) as u8
}

/// Get slot types from template.
///
/// Returns (slot0_type, slot1_type, slot2_type) as characters:
/// 'M' = Memory, 'I' = Integer, 'F' = Float, 'B' = Branch, 'L' = Long, 'X' = Extended
pub fn template_slot_types(template: u8) -> (char, char, char) {
    match template & 0x1E {
        // Ignore stop bit for slot type determination
        0x00 => ('M', 'I', 'I'),
        0x04 => ('M', 'L', 'X'),
        0x08 => ('M', 'M', 'I'),
        0x0C => ('M', 'F', 'I'),
        0x0E => ('M', 'M', 'F'),
        0x10 => ('M', 'I', 'B'),
        0x12 => ('M', 'B', 'B'),
        0x16 => ('B', 'B', 'B'),
        0x18 => ('M', 'M', 'B'),
        0x1C => ('M', 'F', 'B'),
        _ => ('?', '?', '?'),
    }
}

/// Check if slot appears to be a NOP.
pub fn is_slot_nop(slot: u64) -> bool {
    // NOP has specific patterns based on slot type
    // A-unit NOP: major op 8 or 9, with specific encoding
    // M-unit NOP: major op 0 or 1, with specific encoding
    // I-unit NOP: major op 0, with specific encoding
    // B-unit NOP: major op 7
    let major = slot_major_opcode(slot);
    let qp = slot_predicate(slot);

    // Most common NOP patterns
    (slot == 0) || (major == opcode::BR_NOP && qp == 0)
}

/// Check if slot appears to be a branch.
pub fn is_slot_branch(slot: u64, slot_type: char) -> bool {
    if slot_type != 'B' {
        return false;
    }
    let major = slot_major_opcode(slot);
    matches!(
        major,
        opcode::BR_IP_REL | opcode::BR_IP_REL2 | opcode::BR_INDIRECT | opcode::BR_CALL
    )
}

/// Check if slot appears to be a return (br.ret).
pub fn is_slot_return(slot: u64, slot_type: char) -> bool {
    if slot_type != 'B' {
        return false;
    }
    let major = slot_major_opcode(slot);
    // br.ret uses indirect branch with specific encoding
    major == opcode::BR_INDIRECT
}

/// Check if slot appears to be a load/store.
pub fn is_slot_load_store(slot: u64, slot_type: char) -> bool {
    if slot_type != 'M' {
        return false;
    }
    let major = slot_major_opcode(slot);
    matches!(major, opcode::OP_LOAD_STORE | opcode::OP_LOAD_STORE2)
}

/// Check if slot appears to be an ALU operation.
pub fn is_slot_alu(slot: u64) -> bool {
    let major = slot_major_opcode(slot);
    matches!(major, opcode::OP_ALU | opcode::OP_ALU2 | opcode::OP_ALU_MM)
}

/// Check if slot appears to be a compare.
pub fn is_slot_compare(slot: u64) -> bool {
    let major = slot_major_opcode(slot);
    matches!(major, opcode::OP_CMP | opcode::OP_CMP2 | opcode::OP_FCMP)
}

/// Score likelihood of IA-64 code.
///
/// Analyzes raw bytes for patterns characteristic of Itanium:
/// - 16-byte bundle alignment
/// - Valid template encodings
/// - Consistent slot types with template
/// - Predicated instruction patterns
pub fn score(data: &[u8]) -> i64 {
    if data.len() < BUNDLE_SIZE {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut valid_bundles = 0u32;
    let mut invalid_bundles = 0u32;
    let mut branch_count = 0u32;
    let mut return_count = 0u32;
    let mut load_store_count = 0u32;

    // Cross-architecture penalties for 16-bit LE patterns
    // IA64 bundles are 16 bytes; scan halfwords for distinctive patterns from other ISAs
    {
        let mut j = 0;
        while j + 1 < data.len() {
            let hw = u16::from_le_bytes([data[j], data[j + 1]]);
            // MSP430
            if hw == 0x4130 {
                total_score -= 15;
            } // MSP430 RET
            if hw == 0x4303 {
                total_score -= 8;
            } // MSP430 NOP
            if hw == 0x1300 {
                total_score -= 10;
            } // MSP430 RETI
              // AVR
            if hw == 0x9508 {
                total_score -= 12;
            } // AVR RET
            if hw == 0x9518 {
                total_score -= 10;
            } // AVR RETI
              // Thumb
            if hw == 0x4770 {
                total_score -= 10;
            } // Thumb BX LR
            j += 2;
        }
    }
    // Cross-architecture penalties for 32-bit BE patterns (MIPS, SPARC, PPC)
    {
        let mut j = 0;
        while j + 3 < data.len() {
            let be32 = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            // MIPS BE
            if be32 == 0x03E00008 {
                total_score -= 15;
            } // JR $ra
            if (be32 & 0xFFFF0000) == 0x27BD0000 {
                total_score -= 10;
            } // ADDIU $sp
            if (be32 & 0xFFFF0000) == 0xAFBF0000 {
                total_score -= 10;
            } // SW $ra
            if (be32 & 0xFFFF0000) == 0x8FBF0000 {
                total_score -= 10;
            } // LW $ra
              // MIPS generic opcodes (bits 31:26)
            {
                let mips_op = (be32 >> 26) & 0x3F;
                match mips_op {
                    0x23 => total_score -= 3, // LW
                    0x2B => total_score -= 3, // SW
                    0x09 => total_score -= 2, // ADDIU
                    0x0F => total_score -= 3, // LUI
                    0x03 => total_score -= 4, // JAL
                    _ => {}
                }
            }
            // PPC
            if be32 == 0x4E800020 {
                total_score -= 15;
            } // BLR
            if be32 == 0x7C0802A6 {
                total_score -= 10;
            } // MFLR r0
            if be32 == 0x60000000 {
                total_score -= 8;
            } // NOP
              // PPC STWU r1 (store word update, stack frame setup)
            if (be32 & 0xFFFF0000) == 0x94210000 {
                total_score -= 8;
            }
            // SPARC
            if be32 == 0x81C7E008 {
                total_score -= 12;
            } // RET
            if be32 == 0x81C3E008 {
                total_score -= 12;
            } // RETL
            if be32 == 0x01000000 {
                total_score -= 8;
            } // NOP
            j += 4;
        }
    }
    // Cross-architecture penalties for 32-bit LE patterns
    {
        let mut j = 0;
        while j + 3 < data.len() {
            let le32 = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            // MIPS LE
            if le32 == 0x03E00008 {
                total_score -= 15;
            } // JR $ra
            if (le32 & 0xFFFF0000) == 0x27BD0000 {
                total_score -= 10;
            } // ADDIU $sp
            if (le32 & 0xFFFF0000) == 0xAFBF0000 {
                total_score -= 10;
            } // SW $ra
              // AArch64
            if le32 == 0xD65F03C0 {
                total_score -= 12;
            } // RET
            if le32 == 0xD503201F {
                total_score -= 8;
            } // NOP
              // RISC-V
            if le32 == 0x00008067 {
                total_score -= 12;
            } // RET
            if le32 == 0x00000013 {
                total_score -= 8;
            } // NOP
              // LoongArch
            if le32 == 0x4C000020 {
                total_score -= 10;
            } // RET
            j += 4;
        }
    }
    // Penalize long zero runs (NOP sleds, padding — not real IA-64 code)
    {
        let mut zero_run = 0u32;
        let mut j = 0;
        while j + 3 < data.len() {
            let w = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            if w == 0 {
                zero_run += 1;
                if zero_run > 2 {
                    total_score -= 3;
                }
            } else {
                zero_run = 0;
            }
            j += 4;
        }
    }

    // Process bundles (must be 16-byte aligned for real IA-64)
    let mut i = 0;
    while i + BUNDLE_SIZE <= data.len() {
        let mut bundle = [0u8; 16];
        bundle.copy_from_slice(&data[i..i + BUNDLE_SIZE]);

        let template = extract_template(&bundle);

        if !is_valid_template(template) {
            invalid_bundles += 1;
            i += BUNDLE_SIZE;
            continue;
        }

        valid_bundles += 1;

        // Score template (reduced from 5 because 75% of random bytes
        // produce valid templates — 24/32 valid template values)
        total_score += 2;

        // Extract and score slots
        let (t0, t1, t2) = template_slot_types(template);
        let slot0 = extract_slot(&bundle, 0);
        let slot1 = extract_slot(&bundle, 1);
        let slot2 = extract_slot(&bundle, 2);

        // Score slot 0
        if is_slot_nop(slot0) {
            total_score += 3;
        } else if is_slot_load_store(slot0, t0) {
            total_score += 6;
            load_store_count += 1;
        } else if is_slot_alu(slot0) {
            total_score += 4;
        }

        // Score slot 1
        if t1 == 'L' {
            // Long immediate (MLX template)
            total_score += 8; // movl is common
        } else if is_slot_nop(slot1) {
            total_score += 2;
        } else if is_slot_branch(slot1, t1) {
            total_score += 6;
            branch_count += 1;
        } else if is_slot_alu(slot1) {
            total_score += 4;
        }

        // Score slot 2
        if t2 == 'X' {
            // Extended slot (part of MLX)
            total_score += 4;
        } else if is_slot_nop(slot2) {
            total_score += 2;
        } else if is_slot_branch(slot2, t2) {
            total_score += 6;
            branch_count += 1;
        } else if is_slot_return(slot2, t2) {
            total_score += 10; // Returns are strong indicators
            return_count += 1;
        } else if is_slot_compare(slot2) {
            total_score += 5;
        }

        // Bonus for all-branch bundles (BBB template)
        if template == opcode::TEMPLATE_BBB || template == opcode::TEMPLATE_BBB_S {
            total_score += 5;
        }

        // Check predicate usage (non-zero qp indicates predication)
        if slot_predicate(slot0) != 0 {
            total_score += 2; // Predication is IA-64 specific
        }
        if slot_predicate(slot1) != 0 && t1 != 'L' {
            total_score += 2;
        }
        if slot_predicate(slot2) != 0 && t2 != 'X' {
            total_score += 2;
        }

        i += BUNDLE_SIZE;
    }

    // Structural requirement: real IA-64 code must have branches, returns, or load/stores
    // Without this, random data from 16-bit ISAs scores high because 75% of bytes[0]
    // values produce valid templates (24/32 valid)
    // Structural requirement: IA-64 slot matching is broad enough that random data
    // generates false branch/load-store matches. Require meaningful counts.
    let mut structural_ok = true;
    if valid_bundles > 3 {
        let distinctive = branch_count + return_count;
        if distinctive < 2 && load_store_count < 2 {
            // Too few distinctive patterns — likely noise
            if distinctive == 0 && load_store_count == 0 {
                total_score = (total_score as f64 * 0.08) as i64;
            } else {
                total_score = (total_score as f64 * 0.20) as i64;
            }
            structural_ok = false;
        }
    }

    // Adjust based on validity ratio
    if valid_bundles + invalid_bundles > 0 {
        let validity_ratio = valid_bundles as f64 / (valid_bundles + invalid_bundles) as f64;
        total_score = (total_score as f64 * validity_ratio) as i64;

        // Bonus only with structural evidence
        if structural_ok && validity_ratio > 0.85 && valid_bundles > 5 {
            total_score += 20;
        }
    }

    total_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_templates() {
        assert!(is_valid_template(opcode::TEMPLATE_MII));
        assert!(is_valid_template(opcode::TEMPLATE_MLX));
        assert!(is_valid_template(opcode::TEMPLATE_BBB));
        assert!(!is_valid_template(0x06)); // Invalid
        assert!(!is_valid_template(0x07)); // Invalid
        assert!(!is_valid_template(0x14)); // Invalid
    }

    #[test]
    fn test_extract_template() {
        let bundle = [0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(extract_template(&bundle), opcode::TEMPLATE_MMI);

        let bundle2 = [0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(extract_template(&bundle2), opcode::TEMPLATE_BBB);
    }

    #[test]
    fn test_template_slot_types() {
        assert_eq!(template_slot_types(opcode::TEMPLATE_MII), ('M', 'I', 'I'));
        assert_eq!(template_slot_types(opcode::TEMPLATE_MLX), ('M', 'L', 'X'));
        assert_eq!(template_slot_types(opcode::TEMPLATE_BBB), ('B', 'B', 'B'));
    }

    #[test]
    fn test_score_basic() {
        // Simple bundle with MMI template and NOPs
        let mut bundle = [0u8; 16];
        bundle[0] = opcode::TEMPLATE_MMI;
        // Rest is zeros (NOPs)

        let s = score(&bundle);
        assert!(s > 0, "Valid IA-64 bundle should score positive");
    }

    #[test]
    fn test_score_multiple_bundles() {
        // Two bundles
        let mut data = [0u8; 32];
        data[0] = opcode::TEMPLATE_MII;
        data[16] = opcode::TEMPLATE_MIB_S;

        let s = score(&data);
        assert!(s > 5, "Multiple valid bundles should score well");
    }

    #[test]
    fn test_score_invalid_template() {
        let mut bundle = [0u8; 16];
        bundle[0] = 0x06; // Invalid template

        let s = score(&bundle);
        // May score 0 or very low
        assert!(s < 5, "Invalid template should score low");
    }
}
