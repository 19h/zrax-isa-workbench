//! Qualcomm Hexagon (QDSP6) architecture analysis.
//!
//! Hexagon is a VLIW DSP architecture with 32-bit instructions
//! organized into packets of 1-4 instructions. Little-endian.

/// Packet and instruction structure.
pub mod packet {
    /// Parse bits (bits 15:14) indicate packet boundary.
    pub const PARSE_BITS_MASK: u32 = 0x0000C000;
    
    /// End of packet marker (parse bits = 11).
    pub const END_OF_PACKET: u32 = 0x0000C000;
    
    /// Not end of packet (parse bits = 00, 01, 10).
    pub fn is_end_of_packet(instr: u32) -> bool {
        (instr & PARSE_BITS_MASK) == END_OF_PACKET
    }
    
    /// Minimum packet size in bytes.
    pub const MIN_PACKET_SIZE: usize = 4;
    
    /// Maximum packet size in bytes (4 instructions).
    pub const MAX_PACKET_SIZE: usize = 16;
}

/// Instruction classes (bits 31:28).
pub mod iclass {
    pub const ALU32_0: u8 = 0x0;
    pub const ALU32_1: u8 = 0x1;
    pub const ALU32_2: u8 = 0x2;
    pub const ALU32_3: u8 = 0x3;
    pub const XTYPE_0: u8 = 0x4;
    pub const XTYPE_1: u8 = 0x5;
    pub const XTYPE_2: u8 = 0x6;
    pub const XTYPE_3: u8 = 0x7;
    pub const ALU64_0: u8 = 0x8;
    pub const ALU64_1: u8 = 0x9;
    pub const ALU64_2: u8 = 0xA;
    pub const ALU64_3: u8 = 0xB;
    pub const EXT_0: u8 = 0xC;
    pub const EXT_1: u8 = 0xD;
    pub const EXT_2: u8 = 0xE;
    pub const EXT_3: u8 = 0xF;
}

/// Common Hexagon instruction patterns.
pub mod patterns {
    /// NOP.
    pub const NOP: u32 = 0x7F000000;
    
    /// Alternative NOP encoding.
    pub const NOP_ALT: u32 = 0x7F00C000;  // With end-of-packet
    
    /// JUMPR R31 (return) - approximate pattern.
    /// Actual encoding varies by version.
    pub const JUMPR_LR_MASK: u32 = 0xFFE03FFF;
    pub const JUMPR_LR_VAL: u32 = 0x52800000;  // jumpr r31
    
    /// DEALLOC_RETURN - common return pattern.
    pub const DEALLOC_RETURN: u32 = 0x961EC01E;
    
    /// ALLOCFRAME - function prologue.
    pub const ALLOCFRAME_MASK: u32 = 0xFFFFE000;
    pub const ALLOCFRAME_VAL: u32 = 0xA09DC000;
    
    /// Loop setup patterns.
    pub const LOOP0_MASK: u32 = 0xFFE00000;
    pub const LOOP0_VAL: u32 = 0x60000000;
    
    /// Constant extender prefix.
    pub const EXTENDER_MASK: u32 = 0xF0000000;
    pub const EXTENDER_VAL: u32 = 0x00000000;
}

/// Hexagon architecture versions.
pub mod version {
    pub const V5: u8 = 5;
    pub const V55: u8 = 55;
    pub const V60: u8 = 60;
    pub const V62: u8 = 62;
    pub const V65: u8 = 65;
    pub const V66: u8 = 66;
    pub const V67: u8 = 67;
    pub const V68: u8 = 68;
    pub const V69: u8 = 69;
    pub const V71: u8 = 71;
    pub const V73: u8 = 73;
}

/// Register types.
pub mod reg {
    /// General purpose registers R0-R31.
    pub const R0: u8 = 0;
    pub const R29: u8 = 29;  // SP
    pub const R30: u8 = 30;  // FP
    pub const R31: u8 = 31;  // LR
    
    /// Stack pointer alias.
    pub const SP: u8 = 29;
    /// Frame pointer alias.
    pub const FP: u8 = 30;
    /// Link register alias.
    pub const LR: u8 = 31;
    
    /// Predicate registers P0-P3.
    pub const P0: u8 = 0;
    pub const P1: u8 = 1;
    pub const P2: u8 = 2;
    pub const P3: u8 = 3;
}

/// Extract instruction class (bits 31:28).
pub fn get_iclass(instr: u32) -> u8 {
    ((instr >> 28) & 0x0F) as u8
}

/// Extract parse bits (bits 15:14).
pub fn get_parse_bits(instr: u32) -> u8 {
    ((instr >> 14) & 0x03) as u8
}

/// Check if instruction is end of packet.
pub fn is_end_of_packet(instr: u32) -> bool {
    packet::is_end_of_packet(instr)
}

/// Check if instruction is a constant extender.
pub fn is_extender(instr: u32) -> bool {
    // Constant extenders have specific encoding
    (instr & patterns::EXTENDER_MASK) == patterns::EXTENDER_VAL &&
    get_iclass(instr) == 0x0
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u32) -> bool {
    // NOP can have different parse bits
    (instr & 0xFFFF0000) == (patterns::NOP & 0xFFFF0000) ||
    instr == patterns::NOP_ALT
}

/// Check if instruction is likely a return.
pub fn is_return(instr: u32) -> bool {
    // Various return patterns
    // jumpr r31
    // dealloc_return
    instr == patterns::DEALLOC_RETURN ||
    (instr & patterns::JUMPR_LR_MASK) == patterns::JUMPR_LR_VAL
}

/// Check if instruction is ALLOCFRAME (function prologue).
pub fn is_allocframe(instr: u32) -> bool {
    (instr & patterns::ALLOCFRAME_MASK) == patterns::ALLOCFRAME_VAL
}

/// Check if instruction is a jump.
pub fn is_jump(instr: u32) -> bool {
    // Jumps are typically in class 5 (J-type)
    let iclass = get_iclass(instr);
    iclass == 0x5
}

/// Check if instruction is a call.
pub fn is_call(instr: u32) -> bool {
    // Calls are typically in class 5 with specific sub-encoding
    let iclass = get_iclass(instr);
    if iclass != 0x5 {
        return false;
    }
    // Check for call-specific bits (simplified)
    (instr & 0x0E000000) == 0x0A000000
}

/// Check if instruction is a conditional instruction (predicated).
pub fn is_predicated(instr: u32) -> bool {
    // Many Hexagon instructions can be predicated
    // Check for predicate encoding bits
    let iclass = get_iclass(instr);
    match iclass {
        0..=3 => (instr & 0x08000000) != 0,  // ALU32
        _ => false, // Simplified
    }
}

/// Check if instruction is a load.
pub fn is_load(instr: u32) -> bool {
    let iclass = get_iclass(instr);
    // Loads are in XTYPE classes 4-7 with specific sub-encoding
    iclass >= 0x4 && iclass <= 0x7 && (instr & 0x02000000) == 0
}

/// Check if instruction is a store.
pub fn is_store(instr: u32) -> bool {
    let iclass = get_iclass(instr);
    // Stores are in XTYPE classes with specific sub-encoding
    iclass >= 0x4 && iclass <= 0x7 && (instr & 0x02000000) != 0
}

/// Check if instruction is a loop setup.
pub fn is_loop_setup(instr: u32) -> bool {
    (instr & patterns::LOOP0_MASK) == patterns::LOOP0_VAL
}

/// Check if instruction is an ALU32 class.
pub fn is_alu32(instr: u32) -> bool {
    let iclass = get_iclass(instr);
    iclass <= 0x3
}

/// Check if instruction is an ALU64 class.
pub fn is_alu64(instr: u32) -> bool {
    let iclass = get_iclass(instr);
    iclass >= 0x8 && iclass <= 0xB
}

/// Check if instruction is an XTYPE class.
pub fn is_xtype(instr: u32) -> bool {
    let iclass = get_iclass(instr);
    iclass >= 0x4 && iclass <= 0x7
}

/// Count instructions in a packet (returns None if invalid).
pub fn packet_length(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    
    let mut offset = 0;
    let mut count = 0;
    
    while offset + 4 <= data.len() && count < 4 {
        let instr = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        
        count += 1;
        offset += 4;
        
        if is_end_of_packet(instr) {
            return Some(count);
        }
    }
    
    // No end-of-packet found within 4 instructions
    None
}

/// Strong indicator patterns for heuristic detection.
pub const STRONG_INDICATORS: &[u32] = &[
    patterns::NOP,
    patterns::NOP_ALT,
    patterns::DEALLOC_RETURN,
];

/// Check if instruction looks like valid Hexagon code.
pub fn is_likely_valid(instr: u32) -> bool {
    let iclass = get_iclass(instr);
    
    // All instruction classes 0-F are potentially valid
    // But we can check for some obviously invalid patterns
    
    // Check that parse bits are valid (00, 01, 10, or 11)
    // All values are valid, so no check needed there
    
    // NOP pattern
    if is_nop(instr) {
        return true;
    }
    
    // Check for valid instruction class patterns
    match iclass {
        0x0..=0x3 => true,  // ALU32
        0x4..=0x7 => true,  // XTYPE/Load/Store
        0x8..=0xB => true,  // ALU64/Multiply
        0xC..=0xF => true,  // Extended
        _ => false,
    }
}

/// Version-specific feature detection.
pub mod features {
    /// Check if version supports HVX (Hexagon Vector eXtensions).
    pub fn has_hvx(version: u8) -> bool {
        version >= super::version::V60
    }
    
    /// Check if version supports HVX v62 features.
    pub fn has_hvx_v62(version: u8) -> bool {
        version >= super::version::V62
    }
    
    /// Check if version supports HVX v65 features.
    pub fn has_hvx_v65(version: u8) -> bool {
        version >= super::version::V65
    }
    
    /// Check if version supports HVX v66 features.
    pub fn has_hvx_v66(version: u8) -> bool {
        version >= super::version::V66
    }
}

/// Score likelihood of Hexagon code.
///
/// Analyzes raw bytes for patterns characteristic of Hexagon.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // Hexagon is little-endian, 4-byte aligned (VLIW packets)
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // NOP
        if is_nop(word) {
            score += 25;
        }

        // End of packet marker
        if is_end_of_packet(word) {
            score += 5;
        }

        // ALU32
        if is_alu32(word) {
            score += 2;
        }
        
        // XTYPE/Memory
        if is_xtype(word) {
            score += 2;
        }
        
        // ALU64/M
        if is_alu64(word) {
            score += 2;
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop_detection() {
        assert!(is_nop(patterns::NOP));
        assert!(is_nop(patterns::NOP_ALT));
    }

    #[test]
    fn test_iclass_extraction() {
        // ALU32 instruction
        assert_eq!(get_iclass(0x10000000), 0x1);
        // XTYPE instruction
        assert_eq!(get_iclass(0x50000000), 0x5);
        // ALU64 instruction
        assert_eq!(get_iclass(0xA0000000), 0xA);
    }

    #[test]
    fn test_parse_bits() {
        // End of packet
        assert!(is_end_of_packet(0x0000C000));
        assert!(is_end_of_packet(0x1234C000));
        // Not end of packet
        assert!(!is_end_of_packet(0x00000000));
        assert!(!is_end_of_packet(0x00004000));
        assert!(!is_end_of_packet(0x00008000));
    }

    #[test]
    fn test_packet_length() {
        // Single instruction packet (end marker set)
        let single = [0x00u8, 0xC0, 0x00, 0x7F];  // NOP with end marker
        assert_eq!(packet_length(&single), Some(1));
        
        // Two instruction packet
        let double = [
            0x00u8, 0x00, 0x00, 0x10,  // First instruction (no end)
            0x00, 0xC0, 0x00, 0x7F,    // Second instruction (end)
        ];
        assert_eq!(packet_length(&double), Some(2));
    }

    #[test]
    fn test_instruction_class() {
        assert!(is_alu32(0x10000000));
        assert!(is_alu32(0x30000000));
        assert!(!is_alu32(0x50000000));
        
        assert!(is_xtype(0x40000000));
        assert!(is_xtype(0x70000000));
        
        assert!(is_alu64(0x80000000));
        assert!(is_alu64(0xB0000000));
    }

    #[test]
    fn test_hvx_features() {
        assert!(!features::has_hvx(version::V5));
        assert!(features::has_hvx(version::V60));
        assert!(features::has_hvx(version::V73));
        
        assert!(features::has_hvx_v66(version::V66));
        assert!(features::has_hvx_v66(version::V73));
        assert!(!features::has_hvx_v66(version::V65));
    }

    #[test]
    fn test_score() {
        // Hexagon NOP (little-endian)
        let nop = patterns::NOP.to_le_bytes();
        assert!(score(&nop) > 0);
    }
}
