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
    pub const NOP_ALT: u32 = 0x7F00C000; // With end-of-packet

    /// JUMPR R31 (return) - approximate pattern.
    /// Actual encoding varies by version.
    pub const JUMPR_LR_MASK: u32 = 0xFFE03FFF;
    pub const JUMPR_LR_VAL: u32 = 0x52800000; // jumpr r31

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
    pub const R29: u8 = 29; // SP
    pub const R30: u8 = 30; // FP
    pub const R31: u8 = 31; // LR

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
    (instr & patterns::EXTENDER_MASK) == patterns::EXTENDER_VAL && get_iclass(instr) == 0x0
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u32) -> bool {
    // NOP can have different parse bits
    (instr & 0xFFFF0000) == (patterns::NOP & 0xFFFF0000) || instr == patterns::NOP_ALT
}

/// Check if instruction is likely a return.
pub fn is_return(instr: u32) -> bool {
    // Various return patterns
    // jumpr r31
    // dealloc_return
    instr == patterns::DEALLOC_RETURN || (instr & patterns::JUMPR_LR_MASK) == patterns::JUMPR_LR_VAL
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
        0..=3 => (instr & 0x08000000) != 0, // ALU32
        _ => false,                         // Simplified
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
pub const STRONG_INDICATORS: &[u32] = &[patterns::NOP, patterns::NOP_ALT, patterns::DEALLOC_RETURN];

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
        0x0..=0x3 => true, // ALU32
        0x4..=0x7 => true, // XTYPE/Load/Store
        0x8..=0xB => true, // ALU64/Multiply
        0xC..=0xF => true, // Extended
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
/// Analyzes raw bytes using packet structure validation,
/// specific instruction patterns, and cross-architecture penalties.
pub fn score(data: &[u8]) -> i64 {
    let mut total_score: i64 = 0;
    let mut packet_count = 0u32;
    let mut valid_packets = 0u32;

    // Hexagon is little-endian, 4-byte aligned (VLIW packets of 1-4 instructions)
    // Key insight: Every Hexagon instruction has parse bits (15:14) and exactly one
    // instruction per packet must have parse bits = 11 (end of packet).
    // This packet structure is the most distinctive Hexagon feature.

    // Pre-scan for cross-architecture penalties.
    let mut cross_arch_penalty: i64 = 0;

    // Thumb penalty: anchor-gated system — broad patterns only count with anchors.
    {
        let mut anchor_count = 0u32;
        let mut anchor_penalty: i64 = 0;
        let mut broad_penalty: i64 = 0;

        let mut j = 0;
        while j + 1 < data.len() {
            let hw = u16::from_le_bytes([data[j], data[j + 1]]);

            // === High-confidence anchors (very specific to Thumb) ===
            if hw == 0x4770 {
                anchor_count += 1;
                anchor_penalty += 15;
            }
            // BX LR
            else if hw == 0xBF00 {
                anchor_count += 1;
                anchor_penalty += 10;
            }
            // NOP
            else if matches!(hw, 0xB672 | 0xB662 | 0xB673 | 0xB663) {
                // CPSID/CPSIE
                anchor_count += 1;
                anchor_penalty += 20;
            } else if matches!(hw, 0xBF30 | 0xBF20 | 0xBF40) {
                // WFI/WFE/SEV
                anchor_count += 1;
                anchor_penalty += 15;
            }
            // PUSH {.., LR} - function prologue, very common in Thumb firmware
            else if (hw & 0xFF00) == 0xB500 {
                anchor_count += 1;
                anchor_penalty += 8;
            }
            // POP {.., PC} - function return, very common in Thumb firmware
            else if (hw & 0xFF00) == 0xBD00 {
                anchor_count += 1;
                anchor_penalty += 8;
            }
            // === Medium-confidence patterns (counted for broad evidence) ===
            else if (hw & 0xFF00) == 0xB000 {
                broad_penalty += 5;
            }
            // ADD/SUB SP
            else if (hw & 0xF000) == 0xD000 && (hw & 0x0F00) != 0x0E00 && (hw & 0x0F00) != 0x0F00
            {
                broad_penalty += 3; // B<cond> (conditional branch)
            } else if (hw & 0xF800) == 0x4800 {
                broad_penalty += 3;
            }
            // LDR Rt, [PC, #imm]
            else if (hw & 0xFF00) == 0xDF00 {
                broad_penalty += 8;
            }
            // SVC
            else if (hw & 0xFF00) == 0xBE00 {
                broad_penalty += 6;
            }
            // BKPT
            else if (hw & 0xF500) == 0xB100 {
                broad_penalty += 5;
            } // CBZ/CBNZ

            // Thumb-2 32-bit patterns
            if j + 3 < data.len() {
                let hw1 = u16::from_le_bytes([data[j + 2], data[j + 3]]);
                let word32 = ((hw as u32) << 16) | (hw1 as u32);
                // PUSH.W / POP.W
                if (word32 & 0xFFFFE000) == 0xE92D0000 || (word32 & 0xFFFFE000) == 0xE8BD0000 {
                    broad_penalty += 15;
                }
                // BL (Thumb-2) - F000 Dxxx or F000 Fxxx
                else if (hw & 0xF800) == 0xF000 && (hw1 & 0xD000) == 0xD000 {
                    broad_penalty += 12;
                }
            }

            j += 2;
        }

        // Apply penalties proportional to Thumb evidence
        if anchor_count >= 2 {
            cross_arch_penalty += anchor_penalty + broad_penalty;
        } else if anchor_count == 1 {
            cross_arch_penalty += anchor_penalty + broad_penalty / 2;
        }
    }

    // 32-bit LE cross-architecture penalties (AArch64, RISC-V, PPC LE, x86-64)
    {
        let mut vfp_count = 0u32;
        let mut j = 0;
        while j + 3 < data.len() {
            let le32 = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            // AArch64
            if le32 == 0xD65F03C0 {
                cross_arch_penalty += 20;
            } // AArch64 RET
            if le32 == 0xD503201F {
                cross_arch_penalty += 15;
            } // AArch64 NOP
            if (le32 >> 26) == 0x25 {
                cross_arch_penalty += 5;
            } // AArch64 BL
              // RISC-V
            if le32 == 0x00008067 {
                cross_arch_penalty += 15;
            } // RISC-V RET
            if le32 == 0x00000013 {
                cross_arch_penalty += 10;
            } // RISC-V NOP
              // PPC (LE mode)
            if le32 == 0x4E800020 {
                cross_arch_penalty += 15;
            } // PPC BLR
            if le32 == 0x60000000 {
                cross_arch_penalty += 10;
            } // PPC NOP
            if le32 == 0x7C0802A6 {
                cross_arch_penalty += 12;
            } // PPC MFLR r0
            if le32 == 0x7C0803A6 {
                cross_arch_penalty += 12;
            } // PPC MTLR r0
              // LoongArch
            if le32 == 0x03400000 {
                cross_arch_penalty += 10;
            } // LoongArch NOP
            if le32 == 0x4C000020 {
                cross_arch_penalty += 12;
            } // LoongArch JIRL ra
              // ARM Thumb-2 VFP/NEON patterns: upper byte 0xED, 0xEE, 0xEF
              // These naturally set parse bits 15:14=11 causing false packet matches
            {
                let upper_byte = ((le32 >> 16) & 0xFF) as u8;
                if matches!(upper_byte, 0xED | 0xEE | 0xEF) {
                    vfp_count += 1;
                }
            }
            j += 4;
        }
        // If significant VFP patterns found, they create false parse-bit matches
        let num_words = data.len() / 4;
        if num_words > 10 && vfp_count > num_words as u32 / 10 {
            // >10% VFP instructions = very likely ARM, not Hexagon
            cross_arch_penalty += vfp_count as i64 * 3;
        }
    }

    // Track distinctive Hexagon patterns for structural requirement
    let mut distinctive_count = 0u32;

    let mut i = 0;
    while i + 3 < data.len() {
        // Try to parse a packet starting at this position
        let mut packet_instrs = 0u32;
        let mut packet_score: i64 = 0;
        let mut found_end = false;
        let mut j = i;

        while j + 3 < data.len() && packet_instrs < 4 {
            let word = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);

            // Skip padding
            if word == 0x00000000 || word == 0xFFFFFFFF {
                if packet_instrs == 0 {
                    total_score -= 3;
                    j += 4;
                    i = j;
                    continue;
                } else {
                    break; // Invalid mid-packet
                }
            }

            packet_instrs += 1;

            // NOP (high confidence)
            if is_nop(word) {
                packet_score += 15;
                distinctive_count += 1;
            }
            // DEALLOC_RETURN (very distinctive)
            else if word == patterns::DEALLOC_RETURN {
                packet_score += 25;
                distinctive_count += 1;
            }
            // ALLOCFRAME (function prologue)
            else if is_allocframe(word) {
                packet_score += 25;
                distinctive_count += 1;
            }
            // Return patterns
            else if is_return(word) {
                packet_score += 20;
                distinctive_count += 1;
            }
            // Loop setup (don't count as distinctive — the LOOP0 mask 0xFFE00000
            // is broad enough to match non-Hexagon data like Thumb-2)
            else if is_loop_setup(word) {
                packet_score += 10;
            } else {
                // Score based on instruction class with sub-encoding validation.
                // Hexagon instructions have a well-defined class encoding in bits
                // 31:28. Each class has sub-encoding rules. We give higher scores
                // for classes/sub-encodings that are more distinctive to Hexagon.
                let iclass = get_iclass(word);

                match iclass {
                    // ALU32: validate sub-encoding makes sense
                    0x0..=0x3 => {
                        // Predicated ALU32 instructions have bit 27 set
                        if is_predicated(word) {
                            packet_score += 5; // Predication is distinctive
                        } else {
                            packet_score += 2;
                        }
                    }
                    // XTYPE (load/store/complex ALU)
                    0x4..=0x7 => {
                        if is_load(word) || is_store(word) {
                            packet_score += 3;
                        } else {
                            packet_score += 2;
                        }
                    }
                    // ALU64/Multiply
                    0x8..=0xB => packet_score += 2,
                    // Extended (constant extender, etc.)
                    0xC..=0xF => {
                        // Constant extenders are distinctive
                        if is_extender(word) {
                            packet_score += 5;
                        } else {
                            packet_score += 2;
                        }
                    }
                    _ => {}
                }
            }

            // Check end-of-packet
            if is_end_of_packet(word) {
                found_end = true;
                j += 4;
                break;
            }

            j += 4;
        }

        if packet_instrs > 0 {
            packet_count += 1;
            if found_end {
                valid_packets += 1;
                // Bonus for valid packet structure — this is the most distinctive
                // Hexagon feature (parse bits 15:14 = 11 marking packet end).
                packet_score += 5;
                // Multi-instruction packets are more distinctive — random data
                // rarely produces consecutive non-EOP words followed by an EOP.
                if packet_instrs >= 2 {
                    packet_score += 5;
                }
                if packet_instrs >= 3 {
                    packet_score += 8;
                }
                if packet_instrs == 4 {
                    packet_score += 5;
                }
            } else {
                // No end-of-packet found - penalty
                packet_score -= 5;
            }
            total_score += packet_score;
        }

        i = j;
    }

    // Bonus for high ratio of valid packets (strong structural indicator)
    if packet_count > 5 {
        let packet_ratio = valid_packets as f64 / packet_count as f64;
        if packet_ratio > 0.8 {
            total_score += 20;
        } else if packet_ratio > 0.5 {
            total_score += 10;
        } else if packet_ratio < 0.3 {
            // Very few valid packets - probably not Hexagon
            total_score = (total_score as f64 * 0.3) as i64;
        }
    }

    // Structural requirement: Hexagon code of meaningful size should contain
    // distinctive patterns (NOP, ALLOCFRAME, DEALLOC_RETURN, JUMPR R31, LOOP0).
    // Without these, the broad instruction class matching (+1 per valid word)
    // causes false positives from any 32-bit LE data.
    // Random data produces ~68% valid packet ratio from coincidental parse bits,
    // so only bypass if packet ratio is exceptionally strong (>85%).
    let num_words = data.len() / 4;
    if num_words > 20 && distinctive_count == 0 {
        // Require >93% valid packet ratio to bypass structural requirement.
        // Random/non-Hexagon data (especially ARM Thumb-2) often produces
        // 85-92% valid packet ratios due to coincidental parse bit matches.
        // Real Hexagon code has >95% valid packets with proper structure.
        let very_strong_packets =
            packet_count > 10 && (valid_packets as f64 / packet_count as f64) > 0.93;
        if !very_strong_packets {
            total_score = (total_score as f64 * 0.20) as i64;
        }
    }

    // Apply cross-architecture penalty
    total_score -= cross_arch_penalty;

    // Statistical PPC LE penalty: PPC64 LE instructions are byte-swapped but
    // when read as LE u32, they decode as standard PPC opcodes (bits 31:26).
    // IMPORTANT: Hexagon instruction classes 0x8-0xB naturally map to PPC opcode
    // space 32-47 (load/store), producing ~50-70% PPC-looking instructions from
    // real Hexagon code. Therefore we require BOTH high PPC fraction AND specific
    // PPC anchor patterns (MFLR, MTLR, BLR, STWU SP) to avoid self-penalizing.
    {
        let mut ppc_valid = 0u32;
        let mut ppc_total = 0u32;
        let mut ppc_anchors = 0u32;
        let mut j = 0;
        while j + 3 < data.len() {
            let w = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            ppc_total += 1;
            let opcode = w >> 26;
            match opcode {
                14 | 15 => {
                    ppc_valid += 1;
                } // ADDI, ADDIS
                32 | 33 | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 => {
                    ppc_valid += 1; // Load/Store word/byte/half
                }
                16 => {
                    ppc_valid += 1;
                } // BC (branch conditional)
                18 => {
                    ppc_valid += 1;
                } // B (branch)
                11 => {
                    ppc_valid += 1;
                } // CMPI
                31 => {
                    // Extended opcodes (X-form)
                    let xo = (w >> 1) & 0x3FF;
                    if matches!(
                        xo,
                        0 | 4
                            | 8
                            | 10
                            | 19
                            | 20
                            | 21
                            | 23
                            | 24
                            | 26
                            | 28
                            | 32
                            | 40
                            | 266
                            | 339
                            | 444
                            | 467
                    ) {
                        ppc_valid += 1;
                    }
                }
                19 => {
                    ppc_valid += 1;
                } // CR ops, BLR, BCLR
                48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 => {
                    ppc_valid += 1; // FP load/store (LFS, LFSU, LFD, LFDU, STFS, STFSU, STFD, STFDU)
                }
                59 | 63 => {
                    ppc_valid += 1; // FP arithmetic (single=59, double=63)
                }
                _ => {}
            }
            // Check for PPC-specific anchor patterns that are very unlikely in Hexagon:
            // MFLR r0 = 0x7C0802A6, MTLR r0 = 0x7C0803A6, BLR = 0x4E800020,
            // STWU r1, -N(r1) = 0x9421xxxx, PPC NOP = 0x60000000
            if w == 0x7C0802A6
                || w == 0x7C0803A6
                || w == 0x4E800020
                || (w & 0xFFFF0000) == 0x94210000
                || w == 0x60000000
            {
                ppc_anchors += 1;
            }
            j += 4;
        }
        // Apply penalty based on PPC fraction AND anchor evidence.
        // Real PPC64 LE code has ~95%+ fraction with anchors (BLR, MFLR, etc.).
        // Hexagon code has ~50-70% fraction but zero PPC anchors.
        // Strategy: require very high fraction (>0.85) OR anchors+moderate fraction.
        if ppc_total > 8 {
            let ppc_fraction = ppc_valid as f64 / ppc_total as f64;
            if ppc_fraction > 0.85 {
                // Very high fraction — almost certainly PPC regardless of anchors
                total_score = (total_score as f64 * 0.10) as i64;
            } else if ppc_anchors >= 1 && ppc_fraction > 0.5 {
                // Moderate fraction with at least one PPC-specific pattern
                total_score = (total_score as f64 * 0.10) as i64;
            } else if ppc_anchors >= 1 && ppc_fraction > 0.3 {
                total_score = (total_score as f64 * 0.25) as i64;
            }
        }
    }

    // Statistical MIPS BE penalty: MIPS BE instructions, when read byte-by-byte
    // or at 4-byte BE alignment, can produce Hexagon-looking LE u32s.
    // Detect high fraction of valid MIPS BE instructions.
    if data.len() >= 32 {
        let mut mips_valid = 0u32;
        let mut mips_total = 0u32;
        let mut mips_anchors = 0u32;
        let mut j = 0;
        while j + 3 < data.len() {
            let be32 = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            mips_total += 1;
            let opcode = be32 >> 26;
            let is_valid = match opcode {
                0 => {
                    // SPECIAL (R-type): check function field
                    let funct = be32 & 0x3F;
                    matches!(
                        funct,
                        0x00 | 0x02
                            | 0x03
                            | 0x04
                            | 0x06
                            | 0x07
                            | 0x08
                            | 0x09
                            | 0x0C
                            | 0x0D
                            | 0x10
                            | 0x11
                            | 0x12
                            | 0x18
                            | 0x19
                            | 0x1A
                            | 0x1B
                            | 0x20
                            | 0x21
                            | 0x22
                            | 0x23
                            | 0x24
                            | 0x25
                            | 0x26
                            | 0x27
                            | 0x2A
                            | 0x2B
                    )
                }
                2 | 3 => true,   // J, JAL
                4..=7 => true,   // BEQ, BNE, BLEZ, BGTZ
                8..=15 => true,  // immediate ALU (ADDI..LUI)
                32..=43 => true, // loads/stores
                _ => false,
            };
            if is_valid {
                mips_valid += 1;
            }
            // MIPS-specific anchors
            if be32 == 0x03E00008 {
                mips_anchors += 1;
            } // JR $ra
            if (be32 & 0xFFFF0000) == 0x27BD0000 {
                mips_anchors += 1;
            } // ADDIU $sp
            if (be32 & 0xFFFF0000) == 0xAFBF0000 {
                mips_anchors += 1;
            } // SW $ra
            j += 4;
        }
        if mips_total > 8 {
            let mips_fraction = mips_valid as f64 / mips_total as f64;
            if mips_fraction > 0.7 && mips_anchors >= 1 {
                total_score = (total_score as f64 * 0.10) as i64;
            } else if mips_fraction > 0.85 {
                // Very high fraction even without anchors
                total_score = (total_score as f64 * 0.15) as i64;
            }
        }
    }

    // Statistical x86 penalty: x86 has distinctive multi-byte patterns.
    // Anchor-gated: only apply if we find strong x86 prologue/epilogue anchors.
    // Single-byte patterns (0xC3, 0xE8) are too common in Hexagon data.
    {
        let mut x86_anchors = 0u32;
        let mut j = 0;
        while j < data.len() {
            let b = data[j];
            // x86-32 prologue: PUSH EBP; MOV EBP, ESP (55 89 E5)
            if b == 0x55 && j + 2 < data.len() && data[j + 1] == 0x89 && data[j + 2] == 0xE5 {
                x86_anchors += 1;
                j += 3;
                continue;
            }
            // x86-64 prologue: PUSH RBP; MOV RBP, RSP (55 48 89 E5)
            if b == 0x55
                && j + 3 < data.len()
                && data[j + 1] == 0x48
                && data[j + 2] == 0x89
                && data[j + 3] == 0xE5
            {
                x86_anchors += 1;
                j += 4;
                continue;
            }
            // ENDBR64 (F3 0F 1E FA) / ENDBR32 (F3 0F 1E FB)
            if b == 0xF3
                && j + 3 < data.len()
                && data[j + 1] == 0x0F
                && data[j + 2] == 0x1E
                && (data[j + 3] == 0xFA || data[j + 3] == 0xFB)
            {
                x86_anchors += 1;
                j += 4;
                continue;
            }
            // x86 epilogue: POP EBP; RET (5D C3)
            if b == 0x5D && j + 1 < data.len() && data[j + 1] == 0xC3 {
                x86_anchors += 1;
                j += 2;
                continue;
            }
            // LEAVE; RET (C9 C3)
            if b == 0xC9 && j + 1 < data.len() && data[j + 1] == 0xC3 {
                x86_anchors += 1;
                j += 2;
                continue;
            }
            j += 1;
        }
        // Require at least 1 strong x86 anchor to apply penalty.
        // Then check for supportive evidence (MOV r/m patterns with ModR/M).
        if x86_anchors >= 1 && data.len() >= 32 {
            // Count high-confidence x86 MOV patterns: 89 xx and 8B xx where
            // xx has a valid ModR/M byte with mod=01 or mod=10 (register+disp)
            let mut mov_count = 0u32;
            for k in 0..data.len() - 1 {
                if (data[k] == 0x89 || data[k] == 0x8B) {
                    let modrm = data[k + 1];
                    let modv = modrm >> 6;
                    if modv == 1 || modv == 2 {
                        mov_count += 1;
                    }
                }
            }
            // x86 code typically has many MOV instructions with displacement
            let mov_density = mov_count as f64 / (data.len() as f64 / 8.0);
            if x86_anchors >= 2 || (x86_anchors >= 1 && mov_density > 0.5) {
                total_score = (total_score as f64 * 0.15) as i64;
            }
        }
    }

    total_score.max(0)
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
        let single = [0x00u8, 0xC0, 0x00, 0x7F]; // NOP with end marker
        assert_eq!(packet_length(&single), Some(1));

        // Two instruction packet
        let double = [
            0x00u8, 0x00, 0x00, 0x10, // First instruction (no end)
            0x00, 0xC0, 0x00, 0x7F, // Second instruction (end)
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
