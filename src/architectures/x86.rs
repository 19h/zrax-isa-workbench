//! x86/x86-64 architecture analysis.

/// Common x86 opcodes for identification.
pub mod opcodes {
    pub const NOP: u8 = 0x90;
    pub const RET: u8 = 0xC3;
    pub const RET_IMM: u8 = 0xC2;
    pub const RETF: u8 = 0xCB;
    pub const INT3: u8 = 0xCC;
    pub const INT: u8 = 0xCD;
    pub const PUSH_EBP: u8 = 0x55;
    pub const POP_EBP: u8 = 0x5D;
    pub const CALL_REL32: u8 = 0xE8;
    pub const JMP_REL32: u8 = 0xE9;
    pub const JMP_REL8: u8 = 0xEB;
    pub const LEAVE: u8 = 0xC9;

    // Two-byte escape
    pub const TWO_BYTE: u8 = 0x0F;
    pub const SYSCALL: [u8; 2] = [0x0F, 0x05];
    pub const SYSRET: [u8; 2] = [0x0F, 0x07];
    pub const UD2: [u8; 2] = [0x0F, 0x0B];
    pub const CPUID: [u8; 2] = [0x0F, 0xA2];

    // Prefixes
    pub const REX_BASE: u8 = 0x40;
    pub const REX_MAX: u8 = 0x4F;
    pub const VEX2: u8 = 0xC5;
    pub const VEX3: u8 = 0xC4;
    pub const EVEX: u8 = 0x62;
    pub const REX2: u8 = 0xD5;
}

/// Prefix categories.
pub enum PrefixKind {
    None,
    Legacy,
    Rex,
    Vex2,
    Vex3,
    Evex,
    Rex2,
}

/// Classify a prefix byte.
pub fn classify_prefix(byte: u8) -> PrefixKind {
    match byte {
        0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => PrefixKind::Legacy, // Segment
        0x66 | 0x67 => PrefixKind::Legacy,                             // Operand/Address size
        0xF0 | 0xF2 | 0xF3 => PrefixKind::Legacy,                      // Lock/Rep
        0x40..=0x4F => PrefixKind::Rex,
        0xC5 => PrefixKind::Vex2,
        0xC4 => PrefixKind::Vex3,
        0x62 => PrefixKind::Evex,
        0xD5 => PrefixKind::Rex2,
        _ => PrefixKind::None,
    }
}

/// Check if this looks like an x86 prologue.
pub fn is_prologue(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }

    // 32-bit: push ebp; mov ebp, esp
    if data.len() >= 3 && data[0] == 0x55 && data[1] == 0x89 && data[2] == 0xE5 {
        return true;
    }

    // 64-bit: push rbp; mov rbp, rsp
    if data.len() >= 4 && data[0] == 0x55 && data[1] == 0x48 && data[2] == 0x89 && data[3] == 0xE5 {
        return true;
    }

    false
}

/// Check if this looks like an x86 epilogue.
pub fn is_epilogue(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // leave; ret
    if data.len() >= 2 && data[0] == 0xC9 && data[1] == 0xC3 {
        return true;
    }

    // pop rbp; ret
    if data.len() >= 2 && data[0] == 0x5D && data[1] == 0xC3 {
        return true;
    }

    // ret
    if data[0] == 0xC3 {
        return true;
    }

    false
}

/// Score likelihood of x86/x86-64 code.
///
/// Analyzes raw bytes for patterns characteristic of x86/x86-64:
/// - Common opcodes (NOP, RET, CALL, JMP, PUSH)
/// - Prefix bytes (REX for 64-bit, VEX/EVEX for extensions)
/// - Prologue patterns
/// - System calls
pub fn score(data: &[u8], bits: u8) -> i64 {
    let mut score: i64 = 0;
    let is_64 = bits == 64;
    let mut ret_count = 0u32;
    let mut call_count = 0u32;
    let mut prologue_count = 0u32;

    let mut i = 0;
    while i < data.len() {
        let b = data[i];

        // Check for prologue patterns (high confidence)
        if i + 3 < data.len() && is_prologue(&data[i..]) {
            score += 25;
            prologue_count += 1;
            i += 3;
            continue;
        }

        // Two-byte patterns (check before single-byte to avoid double-scoring)
        if i + 1 < data.len() {
            let next = data[i + 1];

            // SYSCALL (64-bit)
            if [b, next] == opcodes::SYSCALL {
                if is_64 { score += 20; } else { score -= 10; }
                i += 2;
                continue;
            }
            // INT 0x80 (32-bit syscall)
            if b == opcodes::INT && next == 0x80 {
                if is_64 { score -= 10; } else { score += 20; }
                i += 2;
                continue;
            }
            // UD2 (undefined instruction, often used as trap)
            if [b, next] == opcodes::UD2 {
                score += 5;
                i += 2;
                continue;
            }
            // Multi-byte NOP (0F 1F)
            if b == opcodes::TWO_BYTE && next == 0x1F {
                score += 8;
                i += 2;
                continue;
            }

            // REX prefix: only score when followed by a valid opcode
            if is_64 && (opcodes::REX_BASE..=opcodes::REX_MAX).contains(&b) {
                // REX + common opcodes (MOV, ADD, SUB, CMP, LEA, TEST, PUSH, POP, CALL)
                if matches!(next, 0x89 | 0x8B | 0x01 | 0x03 | 0x29 | 0x2B | 0x39 | 0x3B
                    | 0x83 | 0x8D | 0x85 | 0x50..=0x5F | 0x63 | 0xFF
                    | 0x0F | 0x31 | 0x33 | 0x21 | 0x23 | 0xC1 | 0xD3 | 0xF7
                    | 0xC7 | 0xB8..=0xBF) {
                    score += 6;
                    i += 2;
                    continue;
                }
                // REX without valid following opcode - no bonus
                i += 1;
                continue;
            }

            // VEX2 prefix - validate structure
            if b == opcodes::VEX2 && i + 2 < data.len() {
                let vex_byte = next;
                // VEX2: bit 7 = inverted R, bits 6:3 = vvvv, bit 2 = L, bits 1:0 = pp
                let pp = vex_byte & 0x03;
                if pp <= 2 {
                    // Valid pp values (0=none, 1=66, 2=F3, but not 3 usually)
                    score += 10;
                    i += 3;
                    continue;
                }
            }

            // VEX3 prefix - validate structure
            if b == opcodes::VEX3 && i + 3 < data.len() {
                let vex_b1 = next;
                let mmmmm = vex_b1 & 0x1F;
                // Valid map select: 1=0F, 2=0F38, 3=0F3A
                if matches!(mmmmm, 1 | 2 | 3) {
                    score += 10;
                    i += 4;
                    continue;
                }
            }

            // EVEX prefix - validate structure
            if b == opcodes::EVEX && i + 4 < data.len() {
                let p0 = next;
                // EVEX P0: bits 1:0 must be 0 (reserved)
                if (p0 & 0x03) == 0 {
                    // Check P0 map select (bits 1:0 of mmm field, which is bits 3:1 after shifting)
                    let mmm = (p0 >> 0) & 0x07; // Actually it's more complex, but basic check
                    if mmm <= 3 {
                        score += 15;
                        i += 5;
                        continue;
                    }
                }
            }
        }

        // Single-byte patterns
        match b {
            b if b == opcodes::NOP => score += 5,
            b if b == opcodes::RET => { score += 10; ret_count += 1; }
            b if b == opcodes::RET_IMM => {
                if i + 2 < data.len() {
                    score += 8;
                    i += 3; // opcode + 2-byte imm
                    continue;
                }
            }
            b if b == opcodes::INT3 => score += 8,
            b if b == opcodes::PUSH_EBP => {
                // push ebp/rbp - common prologue start
                score += 5;
            }
            b if b == opcodes::POP_EBP => {
                // pop ebp/rbp - common epilogue
                score += 3;
            }
            b if b == opcodes::CALL_REL32 => {
                // CALL rel32 - validate we have enough bytes
                if i + 4 < data.len() {
                    score += 6;
                    call_count += 1;
                    i += 5; // skip opcode + 4-byte offset
                    continue;
                }
            }
            b if b == opcodes::JMP_REL32 => {
                if i + 4 < data.len() {
                    score += 4;
                    i += 5;
                    continue;
                }
            }
            b if b == opcodes::JMP_REL8 => score += 2,
            b if b == opcodes::LEAVE => score += 5,
            0x8D => score += 3, // LEA
            0x70..=0x7F => score += 2, // Conditional jumps (Jcc rel8)
            // MOV r/m, r or MOV r, r/m (very common)
            0x89 | 0x8B => score += 3,
            // TEST r/m, r
            0x85 | 0x84 => score += 3,
            // CMP r/m, r or imm
            0x39 | 0x3B | 0x3C | 0x3D => score += 2,
            // ADD r/m, r or r, r/m
            0x01 | 0x03 => score += 2,
            // SUB r/m, r or r, r/m
            0x29 | 0x2B => score += 2,
            // XOR r/m, r (common for zeroing registers)
            0x31 | 0x33 => score += 2,
            // PUSH/POP registers (50-5F)
            0x50..=0x57 => score += 3,
            0x58..=0x5F => score += 3,
            // MOV immediate to register (B0-BF)
            0xB0..=0xBF => score += 2,
            // SUB/ADD r/m, imm8 (83 xx) - very common
            0x83 if i + 2 < data.len() => {
                let modrm = data[i + 1];
                let reg = (modrm >> 3) & 0x07;
                // ADD=0, SUB=5, CMP=7, AND=4, OR=1, XOR=6 are all common
                if matches!(reg, 0 | 1 | 4 | 5 | 6 | 7) {
                    score += 4;
                    i += 3;
                    continue;
                }
            }
            // 0F xx two-byte opcodes (MOVZX, MOVSX, Jcc rel32, SSE, etc.)
            0x0F if i + 1 < data.len() => {
                let next = data[i + 1];
                match next {
                    0xB6 | 0xB7 | 0xBE | 0xBF => { score += 4; i += 2; continue; } // MOVZX/MOVSX
                    0x80..=0x8F => { score += 4; i += 6; continue; } // Jcc rel32
                    0xAF => { score += 3; i += 2; continue; } // IMUL r, r/m
                    0x84 | 0x85 => { score += 3; i += 6; continue; } // JE/JNE rel32
                    // SSE/SSE2 packed operations (no prefix needed)
                    0x10 | 0x11 => { score += 5; i += 2; continue; } // MOVUPS/MOVUPD
                    0x28 | 0x29 => { score += 5; i += 2; continue; } // MOVAPS/MOVAPD
                    0x2A => { score += 5; i += 2; continue; } // CVTPI2PS
                    0x58 => { score += 4; i += 2; continue; } // ADDPS/ADDPD
                    0x59 => { score += 4; i += 2; continue; } // MULPS/MULPD
                    0x5A | 0x5B => { score += 3; i += 2; continue; } // CVTPS2PD
                    0x5C => { score += 4; i += 2; continue; } // SUBPS/SUBPD
                    0x5E => { score += 4; i += 2; continue; } // DIVPS/DIVPD
                    0x2E | 0x2F => { score += 4; i += 2; continue; } // UCOMISS/COMISS
                    0x51 => { score += 3; i += 2; continue; } // SQRTPS
                    0x54 | 0x55 | 0x56 | 0x57 => { score += 3; i += 2; continue; } // ANDPS/ANDNPS/ORPS/XORPS
                    _ => { score += 1; }
                }
            }
            // SSE2 scalar double: F2 0F xx
            0xF2 if i + 2 < data.len() && data[i + 1] == 0x0F => {
                let op = data[i + 2];
                match op {
                    0x10 | 0x11 => { score += 6; i += 3; continue; } // MOVSD
                    0x2A => { score += 6; i += 3; continue; } // CVTSI2SD
                    0x58 => { score += 5; i += 3; continue; } // ADDSD
                    0x59 => { score += 5; i += 3; continue; } // MULSD
                    0x5A => { score += 5; i += 3; continue; } // CVTSD2SS
                    0x5C => { score += 5; i += 3; continue; } // SUBSD
                    0x5E => { score += 5; i += 3; continue; } // DIVSD
                    0x2E | 0x2F => { score += 5; i += 3; continue; } // UCOMISD/COMISD
                    0x51 => { score += 4; i += 3; continue; } // SQRTSD
                    _ => { score += 2; i += 3; continue; }
                }
            }
            // SSE scalar single: F3 0F xx
            0xF3 if i + 2 < data.len() && data[i + 1] == 0x0F => {
                let op = data[i + 2];
                match op {
                    0x10 | 0x11 => { score += 6; i += 3; continue; } // MOVSS
                    0x2A => { score += 6; i += 3; continue; } // CVTSI2SS
                    0x58 => { score += 5; i += 3; continue; } // ADDSS
                    0x59 => { score += 5; i += 3; continue; } // MULSS
                    0x5A => { score += 5; i += 3; continue; } // CVTSS2SD
                    0x5C => { score += 5; i += 3; continue; } // SUBSS
                    0x5E => { score += 5; i += 3; continue; } // DIVSS
                    0x2E | 0x2F => { score += 5; i += 3; continue; } // UCOMISS
                    0x51 => { score += 4; i += 3; continue; } // SQRTSS
                    _ => { score += 2; i += 3; continue; }
                }
            }
            // Operand size prefix (common in 32-bit code)
            0x66 if !is_64 => score += 2,
            // Address size prefix
            0x67 => score += 1,
            // LOCK prefix
            0xF0 => score += 2,
            // REP/REPNE prefix (non-SSE uses)
            0xF2 | 0xF3 => score += 2,
            _ => {}
        }

        i += 1;
    }

    // Cross-architecture penalties: detect distinctive patterns from other ISAs
    // x86 is byte-level and matches most byte values, so we must penalize
    // data that contains known patterns from 32-bit BE or LE ISAs.
    {
        let mut j = 0;
        while j + 3 < data.len() {
            let be32 = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            let le32 = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);

            // PPC (big-endian)
            if be32 == 0x4E800020 { score -= 15; } // BLR
            if be32 == 0x60000000 { score -= 10; } // NOP
            if be32 == 0x7C0802A6 { score -= 12; } // MFLR r0
            if be32 == 0x7C0803A6 { score -= 12; } // MTLR r0
            // PPC STWU r1, -N(r1) = 0x9421xxxx (function prologue)
            if (be32 & 0xFFFF0000) == 0x94210000 { score -= 10; }
            // PPC STDU r1, -N(r1) = 0xF821xxxx (64-bit prologue)
            if (be32 & 0xFFFF0000) == 0xF8210000 { score -= 10; }

            // SPARC (big-endian)
            if be32 == 0x01000000 { score -= 10; } // NOP
            if be32 == 0x81C7E008 { score -= 15; } // RET
            if be32 == 0x81C3E008 { score -= 15; } // RETL
            // SPARC SAVE %sp, -N, %sp
            if (be32 & 0xFFFFE000) == 0x9DE3A000 { score -= 12; }

            // MIPS (big-endian)
            if be32 == 0x03E00008 { score -= 15; } // JR $ra

            // AArch64 (little-endian)
            if le32 == 0xD65F03C0 { score -= 15; } // RET
            if le32 == 0xD503201F { score -= 10; } // NOP

            // RISC-V (little-endian)
            if le32 == 0x00008067 { score -= 12; } // RET
            if le32 == 0x00000013 { score -= 8; }  // NOP

            j += 4;
        }
    }

    // Structural requirement: x86 is a byte-level ISA where most byte values
    // match some opcode or prefix. Real x86 code must contain distinctive
    // structural patterns like RET (0xC3), CALL (0xE8), or function prologues.
    // Without these, the data is likely from a 16-bit ISA (AVR, MSP430)
    // whose instruction bytes happen to match x86 patterns.
    if data.len() > 64 {
        let distinctive = ret_count + call_count + prologue_count;
        if distinctive == 0 {
            score = (score as f64 * 0.15) as i64;
        } else if ret_count == 0 && prologue_count == 0 {
            // Calls but no returns or prologues
            score = (score as f64 * 0.40) as i64;
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_prefix() {
        assert!(matches!(classify_prefix(0x48), PrefixKind::Rex));
        assert!(matches!(classify_prefix(0xC5), PrefixKind::Vex2));
        assert!(matches!(classify_prefix(0x62), PrefixKind::Evex));
    }

    #[test]
    fn test_prologue_detection() {
        assert!(is_prologue(&[0x55, 0x89, 0xE5]));
        assert!(is_prologue(&[0x55, 0x48, 0x89, 0xE5]));
    }

    #[test]
    fn test_score() {
        // x86 prologue
        assert!(score(&[0x55, 0x89, 0xE5], 32) > 0);
        // x86-64 with REX prefix
        assert!(score(&[0x48, 0x89, 0xE5], 64) > 0);
        // NOP sled
        assert!(score(&[0x90, 0x90, 0x90, 0x90], 32) > 0);
    }
}
