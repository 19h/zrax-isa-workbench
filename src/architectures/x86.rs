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
        0x66 | 0x67 => PrefixKind::Legacy, // Operand/Address size
        0xF0 | 0xF2 | 0xF3 => PrefixKind::Legacy, // Lock/Rep
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

    let mut i = 0;
    while i < data.len() {
        let b = data[i];

        // Single-byte patterns using architecture constants
        match b {
            b if b == opcodes::NOP => score += 5,
            b if b == opcodes::RET => score += 10,
            b if b == opcodes::INT3 => score += 8,
            b if b == opcodes::PUSH_EBP => score += 10,
            b if b == opcodes::CALL_REL32 => score += 8,
            b if b == opcodes::JMP_REL32 => score += 5,
            b if b == opcodes::JMP_REL8 => score += 3,
            0x8D => score += 3, // LEA
            0xB8..=0xBF => score += 2, // MOV immediate
            0x70..=0x7F => score += 3, // Conditional jumps
            _ => {}
        }

        // REX prefix (64-bit indicator)
        if is_64 && (opcodes::REX_BASE..=opcodes::REX_MAX).contains(&b) {
            score += 8;
        }

        // Legacy prefixes (not great for 64-bit code but common)
        if !is_64 && b == 0x66 {
            score += 2;
        }

        // Two-byte patterns
        if i + 1 < data.len() {
            let next = data[i + 1];

            // SYSCALL (64-bit)
            if [b, next] == opcodes::SYSCALL {
                if is_64 {
                    score += 20;
                } else {
                    score -= 10;
                }
            }
            // INT 0x80 (32-bit syscall)
            else if b == opcodes::INT && next == 0x80 {
                if is_64 {
                    score -= 10;
                } else {
                    score += 20;
                }
            }
            // UD2 (undefined instruction, often used as trap)
            else if [b, next] == opcodes::UD2 {
                score += 5;
            }
            // Multi-byte NOP (0F 1F)
            else if b == opcodes::TWO_BYTE && next == 0x1F {
                score += 8;
            }
            // MOV r/m, r (common)
            else if matches!(b, 0x89 | 0x8B) {
                score += 2;
            }
            // TEST r/m, r
            else if matches!(b, 0x85 | 0x84) {
                score += 2;
            }
            // CMP r/m, r
            else if matches!(b, 0x39 | 0x3B) {
                score += 2;
            }
        }

        // VEX prefix (AVX)
        if b == opcodes::VEX2 && i + 2 < data.len() {
            score += 15;
        }
        if b == opcodes::VEX3 && i + 3 < data.len() {
            score += 15;
        }

        // EVEX prefix (AVX-512)
        if b == opcodes::EVEX && i + 4 < data.len() {
            score += 20;
        }

        // Check for prologue patterns
        if i + 3 < data.len() && is_prologue(&data[i..]) {
            score += 25;
        }

        i += 1;
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
