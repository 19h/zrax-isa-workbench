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
}
