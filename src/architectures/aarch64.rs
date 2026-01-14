//! AArch64 architecture analysis.

/// AArch64 system instructions.
pub mod system {
    pub const NOP: u32 = 0xD503201F;
    pub const YIELD: u32 = 0xD503203F;
    pub const WFE: u32 = 0xD503205F;
    pub const WFI: u32 = 0xD503207F;
    pub const SEV: u32 = 0xD50320BF;
    pub const SEVL: u32 = 0xD50320DF;
    pub const PACIASP: u32 = 0xD503233F;
    pub const AUTIASP: u32 = 0xD50323BF;
    pub const BTI: u32 = 0xD503241F;
    pub const BTI_C: u32 = 0xD503245F;
    pub const BTI_J: u32 = 0xD503249F;
    pub const BTI_JC: u32 = 0xD50324DF;
}

/// AArch64 return instructions.
pub mod ret {
    pub const RET: u32 = 0xD65F03C0;
    pub const RETAA: u32 = 0xD65F0BFF;
    pub const RETAB: u32 = 0xD65F0FFF;
}

/// AArch64 encoding groups (bits [28:25]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingGroup {
    Reserved,
    DataProcessingImmediate,
    BranchExceptionSystem,
    LoadStore,
    DataProcessingRegister,
    SimdFp,
}

/// Get encoding group from instruction.
pub fn get_encoding_group(instr: u32) -> EncodingGroup {
    let group = (instr >> 25) & 0xF;

    // AArch64 encoding groups based on bits [28:25]
    match group {
        0b1000 | 0b1001 => EncodingGroup::DataProcessingImmediate, // 100x
        0b1010 | 0b1011 => EncodingGroup::BranchExceptionSystem,   // 101x  
        0b0100 | 0b0110 | 0b1100 | 0b1110 => EncodingGroup::LoadStore, // x1x0
        0b0101 | 0b1111 => EncodingGroup::DataProcessingRegister,  // x111
        0b0111 => EncodingGroup::SimdFp,                            // 0111
        _ => EncodingGroup::Reserved,
    }
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    let top6 = (instr >> 26) & 0x3F;
    // B, BL
    if top6 == 0x05 || top6 == 0x25 {
        return true;
    }
    // B.cond
    if (top6 & 0x3E) == 0x14 {
        return true;
    }
    // CBZ, CBNZ, TBZ, TBNZ
    if (top6 & 0x3C) == 0x34 {
        return true;
    }
    false
}

/// Check if instruction is BL (branch with link).
pub fn is_bl(instr: u32) -> bool {
    (instr >> 26) == 0x25
}

/// Check if instruction is a return.
pub fn is_ret(instr: u32) -> bool {
    // RET, RETAA, RETAB
    (instr & 0xFFFFFC1F) == 0xD65F0000
        || instr == ret::RETAA
        || instr == ret::RETAB
}

/// Check if instruction is STP (store pair) - common prologue.
pub fn is_stp(instr: u32) -> bool {
    let opc = (instr >> 22) & 0x1FF;
    opc == 0x150 || opc == 0x151
}

/// Check if instruction is LDP (load pair) - common epilogue.
pub fn is_ldp(instr: u32) -> bool {
    let opc = (instr >> 22) & 0x1FF;
    opc == 0x145 || opc == 0x144
}

/// Check if instruction uses PAC (pointer authentication).
pub fn uses_pac(instr: u32) -> bool {
    // PACIASP, AUTIASP
    if instr == system::PACIASP || instr == system::AUTIASP {
        return true;
    }
    // PAC* instructions
    if (instr & 0xFFFFF800) == 0xDAC10000 {
        return true;
    }
    false
}

/// Check if instruction is BTI.
pub fn is_bti(instr: u32) -> bool {
    (instr & 0xFFFFFF3F) == system::BTI
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_detection() {
        // BL
        assert!(is_bl(0x94000000));
        // B
        assert!(is_branch(0x14000000));
        assert!(!is_bl(0x14000000));
    }

    #[test]
    fn test_ret_detection() {
        assert!(is_ret(ret::RET));
        assert!(is_ret(ret::RETAA));
    }

    #[test]
    fn test_pac_detection() {
        assert!(uses_pac(system::PACIASP));
        assert!(uses_pac(system::AUTIASP));
    }
}
