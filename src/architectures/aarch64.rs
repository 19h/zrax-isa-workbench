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
    pub const ERET: u32 = 0xD69F03E0;
    pub const ERETAA: u32 = 0xD69F0BFF;
    pub const ERETAB: u32 = 0xD69F0FFF;
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
        0b0111 => EncodingGroup::SimdFp,                           // 0111
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
    (instr & 0xFFFFFC1F) == 0xD65F0000 || instr == ret::RETAA || instr == ret::RETAB
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

/// Check if instruction is MRS (move from system register).
/// Pattern: 1101 0101 0011 .... .... .... .... .... = 0xD53xxxxx
pub fn is_mrs(instr: u32) -> bool {
    (instr >> 20) == 0xD53
}

/// Check if instruction is MSR (move to system register).
/// Pattern: 1101 0101 0001 .... .... .... .... .... = 0xD51xxxxx
pub fn is_msr(instr: u32) -> bool {
    (instr >> 20) == 0xD51
}

/// Check if instruction is ERET (exception return).
pub fn is_eret(instr: u32) -> bool {
    instr == ret::ERET || instr == ret::ERETAA || instr == ret::ERETAB
}

/// Check if instruction is a memory barrier (DSB, DMB, ISB).
/// DSB: 0xD503309F | (CRm << 8)
/// DMB: 0xD50330BF | (CRm << 8)
/// ISB: 0xD50330DF | (CRm << 8)
pub fn is_barrier(instr: u32) -> bool {
    // Check for DSB/DMB/ISB pattern
    (instr & 0xFFFFF01F) == 0xD503301F
}

/// Check if instruction is MOV (register) via ORR with XZR.
/// MOV Xd, Xm = ORR Xd, XZR, Xm
/// Pattern: 1010 1010 000x xxxx 0000 0011 111x xxxx = 0xAA0003E0 (with variations)
pub fn is_mov_reg(instr: u32) -> bool {
    // 64-bit MOV via ORR Xd, XZR, Xm (shift=0)
    // Check: sf=1, opc=01, fixed=01010, shift=00, N=0, imm6=0, Rn=XZR(31)
    ((instr & 0xFFE0FFE0) == 0xAA0003E0)
        // Also check 32-bit variant: sf=0
        || ((instr & 0xFFE0FFE0) == 0x2A0003E0)
}

/// Check if instruction is ADRP (address of page).
/// Pattern: 1 immlo op=1 00000 immhi Rd = 0x90000000 | ...
pub fn is_adrp(instr: u32) -> bool {
    (instr & 0x9F000000) == 0x90000000
}

/// Check if instruction is ADR (address).
/// Pattern: 0 immlo op=0 00000 immhi Rd = 0x10000000 | ...
pub fn is_adr(instr: u32) -> bool {
    (instr & 0x9F000000) == 0x10000000
}

/// Check if instruction is a conditional branch (B.cond).
/// Pattern: 0101 0100 xxxx xxxx xxxx xxxx xxx0 cond = 0x54000000 | imm19 << 5 | cond
pub fn is_bcond(instr: u32) -> bool {
    (instr & 0xFF000010) == 0x54000000
}

/// Check if instruction is CBZ or CBNZ.
/// Pattern: x011 010x xxxx xxxx xxxx xxxx xxxx xxxx
pub fn is_cbz_cbnz(instr: u32) -> bool {
    (instr & 0x7E000000) == 0x34000000
}

/// Check if instruction is TBZ or TBNZ.
/// Pattern: x011 011x xxxx xxxx xxxx xxxx xxxx xxxx  
pub fn is_tbz_tbnz(instr: u32) -> bool {
    (instr & 0x7E000000) == 0x36000000
}

/// Check if instruction is LDR/STR (immediate).
/// Pattern varies but common forms have high bits 0xB9/0xF9 (loads) or 0xB8/0xF8 (stores)
pub fn is_ldr_str_imm(instr: u32) -> bool {
    let top8 = (instr >> 24) as u8;
    matches!(top8, 0xB9 | 0xF9 | 0xB8 | 0xF8 | 0x39 | 0x79 | 0x38 | 0x78)
}

/// Check if instruction is a compare (CMP/CMN) or test (TST).
/// CMP = SUBS Xd, Xn, #imm with Rd=31 or SUBS Xd, Xn, Xm with Rd=31
/// CMN = ADDS with Rd=31
/// TST = ANDS with Rd=31
pub fn is_compare_test(instr: u32) -> bool {
    // Check for SUBS/ADDS/ANDS immediate or register with Rd=31 (XZR/WZR)
    let rd = instr & 0x1F;
    if rd != 31 {
        return false;
    }
    // SUBS immediate: 111 10001 xx ...
    // ADDS immediate: 101 10001 xx ...
    // ANDS immediate: x11 10010 0x ...
    let top9 = (instr >> 23) & 0x1FF;
    matches!(top9, 0x1F1 | 0x171 | 0x1E4 | 0x164)
}

/// Check if instruction is MOVZ/MOVK/MOVN (move wide immediate).
/// Very common for loading constants.
/// MOVZ: 1x0 10010 1xx ... = 0x52800000 (32-bit), 0xD2800000 (64-bit)
/// MOVK: 1x1 10010 1xx ... = 0x72800000 (32-bit), 0xF2800000 (64-bit)
/// MOVN: 0x0 10010 1xx ... = 0x12800000 (32-bit), 0x92800000 (64-bit)
pub fn is_mov_wide(instr: u32) -> bool {
    let top8 = (instr >> 24) as u8;
    matches!(top8, 0x52 | 0x72 | 0x12 | 0xD2 | 0xF2 | 0x92)
}

/// Check if instruction is BR or BLR (indirect branch via register).
/// BR Xn:  1101 0110 0001 1111 0000 00nn nnn0 0000 = 0xD61F0000 | (Rn << 5)
/// BLR Xn: 1101 0110 0011 1111 0000 00nn nnn0 0000 = 0xD63F0000 | (Rn << 5)
pub fn is_br_blr(instr: u32) -> bool {
    (instr & 0xFFFFFC1F) == 0xD61F0000 || (instr & 0xFFFFFC1F) == 0xD63F0000
}

/// Check if instruction is a bitfield operation (UBFM, SBFM, BFM).
/// These encode LSL, LSR, ASR, UBFX, SBFX, BFI, BFXIL, etc.
/// x01 10011 0x ... = SBFM: 0x13000000 (32-bit), 0x93400000 (64-bit)
/// x10 10011 0x ... = BFM:  0x33000000 (32-bit), 0xB3400000 (64-bit)
/// x11 10011 0x ... = UBFM: 0x53000000 (32-bit), 0xD3400000 (64-bit)
pub fn is_bitfield(instr: u32) -> bool {
    let top8 = (instr >> 24) as u8;
    matches!(top8, 0x13 | 0x33 | 0x53 | 0x93 | 0xB3 | 0xD3)
}

/// Check if instruction is ADD/SUB register (not immediate).
/// ADD reg: x00 01011 xx0 ... = 0x0B000000 (32-bit), 0x8B000000 (64-bit)
/// SUB reg: x10 01011 xx0 ... = 0x4B000000 (32-bit), 0xCB000000 (64-bit)
pub fn is_add_sub_reg(instr: u32) -> bool {
    let top8 = (instr >> 24) as u8;
    matches!(top8, 0x0B | 0x2B | 0x4B | 0x6B | 0x8B | 0xAB | 0xCB | 0xEB)
}

/// Check if instruction is a logical operation (AND, ORR, EOR, etc.) immediate.
/// x01 10010 0x ... = AND/ORR/EOR/ANDS immediate
pub fn is_logical_imm(instr: u32) -> bool {
    let top7 = (instr >> 25) & 0x7F;
    top7 == 0x24 || top7 == 0x64 // 010 0100 or 110 0100
}

/// Check if instruction is MADD/MSUB (multiply-add).
/// Highly distinctive: x00 11011 000 Rm 0 Ra Rn Rd
pub fn is_madd_msub(instr: u32) -> bool {
    (instr & 0x7FE08000) == 0x1B000000
}

/// Check if instruction is CSEL/CSINC/CSINV/CSNEG (conditional select).
/// x00 11010 100 Rm cond 0x Rn Rd
pub fn is_csel(instr: u32) -> bool {
    (instr & 0x7FE00C00) == 0x1A800000
}

/// Score likelihood of AArch64 code.
///
/// Analyzes raw bytes for patterns characteristic of AArch64:
/// - Fixed 32-bit instructions
/// - Encoding groups in bits [28:25]
/// - Common patterns (NOP, RET, SVC)
/// - System register access (MRS/MSR) - critical for kernel/firmware code
/// - Exception handling (ERET) - critical for exception handlers
/// - Memory barriers (DSB, DMB, ISB)
/// - Multi-instruction patterns (prologues, epilogues, exception handlers)
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut zero_run: u32 = 0;
    let mut prev_was_zero = false;
    let mut prev_instr: u32 = 0;
    let mut prev_prev_instr: u32 = 0;

    // AArch64 instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Multi-instruction pattern detection (very high value - unique to AArch64)

        // Function prologue: STP x29, x30, [sp, #-N]! followed by MOV x29, sp (ADD x29, sp, #0)
        // STP pre-index: 1x10 1001 1xxx xxxx xxxx xxxx xxxx xxxx = 0xA9800000 mask 0xFFC00000
        // MOV x29, sp (via ADD): 1001 0001 00xx xxxx xxxx xx11 1111 1101 = 0x910003FD
        if (prev_instr & 0xFFC003FF) == 0xA98003FD && word == 0x910003FD {
            // STP x29, x30, [sp, #-N]! followed by MOV x29, sp
            score += 50;
        }

        // Function epilogue: LDP x29, x30, [sp], #N followed by RET
        // LDP post-index: 1x10 1000 11xx xxxx xxxx xxxx xxxx xxxx = 0xA8C00000 mask 0xFFC00000
        if (prev_instr & 0xFFC003FF) == 0xA8C003FD && word == ret::RET {
            score += 50;
        }

        // Exception vector pattern: MRS followed by MRS followed by MRS
        // This is the pattern we see in rkos: 3 MRS instructions reading exception state
        if is_mrs(prev_prev_instr) && is_mrs(prev_instr) && is_mrs(word) {
            score += 60;
        }

        // MRS followed by MRS followed by B (exception vector entry)
        if is_mrs(prev_prev_instr) && is_mrs(prev_instr) && is_branch(word) && !is_bl(word) {
            score += 50;
        }

        // BL followed by MOV x0, xN (common call + result handling)
        if is_bl(prev_instr) && is_mov_reg(word) && (word & 0x1F) == 0 {
            score += 25;
        }

        // System register block: MSR followed by ISB/DSB
        if is_msr(prev_instr) && is_barrier(word) {
            score += 40;
        }

        // ADRP followed by ADD/LDR (PC-relative addressing pattern)
        if is_adrp(prev_instr) {
            let prev_rd = prev_instr & 0x1F;
            let curr_rn = (word >> 5) & 0x1F;
            // Check if ADRP destination is used as base in ADD or LDR
            if prev_rd == curr_rn {
                if (word >> 24) & 0x1F == 0x11 {
                    // ADD immediate
                    score += 35;
                } else if is_ldr_str_imm(word) {
                    score += 35;
                }
            }
        }

        // Update instruction history
        prev_prev_instr = prev_instr;
        prev_instr = word;

        // NOP
        if word == system::NOP {
            score += 25;
        }

        // RET
        if word == ret::RET {
            score += 30;
        }

        // RETAA (PAC return)
        if word == ret::RETAA {
            score += 25;
        }

        // RETAB
        if word == ret::RETAB {
            score += 25;
        }

        // ERET (exception return) - highly distinctive for firmware/kernel
        if is_eret(word) {
            score += 40;
        }

        // MRS (read system register) - very distinctive for AArch64
        // Common in kernel/firmware code for accessing system control registers
        if is_mrs(word) {
            score += 35;
        }

        // MSR (write system register) - very distinctive for AArch64
        if is_msr(word) {
            score += 35;
        }

        // Memory barriers (DSB, DMB, ISB) - distinctive system instructions
        if is_barrier(word) {
            score += 25;
        }

        // BL (branch with link)
        if is_bl(word) {
            score += 10;
        }

        // B (unconditional branch)
        if is_branch(word) && !is_bl(word) {
            score += 8;
        }

        // SVC (system call)
        if (word & 0xFFE0001F) == 0xD4000001 {
            score += 20;
        }

        // HVC (hypervisor call)
        if (word & 0xFFE0001F) == 0xD4000002 {
            score += 25;
        }

        // SMC (secure monitor call)
        if (word & 0xFFE0001F) == 0xD4000003 {
            score += 25;
        }

        // BRK (breakpoint)
        if (word & 0xFFE0001F) == 0xD4200000 {
            score += 15;
        }

        // BTI (branch target identification)
        if is_bti(word) {
            score += 20;
        }

        // PACIASP (pointer authentication)
        if word == system::PACIASP {
            score += 20;
        }

        // AUTIASP
        if word == system::AUTIASP {
            score += 20;
        }

        // STP (store pair - common in prologue)
        if is_stp(word) {
            score += 10;
        }

        // LDP (load pair - common in epilogue)
        if is_ldp(word) {
            score += 10;
        }

        // MOV (register) via ORR - very common
        if is_mov_reg(word) {
            score += 8;
        }

        // ADRP (address of page) - common for PC-relative addressing
        if is_adrp(word) {
            score += 12;
        }

        // ADR (address) - common for PC-relative addressing
        if is_adr(word) {
            score += 10;
        }

        // Conditional branches (B.cond) - very common in code
        if is_bcond(word) {
            score += 12;
        }

        // CBZ/CBNZ - compare and branch
        if is_cbz_cbnz(word) {
            score += 10;
        }

        // TBZ/TBNZ - test and branch
        if is_tbz_tbnz(word) {
            score += 10;
        }

        // LDR/STR immediate - common load/store patterns
        if is_ldr_str_imm(word) {
            score += 8;
        }

        // CMP/CMN/TST - comparison and test instructions
        if is_compare_test(word) {
            score += 10;
        }

        // MOV wide (MOVZ/MOVK/MOVN) - very common for loading constants
        if is_mov_wide(word) {
            score += 10;
        }

        // BR/BLR (indirect branch) - common for function pointers, vtables
        if is_br_blr(word) {
            score += 15;
        }

        // Bitfield operations (UBFM/SBFM/BFM encode LSL, LSR, ASR, etc.)
        if is_bitfield(word) {
            score += 8;
        }

        // ADD/SUB register
        if is_add_sub_reg(word) {
            score += 6;
        }

        // Logical immediate (AND/ORR/EOR with immediate)
        if is_logical_imm(word) {
            score += 6;
        }

        // MADD/MSUB - multiply-add is distinctive
        if is_madd_msub(word) {
            score += 12;
        }

        // CSEL/CSINC/CSINV/CSNEG - conditional select is very AArch64-specific
        if is_csel(word) {
            score += 12;
        }

        // ADD/SUB immediate (original detection)
        if (word >> 24) & 0x1F == 0x11 {
            score += 5;
        }

        // Check encoding groups
        let group = get_encoding_group(word);
        match group {
            EncodingGroup::DataProcessingImmediate => score += 2,
            EncodingGroup::BranchExceptionSystem => score += 2,
            EncodingGroup::LoadStore => score += 2,
            EncodingGroup::DataProcessingRegister => score += 2,
            _ => {}
        }

        // Handle zero words more gracefully:
        // - Single zeros in vector tables are normal (exception entry padding)
        // - Penalize only long runs of zeros (likely data, not code)
        if word == 0x00000000 {
            zero_run += 1;
            if prev_was_zero && zero_run > 4 {
                // Only penalize after seeing 4+ consecutive zeros
                score -= 2;
            }
            prev_was_zero = true;
        } else {
            prev_was_zero = false;
            zero_run = 0;
        }

        // Heavy penalty for all-ones (very unlikely in valid code)
        if word == 0xFFFFFFFF {
            score -= 15;
        }
    }

    score.max(0)
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
    fn test_eret_detection() {
        assert!(is_eret(ret::ERET));
        assert!(is_eret(ret::ERETAA));
        assert!(is_eret(ret::ERETAB));
        assert!(!is_eret(ret::RET));
    }

    #[test]
    fn test_pac_detection() {
        assert!(uses_pac(system::PACIASP));
        assert!(uses_pac(system::AUTIASP));
    }

    #[test]
    fn test_mrs_msr_detection() {
        // MRS x0, VBAR_EL1 (from rkos file)
        assert!(is_mrs(0xD538C000));
        // MRS x28, VBAR_EL1 (actual from rkos: 0xD538521C)
        assert!(is_mrs(0xD538521C));
        // MSR VBAR_EL1, x1
        assert!(is_msr(0xD518C001));
        // Not MRS/MSR
        assert!(!is_mrs(ret::RET));
        assert!(!is_msr(ret::RET));
    }

    #[test]
    fn test_barrier_detection() {
        // DSB SY (0xD503309F)
        assert!(is_barrier(0xD503309F));
        // DMB SY (0xD50330BF)
        assert!(is_barrier(0xD50330BF));
        // ISB (0xD50330DF)
        assert!(is_barrier(0xD50330DF));
        // DSB with different option
        assert!(is_barrier(0xD5033F9F));
        // Not a barrier
        assert!(!is_barrier(ret::RET));
    }

    #[test]
    fn test_mov_reg_detection() {
        // MOV X0, X0 (0xAA0003E0)
        assert!(is_mov_reg(0xAA0003E0));
        // MOV X1, X1 (0xAA0103E1)
        assert!(is_mov_reg(0xAA0103E1));
        // Not MOV reg
        assert!(!is_mov_reg(ret::RET));
    }

    #[test]
    fn test_adr_adrp_detection() {
        // ADRP X0, <addr>
        assert!(is_adrp(0x90000000));
        assert!(is_adrp(0xB0000000));
        // ADR X0, <addr>
        assert!(is_adr(0x10000000));
        assert!(is_adr(0x30000000));
        // Not ADR/ADRP
        assert!(!is_adrp(ret::RET));
        assert!(!is_adr(ret::RET));
    }

    #[test]
    fn test_score() {
        // AArch64 NOP
        let nop = system::NOP.to_le_bytes();
        assert!(score(&nop) > 0);
        // RET
        let ret_bytes = ret::RET.to_le_bytes();
        assert!(score(&ret_bytes) > 0);
    }

    #[test]
    fn test_score_firmware_patterns() {
        // Simulate a firmware-like pattern with MRS instructions and vector table structure
        // This mimics what we see in rkos: MRS instructions followed by branch
        let mut data = Vec::new();

        // Exception vector entry: MRS x28, reg; MRS x29, reg; MRS x30, reg; B .
        data.extend_from_slice(&0xD538521Cu32.to_le_bytes()); // MRS x28, VBAR_EL1
        data.extend_from_slice(&0xD538601Du32.to_le_bytes()); // MRS x29, FAR_EL1
        data.extend_from_slice(&0xD538403Eu32.to_le_bytes()); // MRS x30, ESR_EL1
        data.extend_from_slice(&0x14000000u32.to_le_bytes()); // B .

        // Some zeros (padding) - should not heavily penalize
        for _ in 0..4 {
            data.extend_from_slice(&0u32.to_le_bytes());
        }

        // More code
        data.extend_from_slice(&0xD69F03E0u32.to_le_bytes()); // ERET

        let s = score(&data);
        // Should score well due to 3 MRS + 1 B + 1 ERET
        // 35*3 + 8 + 40 = 153 minimum from these alone
        assert!(
            s >= 100,
            "Score {} should be >= 100 for firmware pattern",
            s
        );
    }
}
