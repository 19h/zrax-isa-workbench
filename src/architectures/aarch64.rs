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
    let mut ret_count = 0u32;
    let mut mrs_msr_count = 0u32;
    let mut prologue_count = 0u32;
    let mut bl_count = 0u32;
    let mut stp_fp_lr_count = 0u32;
    let mut extra_distinctive = 0u32; // barriers, system calls, BTI, PAC, CSEL, MADD, etc.

    // AArch64 instructions are 4 bytes, aligned
    let num_words = data.len() / 4;
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // --- Cross-architecture penalties for 16-bit LE ISAs ---
        // Check both halfwords for distinctive 16-bit LE patterns
        {
            let hw0 = u16::from_le_bytes([data[i], data[i + 1]]);
            let hw1 = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            // MSP430
            if hw0 == 0x4130 || hw1 == 0x4130 { score -= 15; continue; } // MSP430 RET
            if hw0 == 0x4303 || hw1 == 0x4303 { score -= 10; }           // MSP430 NOP
            if hw0 == 0x1300 || hw1 == 0x1300 { score -= 10; continue; } // MSP430 RETI
            // AVR
            if hw0 == 0x9508 || hw1 == 0x9508 { score -= 15; continue; } // AVR RET
            if hw0 == 0x9518 || hw1 == 0x9518 { score -= 12; continue; } // AVR RETI
            // Thumb
            if hw0 == 0x4770 || hw1 == 0x4770 { score -= 12; continue; } // Thumb BX LR
            if hw0 == 0xBF00 || hw1 == 0xBF00 { score -= 8; }            // Thumb NOP
            // Thumb PUSH {.., LR} / POP {.., PC}
            if (hw0 & 0xFF00) == 0xB500 || (hw1 & 0xFF00) == 0xB500 { score -= 6; }
            if (hw0 & 0xFF00) == 0xBD00 || (hw1 & 0xFF00) == 0xBD00 { score -= 6; }
        }

        // --- Cross-architecture penalties for other 32-bit LE ISAs ---
        // RISC-V
        if word == 0x00008067 { score -= 15; continue; } // RISC-V RET
        if word == 0x00000013 { score -= 10; continue; } // RISC-V NOP

        // Multi-instruction pattern detection (very high value - unique to AArch64)

        // Function prologue: STP x29, x30, [sp, #-N]! followed by MOV x29, sp (ADD x29, sp, #0)
        // STP pre-index: 1x10 1001 1xxx xxxx xxxx xxxx xxxx xxxx = 0xA9800000 mask 0xFFC00000
        // MOV x29, sp (via ADD): 1001 0001 00xx xxxx xxxx xx11 1111 1101 = 0x910003FD
        if (prev_instr & 0xFFC003FF) == 0xA98003FD && word == 0x910003FD {
            // STP x29, x30, [sp, #-N]! followed by MOV x29, sp
            score += 80; // Boosted - very distinctive AArch64 function boundary
            prologue_count += 1;
        }

        // Function epilogue: LDP x29, x30, [sp], #N followed by RET
        // LDP post-index: 1x10 1000 11xx xxxx xxxx xxxx xxxx xxxx = 0xA8C00000 mask 0xFFC00000
        if (prev_instr & 0xFFC003FF) == 0xA8C003FD && word == ret::RET {
            score += 80; // Boosted - very distinctive AArch64 function boundary
        }

        // Exception vector pattern: MRS followed by MRS followed by MRS
        // This is the pattern we see in rkos: 3 MRS instructions reading exception state
        if is_mrs(prev_prev_instr) && is_mrs(prev_instr) && is_mrs(word) {
            score += 100; // Boosted - extremely distinctive
        }

        // MRS followed by MRS followed by B (exception vector entry)
        if is_mrs(prev_prev_instr) && is_mrs(prev_instr) && is_branch(word) && !is_bl(word) {
            score += 80; // Boosted
        }

        // BL followed by MOV x0, xN (common call + result handling)
        if is_bl(prev_instr) && is_mov_reg(word) && (word & 0x1F) == 0 {
            score += 35;
        }

        // System register block: MSR followed by ISB/DSB
        if is_msr(prev_instr) && is_barrier(word) {
            score += 60; // Boosted
        }

        // ADRP followed by ADD/LDR (PC-relative addressing pattern)
        if is_adrp(prev_instr) {
            let prev_rd = prev_instr & 0x1F;
            let curr_rn = (word >> 5) & 0x1F;
            // Check if ADRP destination is used as base in ADD or LDR
            if prev_rd == curr_rn {
                if (word >> 24) & 0x1F == 0x11 {
                    // ADD immediate
                    score += 50; // Boosted - very distinctive pattern
                } else if is_ldr_str_imm(word) {
                    score += 50; // Boosted
                }
            }
        }

        // Update instruction history
        prev_prev_instr = prev_instr;
        prev_instr = word;

        // NOP
        if word == system::NOP {
            score += 30;
        }

        // RET - very distinctive encoding
        if word == ret::RET {
            score += 40; // Boosted - specific encoding
            ret_count += 1;
        }

        // RETAA (PAC return) - extremely distinctive ARMv8.3-A feature
        if word == ret::RETAA {
            score += 40;
            ret_count += 1;
        }

        // RETAB
        if word == ret::RETAB {
            score += 40;
            ret_count += 1;
        }

        // ERET (exception return) - highly distinctive for firmware/kernel
        if is_eret(word) {
            score += 50; // Boosted
            ret_count += 1;
        }

        // MRS (read system register) - VERY distinctive for AArch64
        // Common in kernel/firmware code for accessing system control registers
        if is_mrs(word) {
            score += 50; // Boosted - this is a key AArch64 differentiator
            mrs_msr_count += 1;
        }

        // MSR (write system register) - VERY distinctive for AArch64
        if is_msr(word) {
            score += 50; // Boosted - this is a key AArch64 differentiator
            mrs_msr_count += 1;
        }

        // Memory barriers (DSB, DMB, ISB) - distinctive system instructions
        if is_barrier(word) {
            score += 35;
            extra_distinctive += 1;
        }

        // BL (branch with link)
        if is_bl(word) {
            score += 8;
            bl_count += 1;
        }

        // B (unconditional branch)
        if is_branch(word) && !is_bl(word) {
            score += 5;
        }

        // SVC (system call)
        if (word & 0xFFE0001F) == 0xD4000001 {
            score += 20;
            extra_distinctive += 1;
        }

        // HVC (hypervisor call)
        if (word & 0xFFE0001F) == 0xD4000002 {
            score += 25;
            extra_distinctive += 1;
        }

        // SMC (secure monitor call)
        if (word & 0xFFE0001F) == 0xD4000003 {
            score += 25;
            extra_distinctive += 1;
        }

        // BRK (breakpoint)
        if (word & 0xFFE0001F) == 0xD4200000 {
            score += 15;
            extra_distinctive += 1;
        }

        // BTI (branch target identification)
        if is_bti(word) {
            score += 20;
            extra_distinctive += 1;
        }

        // PACIASP (pointer authentication)
        if word == system::PACIASP {
            score += 20;
            extra_distinctive += 1;
        }

        // AUTIASP
        if word == system::AUTIASP {
            score += 20;
            extra_distinctive += 1;
        }

        // STP (store pair - common in prologue)
        if is_stp(word) {
            score += 10;
            // Track STP involving x29 (FP) and x30 (LR) - very distinctive prologue marker
            let rt = word & 0x1F;
            let rt2 = (word >> 10) & 0x1F;
            if rt == 29 && rt2 == 30 {
                stp_fp_lr_count += 1;
            }
        }

        // LDP (load pair - common in epilogue)
        if is_ldp(word) {
            score += 10;
            let rt = word & 0x1F;
            let rt2 = (word >> 10) & 0x1F;
            if rt == 29 && rt2 == 30 {
                stp_fp_lr_count += 1;
            }
        }

        // MOV (register) via ORR - very common
        if is_mov_reg(word) {
            score += 10;
        }

        // ADRP (address of page) - broad mask, reduce score
        if is_adrp(word) {
            score += 10;
        }

        // ADR (address) - broad mask
        if is_adr(word) {
            score += 5;
        }

        // Conditional branches (B.cond)
        if is_bcond(word) {
            score += 6;
        }

        // CBZ/CBNZ - compare and branch
        if is_cbz_cbnz(word) {
            score += 5;
        }

        // TBZ/TBNZ - test and branch
        if is_tbz_tbnz(word) {
            score += 5;
        }

        // LDR/STR immediate - common load/store patterns
        if is_ldr_str_imm(word) {
            score += 3;
        }

        // CMP/CMN/TST - comparison and test instructions
        if is_compare_test(word) {
            score += 5;
        }

        // MOV wide (MOVZ/MOVK/MOVN)
        if is_mov_wide(word) {
            score += 5;
        }

        // BR/BLR (indirect branch) - distinctive
        if is_br_blr(word) {
            score += 12;
        }

        // Bitfield operations (UBFM/SBFM/BFM encode LSL, LSR, ASR, etc.)
        if is_bitfield(word) {
            score += 4;
        }

        // ADD/SUB register
        if is_add_sub_reg(word) {
            score += 3;
        }

        // Logical immediate (AND/ORR/EOR with immediate)
        if is_logical_imm(word) {
            score += 3;
        }

        // MADD/MSUB - multiply-add is distinctive
        if is_madd_msub(word) {
            score += 10;
            extra_distinctive += 1;
        }

        // CSEL/CSINC/CSINV/CSNEG - conditional select is very AArch64-specific
        if is_csel(word) {
            score += 10;
            extra_distinctive += 1;
        }

        // ADD/SUB immediate
        if (word >> 24) & 0x1F == 0x11 {
            score += 3;
        }

        // Floating-point data processing (scalar): 0x1Exxxxxx
        // Covers FMOV, FADD, FSUB, FMUL, FDIV, FABS, FNEG, FSQRT, FCMP, FCVT, etc.
        // Very distinctive AArch64 encoding range
        if (word >> 24) as u8 == 0x1E {
            score += 6;
        }

        // FP/SIMD load/store (different from integer LDR/STR encodings)
        {
            let top8 = (word >> 24) as u8;
            if matches!(top8, 0xBD | 0xFD | 0x3D | 0x7D | 0xBC | 0xFC | 0x3C | 0x7C) {
                score += 4;
            }
        }

        // Advanced SIMD data processing: 0x0Exxxxxx, 0x4Exxxxxx, 0x0Fxxxxxx, 0x4Fxxxxxx
        {
            let top8 = (word >> 24) as u8;
            if matches!(top8, 0x0E | 0x4E | 0x0F | 0x4F | 0x2E | 0x6E | 0x2F | 0x6F) {
                score += 5;
            }
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

    // Structural requirement: for meaningful-length data, require distinctive patterns
    // AArch64 has broad pattern matches (~20-25% of random words score), so without
    // this check, random data from 16-bit ISAs (MSP430, AVR) accumulates high scores
    if num_words > 20 {
        let distinctive = ret_count + mrs_msr_count + prologue_count + stp_fp_lr_count + extra_distinctive;
        if distinctive == 0 && bl_count == 0 {
            score = (score as f64 * 0.15) as i64;
        } else if distinctive == 0 && bl_count >= 3 {
            // Multiple BL calls suggest real code even without returns/prologues
            score = (score as f64 * 0.50) as i64;
        } else if distinctive == 0 {
            // Has BL calls but no returns/system regs/prologues
            score = (score as f64 * 0.35) as i64;
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
