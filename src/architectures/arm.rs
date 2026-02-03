//! ARM32 architecture analysis.

/// ARM condition codes.
pub mod condition {
    pub const EQ: u8 = 0x0; // Equal
    pub const NE: u8 = 0x1; // Not equal
    pub const CS: u8 = 0x2; // Carry set / unsigned higher or same
    pub const CC: u8 = 0x3; // Carry clear / unsigned lower
    pub const MI: u8 = 0x4; // Negative
    pub const PL: u8 = 0x5; // Positive or zero
    pub const VS: u8 = 0x6; // Overflow
    pub const VC: u8 = 0x7; // No overflow
    pub const HI: u8 = 0x8; // Unsigned higher
    pub const LS: u8 = 0x9; // Unsigned lower or same
    pub const GE: u8 = 0xA; // Signed greater or equal
    pub const LT: u8 = 0xB; // Signed less than
    pub const GT: u8 = 0xC; // Signed greater than
    pub const LE: u8 = 0xD; // Signed less or equal
    pub const AL: u8 = 0xE; // Always
    pub const NV: u8 = 0xF; // Never / unconditional
}

/// ARM instruction patterns.
pub mod patterns {
    pub const NOP: u32 = 0xE1A00000; // MOV R0, R0
    pub const NOP_HINT: u32 = 0xE320F000; // NOP (hint)
    pub const BX_LR: u32 = 0xE12FFF1E; // BX LR (return)
    pub const SVC_BASE: u32 = 0xEF000000; // SVC #0
    pub const BKPT_BASE: u32 = 0xE1200070; // BKPT
}

/// Extract condition code from ARM32 instruction.
pub fn get_condition(instr: u32) -> u8 {
    ((instr >> 28) & 0xF) as u8
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    let cond = get_condition(instr);
    if cond == 0xF {
        // Unconditional instructions
        return (instr & 0x0E000000) == 0x0A000000;
    }

    let op = (instr >> 24) & 0xF;
    op == 0xA || op == 0xB
}

/// Check if instruction is BL (branch with link).
pub fn is_bl(instr: u32) -> bool {
    let cond = get_condition(instr);
    if cond > 0xE {
        return false;
    }

    (instr & 0x0F000000) == 0x0B000000
}

/// Check if this is a PUSH instruction.
pub fn is_push(instr: u32) -> bool {
    (instr & 0xFFFF0000) == 0xE92D0000
}

/// Check if this is a POP instruction.
pub fn is_pop(instr: u32) -> bool {
    (instr & 0xFFFF0000) == 0xE8BD0000
}

/// Thumb-2 instruction length detection.
pub fn thumb_instruction_length(first_halfword: u16) -> usize {
    let top5 = (first_halfword >> 11) & 0x1F;
    if top5 == 0x1D || top5 == 0x1E || top5 == 0x1F {
        4 // 32-bit Thumb-2 instruction
    } else {
        2 // 16-bit Thumb instruction
    }
}

/// Score likelihood of ARM32 code (ARM mode only).
///
/// Analyzes raw bytes for patterns characteristic of ARM32:
/// - Condition codes in bits [31:28]
/// - Common instructions (NOP, BX LR, PUSH, POP)
/// - Data processing patterns
fn score_arm32(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut consecutive_zeros = 0u32;

    // ARM32 instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Track consecutive zero words
        if word == 0x00000000 {
            consecutive_zeros += 1;
            if consecutive_zeros > 2 {
                score -= 5; // Penalize long zero runs
            }
            continue;
        }
        consecutive_zeros = 0;

        // Check condition code
        let cond = get_condition(word);

        // AL (always) condition is most common
        if cond == condition::AL {
            score += 3;
        } else if cond <= condition::LE {
            // Valid condition codes
            score += 1;
        } else if cond == condition::NV {
            // Unconditional - less common but valid
            score += 1;
        }

        // NOP (MOV R0, R0)
        if word == patterns::NOP {
            score += 20;
        }

        // NOP.W (ARMv6K+)
        if word == patterns::NOP_HINT {
            score += 20;
        }

        // BX LR (return)
        if word == patterns::BX_LR {
            score += 25;
        }

        // PUSH
        if is_push(word) {
            score += 15;
        }

        // POP
        if is_pop(word) {
            score += 15;
        }

        // BL (branch with link)
        if is_bl(word) {
            score += 8;
        }

        // LDR/STR
        if (word & 0x0E000000) == 0x04000000 && cond <= condition::AL {
            score += 3;
        }

        // Data processing (AND, EOR, SUB, ADD, etc.)
        if (word & 0x0C000000) == 0x00000000 && cond <= condition::AL {
            score += 2;
        }

        // SVC/SWI (system call)
        if (word & 0x0F000000) == 0x0F000000 && cond == condition::AL {
            score += 15;
        }

        // All ones is invalid
        if word == 0xFFFFFFFF {
            score -= 10;
        }
    }

    score.max(0)
}

/// Score likelihood of Thumb/Thumb-2 code.
///
/// Analyzes raw bytes for patterns characteristic of Thumb/Thumb-2:
/// - 16-bit Thumb instructions (PUSH, POP, BX LR, MOV, ADD, etc.)
/// - 32-bit Thumb-2 instructions (BL, LDR.W, STR.W, etc.)
fn score_thumb(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut consecutive_zeros = 0u32;
    let mut last_hw: u16 = 0;
    let mut repeat_count = 0u32;
    let mut aarch64_penalty: i64 = 0;
    let mut i = 0;

    // Pre-scan for AArch64 patterns to apply penalty
    // AArch64 instructions are 32-bit aligned, look for distinctive patterns
    if data.len() >= 8 {
        let mut j = 0;
        while j + 3 < data.len().min(4096) {
            let word = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);

            // AArch64 MRS/MSR system register instructions (0xD5xxxxxx)
            if (word >> 20) == 0xD53 || (word >> 20) == 0xD51 {
                aarch64_penalty += 50;
            }
            // AArch64 STP/LDP with signed offset (0xA9/0x29 prefix for sp-based)
            else if (word >> 22) == 0x2A4 || (word >> 22) == 0x2A5 {
                aarch64_penalty += 30;
            }
            // AArch64 BL (0x94 or 0x97 prefix = bits 31:26 = 100101)
            else if (word >> 26) == 0x25 {
                aarch64_penalty += 20;
            }
            // AArch64 ADD/SUB immediate with SP (0x91/0xD1 patterns)
            else if (word >> 24) == 0x91 || (word >> 24) == 0xD1 {
                aarch64_penalty += 15;
            }
            // AArch64 RET (D65F03C0)
            else if word == 0xD65F03C0 {
                aarch64_penalty += 40;
            }
            // AArch64 NOP (D503201F)
            else if word == 0xD503201F {
                aarch64_penalty += 25;
            }
            // AArch64 ADRP (1xxxxxxx 0xxx where opcode is 10xxx)
            else if (word & 0x9F000000) == 0x90000000 {
                aarch64_penalty += 20;
            }
            // AArch64 B (unconditional branch - 000101xx pattern)
            else if (word >> 26) == 0x05 {
                aarch64_penalty += 15;
            }
            j += 4;
        }
    }

    while i + 1 < data.len() {
        let hw = u16::from_le_bytes([data[i], data[i + 1]]);

        // Track consecutive zero halfwords
        if hw == 0x0000 {
            consecutive_zeros += 1;
            if consecutive_zeros > 4 {
                score -= 3; // Penalize long zero runs
            }
            i += 2;
            last_hw = hw;
            continue;
        }
        consecutive_zeros = 0;

        // Track repeated halfwords (padding detection)
        if hw == last_hw {
            repeat_count += 1;
            if repeat_count > 8 {
                // Long runs of identical values are likely padding, not code
                score -= 2;
                i += 2;
                continue;
            }
        } else {
            repeat_count = 0;
        }
        last_hw = hw;

        // Common padding patterns - penalize
        if hw == 0x5A5A || hw == 0xDEAD || hw == 0xBEEF || hw == 0xCAFE || hw == 0xFEED {
            score -= 5;
            i += 2;
            continue;
        }

        // Check if this is a 32-bit Thumb-2 instruction
        let top5 = (hw >> 11) & 0x1F;
        let is_thumb2 = matches!(top5, 0x1D | 0x1E | 0x1F);

        if is_thumb2 && i + 3 < data.len() {
            // 32-bit Thumb-2 instruction
            let hw2 = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            let word = ((hw as u32) << 16) | (hw2 as u32);

            // BL/BLX - Branch with Link (VERY common in Thumb-2 firmware)
            // Encoding: 11110Sxxxxxxxxxx 11J1Jxxxxxxxxxxx
            if (hw & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000 {
                score += 45; // BL is THE most common instruction in firmware
            }
            // B.W - Unconditional branch (32-bit)
            else if (hw & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0x9000 {
                score += 25;
            }
            // LDR.W Rt, [PC, #imm] - Literal pool load (VERY common)
            // Encoding: 1111 1000 x101 1111 (F85F or F8DF)
            else if (hw & 0xFF7F) == 0xF85F || (hw & 0xFF7F) == 0xF8DF {
                score += 40; // PC-relative load is very distinctive
            }
            // LDR.W / STR.W (32-bit load/store with immediate)
            else if (hw & 0xFFF0) == 0xF8D0 || (hw & 0xFFF0) == 0xF8C0 {
                score += 22; // LDR.W Rt, [Rn, #imm12] / STR.W
            }
            // LDR.W / STR.W with register offset
            else if (hw & 0xFFF0) == 0xF850 || (hw & 0xFFF0) == 0xF840 {
                score += 22;
            }
            // LDRB.W / STRB.W / LDRH.W / STRH.W
            else if (hw & 0xFE50) == 0xF810 || (hw & 0xFE50) == 0xF830 {
                score += 18;
            }
            // PUSH.W / POP.W (multiple registers) - function boundaries
            else if (word & 0xFFFFE000) == 0xE92D0000 {
                score += 55; // PUSH.W {reglist} - strong function marker
            } else if (word & 0xFFFFE000) == 0xE8BD0000 {
                score += 55; // POP.W {reglist}
            }
            // STMDB / LDMIA (other multiple load/store)
            else if (hw & 0xFFD0) == 0xE880 || (hw & 0xFFD0) == 0xE900 {
                score += 25;
            }
            // MOV.W Rd, #imm (4FF0 xxxx pattern)
            else if (hw & 0xFBEF) == 0xF04F {
                score += 20; // Very common
            }
            // MOVW / MOVT (load 16-bit immediate)
            else if (hw & 0xFBF0) == 0xF240 || (hw & 0xFBF0) == 0xF2C0 {
                score += 22; // MOVW / MOVT - address construction
            }
            // ADD.W / SUB.W with immediate
            else if (hw & 0xFBE0) == 0xF100 || (hw & 0xFBE0) == 0xF1A0 {
                score += 12;
            }
            // ADD.W / SUB.W with register
            else if (hw & 0xFFE0) == 0xEB00 || (hw & 0xFFE0) == 0xEBA0 {
                score += 12;
            }
            // CMP.W with immediate
            else if (hw & 0xFBF0) == 0xF1B0 {
                score += 12;
            }
            // TST.W / TEQ.W
            else if (hw & 0xFBF0) == 0xF010 || (hw & 0xFBF0) == 0xF090 {
                score += 10;
            }
            // AND.W / ORR.W / EOR.W / BIC.W
            else if (hw & 0xFFE0) == 0xF000
                || (hw & 0xFFE0) == 0xF040
                || (hw & 0xFFE0) == 0xF080
                || (hw & 0xFFE0) == 0xF020
            {
                score += 10;
            }
            // MRS (system register read) - firmware specific
            else if (hw & 0xFFF0) == 0xF3E0 && (hw2 & 0xF000) == 0x8000 {
                score += 50; // MRS Rd, spec_reg - very distinctive
            }
            // MSR (system register write) - firmware specific
            else if (hw & 0xFFF0) == 0xF380 && (hw2 & 0xFF00) == 0x8800 {
                score += 50; // MSR spec_reg, Rn - very distinctive
            }
            // DMB / DSB / ISB (memory barriers) - firmware specific
            else if (word & 0xFFFFFFF0) == 0xF3BF8F50 {
                score += 40; // DMB
            } else if (word & 0xFFFFFFF0) == 0xF3BF8F40 {
                score += 40; // DSB - firmware barrier
            } else if word == 0xF3BF8F6F {
                score += 40; // ISB - firmware barrier
            }
            // CPSIE / CPSID (interrupt control) - 32-bit encoding
            else if (word & 0xFFFFFF00) == 0xF3AF8600 || (word & 0xFFFFFF00) == 0xF3AF8700 {
                score += 45; // CPSIE/CPSID - very firmware specific
            }
            // IT block handling (If-Then) - Thumb-2 specific
            else if (hw & 0xFF00) == 0xBF00 && (hw & 0x00FF) != 0x00 {
                score += 25; // IT instruction - Thumb-2 exclusive
            }
            // TBB / TBH (table branch) - switch statement implementation
            else if (hw & 0xFFF0) == 0xE8D0
                && ((hw2 & 0xFFF0) == 0xF000 || (hw2 & 0xFFF0) == 0xF010)
            {
                score += 35; // Table branch - very Thumb-2 specific
            }
            // LDRD / STRD (double-word load/store)
            else if (hw & 0xFE50) == 0xE850 || (hw & 0xFE50) == 0xE940 {
                score += 20;
            }
            // CLREX / LDREX / STREX (exclusive access)
            else if (hw & 0xFFF0) == 0xE850 && (hw2 & 0x0F00) == 0x0F00 {
                score += 25;
            }
            // BFI / BFC / UBFX / SBFX (bitfield operations)
            else if (hw & 0xFFE0) == 0xF360 || (hw & 0xFFE0) == 0xF3C0 || (hw & 0xFFE0) == 0xF340
            {
                score += 18;
            }
            // SDIV / UDIV (division - Cortex-M3+)
            else if (hw & 0xFFF0) == 0xFB90 || (hw & 0xFFF0) == 0xFBB0 {
                score += 30; // Division is distinctive
            }
            // MLA / MLS / SMULL / UMULL (multiply)
            else if (hw & 0xFFF0) == 0xFB00 || (hw & 0xFFF0) == 0xFB80 || (hw & 0xFFF0) == 0xFBA0
            {
                score += 15;
            }
            // Generic valid 32-bit Thumb-2 instruction prefix
            else {
                score += 8;
            }

            i += 4;
        } else {
            // 16-bit Thumb instruction

            // BX LR - Return from function (very common)
            if hw == 0x4770 {
                score += 40; // Extremely common in firmware
            }
            // BX Rn (other register)
            else if (hw & 0xFF87) == 0x4700 {
                score += 20;
            }
            // PUSH {reglist} with LR
            else if (hw & 0xFE00) == 0xB400 {
                let has_lr = (hw & 0x0100) != 0;
                score += if has_lr { 35 } else { 18 }; // PUSH with LR is function prologue
            }
            // POP {reglist} with PC
            else if (hw & 0xFE00) == 0xBC00 {
                let has_pc = (hw & 0x0100) != 0;
                score += if has_pc { 35 } else { 18 }; // POP with PC is function return
            }
            // NOP.N
            else if hw == 0xBF00 {
                score += 10;
            }
            // WFI (Wait For Interrupt) - very firmware specific
            else if hw == 0xBF30 {
                score += 40; // Sleep instruction - very distinctive
            }
            // WFE (Wait For Event) - very firmware specific
            else if hw == 0xBF20 {
                score += 40; // Sleep instruction - very distinctive
            }
            // SEV (Send Event) - firmware specific
            else if hw == 0xBF40 {
                score += 35;
            }
            // CPSID i (disable interrupts) - 16-bit encoding
            else if hw == 0xB672 {
                score += 50; // Very firmware specific
            }
            // CPSIE i (enable interrupts) - 16-bit encoding
            else if hw == 0xB662 {
                score += 50; // Very firmware specific
            }
            // CPSID f (disable faults)
            else if hw == 0xB673 {
                score += 50;
            }
            // CPSIE f (enable faults)
            else if hw == 0xB663 {
                score += 50;
            }
            // MOV Rd, Rn (low registers)
            else if (hw & 0xFFC0) == 0x0000 && hw != 0x0000 {
                // Actually LSL Rd, Rm, #0 = MOV
                score += 6;
            }
            // MOV Rd, Rn (high registers)
            else if (hw & 0xFF00) == 0x4600 {
                score += 10;
            }
            // ADD/SUB with immediate (common)
            else if (hw & 0xF800) == 0x3000 || (hw & 0xF800) == 0x3800 {
                score += 8; // ADD Rn, #imm8 / SUB Rn, #imm8
            }
            // ADD/SUB (register)
            else if (hw & 0xFE00) == 0x1800 || (hw & 0xFE00) == 0x1A00 {
                score += 7;
            }
            // CMP with immediate
            else if (hw & 0xF800) == 0x2800 {
                score += 8;
            }
            // CMP (register, low)
            else if (hw & 0xFFC0) == 0x4280 {
                score += 7;
            }
            // CMP (register, high)
            else if (hw & 0xFF00) == 0x4500 {
                score += 7;
            }
            // LDR Rt, [PC, #imm] (literal pool)
            else if (hw & 0xF800) == 0x4800 {
                score += 15; // Very common pattern
            }
            // LDR/STR with register offset
            else if (hw & 0xF000) == 0x5000 {
                score += 8;
            }
            // LDR/STR with immediate offset
            else if (hw & 0xE000) == 0x6000 {
                score += 8;
            }
            // LDRB/STRB with immediate offset
            else if (hw & 0xF000) == 0x7000 {
                score += 7;
            }
            // LDRH/STRH with immediate offset
            else if (hw & 0xF000) == 0x8000 {
                score += 7;
            }
            // LDR/STR (SP-relative)
            else if (hw & 0xF000) == 0x9000 {
                score += 10;
            }
            // ADD Rd, PC, #imm (ADR - address calculation)
            else if (hw & 0xF800) == 0xA000 {
                score += 12;
            }
            // ADD Rd, SP, #imm (stack offset calculation)
            else if (hw & 0xF800) == 0xA800 {
                score += 12;
            }
            // ADD/SUB SP, #imm (stack frame adjustment)
            else if (hw & 0xFF00) == 0xB000 {
                score += 15; // Very common in function prologues/epilogues
            }
            // Conditional branch B<cond>
            else if (hw & 0xF000) == 0xD000 && (hw & 0x0F00) != 0x0E00 && (hw & 0x0F00) != 0x0F00
            {
                score += 10;
            }
            // Unconditional branch B
            else if (hw & 0xF800) == 0xE000 {
                score += 8;
            }
            // CBZ / CBNZ (Thumb-2)
            else if (hw & 0xF500) == 0xB100 || (hw & 0xF500) == 0xB900 {
                score += 18; // Compare and Branch - Thumb-2 specific
            }
            // SVC (Supervisor Call)
            else if (hw & 0xFF00) == 0xDF00 {
                score += 20;
            }
            // BKPT (Breakpoint)
            else if (hw & 0xFF00) == 0xBE00 {
                score += 15;
            }
            // ADR (load address)
            else if (hw & 0xF800) == 0xA000 {
                score += 10;
            }
            // Logical ops (AND, EOR, LSL, LSR, ASR, ADC, SBC, ROR, TST, RSB, etc.)
            else if (hw & 0xFC00) == 0x4000 {
                score += 6;
            }
            // SXTH, SXTB, UXTH, UXTB - sign/zero extend
            else if (hw & 0xFF00) == 0xB200 {
                score += 10;
            }
            // REV, REV16, REVSH - byte reverse
            else if (hw & 0xFFC0) == 0xBA00 || (hw & 0xFFC0) == 0xBA40 || (hw & 0xFFC0) == 0xBAC0
            {
                score += 12;
            }
            // UDF (Undefined) - often used as assertions
            else if (hw & 0xFF00) == 0xDE00 {
                score += 5;
            }
            // All ones is padding/invalid
            else if hw == 0xFFFF {
                score -= 3;
            }

            i += 2;
        }
    }

    // Apply AArch64 penalty - if we detected significant AArch64 code, reduce Thumb score
    score -= aarch64_penalty;

    score.max(0)
}

/// Score multi-instruction Thumb-2 patterns.
/// Detects consecutive BL calls, function prologues/epilogues, etc.
fn score_thumb_patterns(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut consecutive_bl = 0u32;
    let mut i = 0;

    while i + 3 < data.len() {
        let hw0 = u16::from_le_bytes([data[i], data[i + 1]]);

        // Check for 32-bit Thumb-2 instruction
        let top5 = (hw0 >> 11) & 0x1F;
        if matches!(top5, 0x1D | 0x1E | 0x1F) && i + 3 < data.len() {
            let hw1 = u16::from_le_bytes([data[i + 2], data[i + 3]]);

            // BL instruction pattern: F0xx Dxxx or F0xx Fxxx
            let is_bl =
                (hw0 & 0xF800) == 0xF000 && ((hw1 & 0xD000) == 0xD000 || (hw1 & 0xD000) == 0x9000);

            if is_bl {
                consecutive_bl += 1;
                // Consecutive BL calls are very common in firmware init
                if consecutive_bl >= 2 {
                    score += 15; // Bonus for consecutive BLs
                }
                if consecutive_bl >= 4 {
                    score += 25; // Strong pattern
                }
            } else {
                // Reset but don't penalize for small gaps
                if consecutive_bl > 0 {
                    consecutive_bl = 0;
                }
            }

            // PUSH.W {reglist} followed by SUB SP - function prologue
            if (hw0 == 0xE92D) && i + 7 < data.len() {
                let next_hw0 = u16::from_le_bytes([data[i + 4], data[i + 5]]);
                // SUB SP, SP, #imm or MOV
                if (next_hw0 & 0xFBEF) == 0xF1AD || (next_hw0 & 0xFF00) == 0xB000 {
                    score += 40; // Strong function prologue pattern
                }
            }

            // POP.W {reglist, PC} - function epilogue
            if hw0 == 0xE8BD && (hw1 & 0x8000) != 0 {
                score += 30; // Function return pattern
            }

            i += 4;
        } else {
            // 16-bit instruction
            consecutive_bl = 0;

            // BX LR followed by PUSH = new function start
            if hw0 == 0x4770 && i + 3 < data.len() {
                let next = u16::from_le_bytes([data[i + 2], data[i + 3]]);
                if (next & 0xFE00) == 0xB400 || next == 0xE92D {
                    score += 35; // Function boundary pattern
                }
            }

            i += 2;
        }
    }

    score
}

/// Detect Cortex-M vector table pattern.
/// Vector tables have addresses with odd LSB (Thumb mode indicator) pointing within firmware.
fn score_cortex_m_vector_table(data: &[u8]) -> i64 {
    // Try vector table at offset 0 and a few common header sizes
    let offsets = [0usize, 0x100, 0x200, 0x400];
    let mut best_score: i64 = 0;

    for &offset in &offsets {
        let score = score_vector_table_at_offset(data, offset);
        if score > best_score {
            best_score = score;
        }
    }

    best_score
}

/// Score vector table at a specific offset.
fn score_vector_table_at_offset(data: &[u8], offset: usize) -> i64 {
    if data.len() < offset + 64 {
        return 0;
    }

    let mut score: i64 = 0;
    let mut valid_vectors = 0u32;
    let mut vector_addrs: Vec<u32> = Vec::new();
    let mut sp_valid = false;

    // Check up to 48 vectors (192 bytes) - covers main Cortex-M exceptions
    // Need at least 4 bytes for each read
    let available = data.len().saturating_sub(offset);
    let check_size = 192.min(available.saturating_sub(3));

    for i in (0..check_size).step_by(4) {
        let idx = offset + i;
        if idx + 3 >= data.len() {
            break;
        }
        let addr = u32::from_le_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);

        // First entry is Initial SP - should be even, in RAM range
        if i == 0 {
            // SP typically in 0x20000000-0x20FFFFFF (SRAM) or 0x10000000 range
            if (addr & 0xF0000000) == 0x20000000 {
                score += 50;
                sp_valid = true;
            } else if (addr & 0xFFF00000) == 0x10000000 {
                score += 40;
                sp_valid = true;
            }
            // SP should be word-aligned and reasonable size (4KB - 1MB)
            if sp_valid && (addr & 3) == 0 {
                let sp_size = addr & 0x00FFFFFF;
                if sp_size >= 0x1000 && sp_size <= 0x100000 {
                    score += 20;
                }
            }
            continue;
        }

        // Reserved/unused vectors are often 0
        if addr == 0 {
            continue;
        }

        // Must be odd (Thumb mode indicator)
        if (addr & 1) == 1 {
            let code_addr = addr & !1;
            // Must be in reasonable code range
            if code_addr < 0x20000000 && code_addr >= 0x100 {
                valid_vectors += 1;
                vector_addrs.push(code_addr);
            }
        }
    }

    // Check if vectors cluster in similar address range (typical for real firmware)
    if vector_addrs.len() >= 4 {
        let min_addr = *vector_addrs.iter().min().unwrap_or(&0);
        let max_addr = *vector_addrs.iter().max().unwrap_or(&0);
        let range = max_addr.saturating_sub(min_addr);

        // Vectors typically span less than 1MB in real firmware
        if range < 0x100000 && range > 0 {
            score += 30; // Clustered vectors = strong indicator
        }

        // Check if most vectors share the same upper bits (same memory region)
        let region_mask = 0xFFFF0000u32;
        let first_region = vector_addrs[0] & region_mask;
        let same_region_count = vector_addrs
            .iter()
            .filter(|&&a| (a & region_mask) == first_region)
            .count();
        if same_region_count >= vector_addrs.len() * 3 / 4 {
            score += 40; // Most vectors in same 64KB region
        }
    }

    // Score based on valid vector count
    if valid_vectors >= 12 && sp_valid {
        score += 150; // Very strong indicator
    } else if valid_vectors >= 8 && sp_valid {
        score += 100;
    } else if valid_vectors >= 8 {
        score += 80;
    } else if valid_vectors >= 4 {
        score += 40;
    }

    score
}

/// Score likelihood of ARM32 code (ARM mode or Thumb mode).
///
/// This scores both ARM32 and Thumb modes and returns the higher score.
pub fn score(data: &[u8]) -> i64 {
    let arm32_score = score_arm32(data);
    let thumb_score = score_thumb(data);
    let thumb_pattern_score = score_thumb_patterns(data);
    let vector_table_score = score_cortex_m_vector_table(data);

    // Take the best score, adding pattern bonus to Thumb score
    let effective_thumb_score = thumb_score + thumb_pattern_score;
    let base_score = arm32_score.max(effective_thumb_score);

    // Vector table is a strong indicator - scale the bonus based on confidence
    // A high vector table score (200+) indicates very likely Cortex-M firmware
    let vector_bonus = if vector_table_score >= 200 {
        // Strong vector table - add significant bonus (up to 50% of base score)
        vector_table_score.min(base_score / 2)
    } else if vector_table_score >= 100 {
        // Good vector table - moderate bonus (up to 30% of base score)
        vector_table_score.min(base_score * 3 / 10)
    } else {
        // Weak or no vector table - small bonus
        vector_table_score.min(base_score / 5)
    };

    // Also add a multiplier if we have both strong thumb code AND vector table
    let multiplier = if vector_table_score >= 150 && effective_thumb_score > arm32_score {
        // Cortex-M firmware typically uses Thumb-2, boost confidence
        110 // 10% boost
    } else {
        100
    };

    let final_score = (base_score + vector_bonus) * multiplier / 100;
    final_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_extraction() {
        assert_eq!(get_condition(0xE1A00000), condition::AL);
        assert_eq!(get_condition(0x01A00000), condition::EQ);
    }

    #[test]
    fn test_branch_detection() {
        assert!(is_bl(0xEB000000));
        assert!(!is_bl(0xEA000000));
    }

    #[test]
    fn test_thumb_length() {
        assert_eq!(thumb_instruction_length(0xBF00), 2); // NOP.N
        assert_eq!(thumb_instruction_length(0xF3AF), 4); // NOP.W prefix
    }

    #[test]
    fn test_score() {
        // ARM NOP
        let nop = 0xE1A00000u32.to_le_bytes();
        assert!(score(&nop) > 0);
        // BX LR (return)
        let ret = 0xE12FFF1Eu32.to_le_bytes();
        assert!(score(&ret) > 0);
    }
}
