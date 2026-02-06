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
/// - Exact instruction matches (NOP, BX LR, PUSH, POP)
/// - Well-formed opcode patterns with valid condition codes
/// - Multi-instruction patterns (prologue/epilogue sequences)
fn score_arm32(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut consecutive_zeros = 0u32;
    let mut al_count = 0u32;
    let mut total_count = 0u32;
    let mut push_seen = false;
    let mut bl_count = 0u32;
    let mut ret_seen = false;

    // ARM32 instructions are 4 bytes, aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        total_count += 1;

        // Track consecutive zero words
        if word == 0x00000000 {
            consecutive_zeros += 1;
            if consecutive_zeros > 2 {
                score -= 5;
            }
            continue;
        }
        consecutive_zeros = 0;

        // All ones is invalid
        if word == 0xFFFFFFFF {
            score -= 10;
            continue;
        }

        let cond = get_condition(word);

        // Track AL condition prevalence (statistical heuristic applied at end)
        if cond == condition::AL {
            al_count += 1;
        }

        // === AArch64 cross-architecture penalties ===
        // AArch64 shares 32-bit LE encoding but different instruction formats.
        // Only penalize highly-specific AArch64 patterns to avoid hurting
        // ARM32 firmware scoring (broad masks match too many data words).
        if word == 0xD503201F { score -= 15; continue; } // AArch64 NOP
        if word == 0xD65F03C0 { score -= 20; continue; } // AArch64 RET
        // AArch64 STP x29,x30,[sp,#off] (function prologue)
        if (word & 0xFFC07FFF) == 0xA9007BFD { score -= 15; continue; }
        // AArch64 LDP x29,x30,[sp],#N (function epilogue)
        if (word & 0xFFC07FFF) == 0xA8407BFD { score -= 15; continue; }

        // === Exact match patterns (very high confidence) ===

        // NOP (MOV R0, R0)
        if word == patterns::NOP {
            score += 20;
            continue;
        }

        // NOP.W (ARMv6K+ hint NOP)
        if word == patterns::NOP_HINT {
            score += 20;
            continue;
        }

        // BX LR (return from function)
        if word == patterns::BX_LR {
            score += 25;
            ret_seen = true;
            continue;
        }

        // SVC/SWI (system call) - EF000000 base
        if (word & 0x0F000000) == 0x0F000000 && cond == condition::AL {
            score += 15;
            continue;
        }

        // === Structural patterns (require valid cond + specific opcode bits) ===

        // Only score instructions with valid condition codes (0x0-0xE)
        if cond > condition::AL {
            // 0xF = unconditional extension space - only a few are valid
            // Check for specific unconditional instructions
            if (word & 0xFE000000) == 0xFA000000 {
                // BLX (immediate) - unconditional branch with link and exchange
                score += 10;
            }
            continue;
        }

        // PUSH {reglist} - function prologue marker
        if is_push(word) {
            score += 15;
            push_seen = true;
            continue;
        }

        // POP {reglist} - function epilogue marker
        if is_pop(word) {
            score += 15;
            continue;
        }

        // BL (branch with link) - function calls
        if is_bl(word) {
            score += 8;
            bl_count += 1;
            continue;
        }

        // B (branch without link)
        if (word & 0x0F000000) == 0x0A000000 {
            score += 5;
            continue;
        }

        // BX Rn (branch and exchange)
        if (word & 0x0FFFFFF0) == 0x012FFF10 {
            score += 12;
            continue;
        }

        // MRS/MSR (status register access) - very ARM-specific
        if (word & 0x0FBF0FFF) == 0x010F0000 {
            // MRS Rd, CPSR/SPSR
            score += 20;
            continue;
        }
        if (word & 0x0FBFFFF0) == 0x0129F000 {
            // MSR CPSR/SPSR, Rm
            score += 20;
            continue;
        }

        // LDR/STR (single data transfer) - bits [27:26] = 01
        if (word & 0x0C000000) == 0x04000000 {
            // Validate: check Rn and Rd are reasonable (not all same)
            let rn = (word >> 16) & 0xF;
            let rd = (word >> 12) & 0xF;
            if rn != rd || rn == 13 || rn == 15 {
                // SP-relative or PC-relative loads are very common
                score += 4;
            } else {
                score += 2;
            }
            continue;
        }

        // LDM/STM (block data transfer) - bits [27:25] = 100
        if (word & 0x0E000000) == 0x08000000 {
            let reglist = word & 0xFFFF;
            let reg_count = reglist.count_ones();
            if reg_count >= 2 && reg_count <= 16 {
                score += 6;
            }
            continue;
        }

        // Data processing - bits [27:26] = 00, but require more specificity
        if (word & 0x0C000000) == 0x00000000 {
            let op1 = (word >> 21) & 0xF;
            let s_bit = (word >> 20) & 1;
            let rd = (word >> 12) & 0xF;
            let rn = (word >> 16) & 0xF;

            // MOV/MVN with specific register patterns
            if op1 == 0xD || op1 == 0xF {
                score += 3;
                continue;
            }
            // CMP/CMN/TST/TEQ (S bit must be 1, Rd must be 0)
            if matches!(op1, 0x8 | 0x9 | 0xA | 0xB) && s_bit == 1 {
                score += 4;
                continue;
            }
            // ADD/SUB with SP (r13) - stack operations
            if matches!(op1, 0x2 | 0x4) && (rn == 13 || rd == 13) {
                score += 5;
                continue;
            }
            // Other ALU ops: modest score
            if op1 <= 0xF {
                score += 2;
            }
            continue;
        }

        // Coprocessor instructions (MRC, MCR, etc.) - bits [27:24] = 1110
        if (word & 0x0F000000) == 0x0E000000 {
            score += 3;
            continue;
        }
    }

    // ARM32 has a very distinctive condition code distribution: real code
    // is dominated by condition 0xE (AL = always). Other ISAs read as LE
    // 32-bit words have ~uniform condition distribution (~6.25% per code).
    // Require 2+ distinct ARM evidence types to waive condition penalty.
    // Single evidence (e.g., coincidental BL from LoongArch/AArch64 SUBS)
    // is insufficient since ~49% of random 125-word blocks produce one match.
    let evidence_count = (push_seen as u32) + bl_count.min(1) + (ret_seen as u32);
    if total_count > 20 {
        let al_ratio = al_count as f64 / total_count as f64;
        if al_ratio > 0.6 {
            // High AL ratio - strong ARM indicator, bonus
            score += (score / 10).min(50);
        } else if al_ratio < 0.25 && evidence_count < 2 {
            // Very low AL ratio and weak ARM evidence - not ARM32
            // Real ARM firmware with mixed code/data still has PUSH+BL+BX_LR
            score = (score as f64 * 0.15) as i64;
        } else if al_ratio < 0.40 && evidence_count < 2 {
            // Low AL ratio and weak ARM evidence - unlikely ARM32
            score = (score as f64 * 0.30) as i64;
        }
    }

    // Bonus for multiple BL calls (common in real code)
    if bl_count >= 3 {
        score += 15;
    }

    // Bonus for prologue pattern
    if push_seen && bl_count >= 1 {
        score += 10;
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
    let mut hexagon_penalty: i64 = 0;
    let mut ret_count = 0u32;
    let mut bl_count = 0u32;
    let mut push_lr_count = 0u32;
    let mut i = 0;

    // Pre-scan for Hexagon patterns to apply penalty
    // Hexagon uses 32-bit LE instructions with VLIW packet structure.
    // Key patterns: NOP (0x7F00xxxx), ALLOCFRAME, DEALLOC_RETURN
    if data.len() >= 8 {
        let mut j = 0;
        while j + 3 < data.len() {
            let word = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            // Hexagon NOP
            if (word & 0xFFFF0000) == 0x7F000000 { hexagon_penalty += 25; }
            // Hexagon DEALLOC_RETURN
            else if word == 0x961EC01E { hexagon_penalty += 30; }
            // Hexagon ALLOCFRAME
            else if (word & 0xFFFFE000) == 0xA09DC000 { hexagon_penalty += 25; }
            // Hexagon JUMPR R31 (return)
            else if (word & 0xFFE03FFF) == 0x52800000 { hexagon_penalty += 20; }
            j += 4;
        }
    }

    // Pre-scan for AArch64 patterns to apply penalty
    // AArch64 instructions are 32-bit aligned, look for distinctive patterns
    if data.len() >= 8 {
        let mut j = 0;
        while j + 3 < data.len() {
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
        // Exempt known valid repeated patterns like Thumb NOP (0xBF00)
        if hw == last_hw {
            repeat_count += 1;
            if repeat_count > 8 && hw != 0xBF00 {
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
            if (hw & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000 {
                score += 45;
                bl_count += 1;
            }
            // B.W - Unconditional branch (32-bit)
            else if (hw & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0x9000 {
                score += 25;
            }
            // LDR.W Rt, [PC, #imm] - Literal pool load
            else if (hw & 0xFF7F) == 0xF85F || (hw & 0xFF7F) == 0xF8DF {
                score += 40;
            }
            // PUSH.W / POP.W (multiple registers) - function boundaries
            else if (word & 0xFFFFE000) == 0xE92D0000 {
                score += 55;
            } else if (word & 0xFFFFE000) == 0xE8BD0000 {
                score += 55;
                ret_count += 1;
            }
            // MRS/MSR (system register) - firmware specific
            else if (hw & 0xFFF0) == 0xF3E0 && (hw2 & 0xF000) == 0x8000 {
                score += 50;
            } else if (hw & 0xFFF0) == 0xF380 && (hw2 & 0xFF00) == 0x8800 {
                score += 50;
            }
            // DMB / DSB / ISB (memory barriers) - firmware specific
            else if (word & 0xFFFFFFF0) == 0xF3BF8F50
                || (word & 0xFFFFFFF0) == 0xF3BF8F40
                || word == 0xF3BF8F6F
            {
                score += 40;
            }
            // CPSIE / CPSID (interrupt control) - very firmware specific
            else if (word & 0xFFFFFF00) == 0xF3AF8600 || (word & 0xFFFFFF00) == 0xF3AF8700 {
                score += 45;
            }
            // MOVW / MOVT (load 16-bit immediate) - address construction
            else if (hw & 0xFBF0) == 0xF240 || (hw & 0xFBF0) == 0xF2C0 {
                score += 15;
            }
            // LDR.W / STR.W (32-bit load/store)
            else if (hw & 0xFFF0) == 0xF8D0 || (hw & 0xFFF0) == 0xF8C0
                || (hw & 0xFFF0) == 0xF850 || (hw & 0xFFF0) == 0xF840
            {
                score += 12;
            }
            // SDIV / UDIV (division - distinctive)
            else if (hw & 0xFFF0) == 0xFB90 || (hw & 0xFFF0) == 0xFBB0 {
                score += 25;
            }
            // TBB / TBH (table branch)
            else if (hw & 0xFFF0) == 0xE8D0
                && ((hw2 & 0xFFF0) == 0xF000 || (hw2 & 0xFFF0) == 0xF010)
            {
                score += 30;
            }
            // IT block (If-Then) - Thumb-2 exclusive
            else if (hw & 0xFF00) == 0xBF00 && (hw & 0x00FF) != 0x00 {
                score += 20;
            }
            // MOV.W Rd, #imm
            else if (hw & 0xFBEF) == 0xF04F {
                score += 10;
            }
            // ADD.W/SUB.W with immediate
            else if (hw & 0xFBE0) == 0xF100 || (hw & 0xFBE0) == 0xF1A0 {
                score += 8;
            }
            // Unrecognized 32-bit Thumb-2 - no points

            i += 4;
        } else {
            // 16-bit Thumb instruction
            let mut matched = true;

            // --- MSP430 cross-architecture penalties ---
            if hw == 0x4130 { score -= 15; i += 2; continue; } // MSP430 RET
            if hw == 0x4303 { score -= 10; i += 2; continue; } // MSP430 NOP
            if hw == 0x1300 { score -= 10; i += 2; continue; } // MSP430 RETI
            if (hw & 0xFF80) == 0x1280 { score -= 8; i += 2; continue; } // MSP430 CALL
            // --- AVR cross-architecture penalties ---
            if hw == 0x9508 { score -= 12; i += 2; continue; } // AVR RET
            if hw == 0x9518 { score -= 10; i += 2; continue; } // AVR RETI
            if hw == 0x9588 { score -= 8; i += 2; continue; }  // AVR SLEEP

            // === High-confidence exact patterns ===
            if hw == 0x4770 {
                score += 40; // BX LR - return
                ret_count += 1;
            } else if hw == 0xBF00 {
                score += 10; // NOP.N
            } else if hw == 0xBF30 || hw == 0xBF20 {
                score += 40; // WFI/WFE
            } else if hw == 0xBF40 {
                score += 35; // SEV
            } else if hw == 0xB672 || hw == 0xB662 || hw == 0xB673 || hw == 0xB663 {
                score += 50; // CPSID/CPSIE - very firmware specific
            }
            // === Structural patterns (tighter masks) ===
            // BX Rn (other register)
            else if (hw & 0xFF87) == 0x4700 {
                score += 15;
            }
            // PUSH {reglist} with LR
            else if (hw & 0xFE00) == 0xB400 {
                let has_lr = (hw & 0x0100) != 0;
                score += if has_lr { 30 } else { 10 };
                if has_lr { push_lr_count += 1; }
            }
            // POP {reglist} with PC
            else if (hw & 0xFE00) == 0xBC00 {
                let has_pc = (hw & 0x0100) != 0;
                score += if has_pc { 30 } else { 10 };
                if has_pc { ret_count += 1; }
            }
            // CBZ / CBNZ (Thumb-2 exclusive)
            else if (hw & 0xF500) == 0xB100 || (hw & 0xF500) == 0xB900 {
                score += 15;
            }
            // ADD/SUB SP, #imm (stack frame adjustment) - tight mask
            else if (hw & 0xFF00) == 0xB000 {
                score += 8;
            }
            // SVC (Supervisor Call)
            else if (hw & 0xFF00) == 0xDF00 {
                score += 15;
            }
            // BKPT (Breakpoint)
            else if (hw & 0xFF00) == 0xBE00 {
                score += 10;
            }
            // MOV Rd, Rn (high registers) - tight mask
            else if (hw & 0xFF00) == 0x4600 {
                score += 5;
            }
            // LDR Rt, [PC, #imm] (literal pool) - distinctive
            else if (hw & 0xF800) == 0x4800 {
                score += 8;
            }
            // Conditional branch B<cond> - distinctive
            else if (hw & 0xF000) == 0xD000 && (hw & 0x0F00) != 0x0E00 && (hw & 0x0F00) != 0x0F00
            {
                score += 5;
            }
            // SXTH, SXTB, UXTH, UXTB - sign/zero extend
            else if (hw & 0xFF00) == 0xB200 {
                score += 8;
            }
            // REV, REV16, REVSH - byte reverse
            else if (hw & 0xFFC0) == 0xBA00 || (hw & 0xFFC0) == 0xBA40 || (hw & 0xFFC0) == 0xBAC0
            {
                score += 10;
            }
            // All ones is padding/invalid
            else if hw == 0xFFFF {
                score -= 3;
            }
            // Moderate-confidence 16-bit patterns
            // ADD Rd, Rm (high register) - very common in real code, narrow mask
            else if (hw & 0xFF00) == 0x4400 {
                score += 3;
            }
            // Data processing (AND/EOR/LSL/LSR/ASR/ADC/SBC/NEG/CMP/CMN/ORR/TST/BIC/MVN/MUL)
            else if (hw & 0xFC00) == 0x4000 {
                score += 2;
            }
            // Broad 16-bit patterns: only give minimal points
            // These match large fractions of random data
            else if (hw & 0xF800) == 0x2000 {
                score += 2; // MOV Rn, #imm8
            } else if (hw & 0xF800) == 0x3000 || (hw & 0xF800) == 0x3800 {
                score += 2; // ADD/SUB Rn, #imm8
            } else if (hw & 0xF800) == 0x2800 {
                score += 2; // CMP Rn, #imm8
            } else if (hw & 0xE000) == 0x6000 {
                score += 2; // LDR/STR with immediate offset
            } else if (hw & 0xF000) == 0x9000 {
                score += 2; // LDR/STR (SP-relative)
            } else if (hw & 0xF800) == 0xE000 {
                score += 2; // B (unconditional)
            } else {
                matched = false;
            }

            // Penalty for completely unrecognized halfwords
            if !matched {
                score -= 1;
            }

            i += 2;
        }
    }

    // Structural bonus: Thumb code with function boundaries
    if ret_count > 0 && (bl_count > 0 || push_lr_count > 0) {
        score += 25;
    }

    // Apply AArch64 penalty - if we detected significant AArch64 code, reduce Thumb score
    score -= aarch64_penalty;

    // Apply Hexagon penalty
    score -= hexagon_penalty;

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

            if i + 3 < data.len() {
                let hw1 = u16::from_le_bytes([data[i + 2], data[i + 3]]);

                // BX LR followed by PUSH = new function start
                if hw0 == 0x4770 {
                    if (hw1 & 0xFE00) == 0xB400 || hw1 == 0xE92D {
                        score += 35; // Function boundary pattern
                    }
                }

                // PUSH {regs, LR} followed by SUB SP, #imm = function prologue
                if (hw0 & 0xFF00) == 0xB500 && (hw1 & 0xFF80) == 0xB080 {
                    score += 25; // 16-bit function prologue
                }

                // POP {regs, PC} followed by PUSH {regs, LR} = function boundary
                if (hw0 & 0xFF00) == 0xBD00 && (hw1 & 0xFF00) == 0xB500 {
                    score += 30; // Function boundary
                }

                // MOV R12, SP followed by PUSH (ARM calling convention)
                if hw0 == 0x466C && (hw1 & 0xFE00) == 0xB400 {
                    score += 20;
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
