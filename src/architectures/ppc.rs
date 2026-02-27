//! PowerPC architecture analysis.

/// PowerPC primary opcodes.
pub mod opcode {
    pub const TWI: u8 = 3;
    pub const MULLI: u8 = 7;
    pub const SUBFIC: u8 = 8;
    pub const CMPLI: u8 = 10;
    pub const CMPI: u8 = 11;
    pub const ADDIC: u8 = 12;
    pub const ADDIC_DOT: u8 = 13;
    pub const ADDI: u8 = 14;
    pub const ADDIS: u8 = 15;
    pub const BC: u8 = 16;
    pub const SC: u8 = 17;
    pub const B: u8 = 18;
    pub const XL_FORM: u8 = 19; // CR ops, bclr, bcctr, etc.
    pub const RLWIMI: u8 = 20;
    pub const RLWINM: u8 = 21;
    pub const RLWNM: u8 = 23;
    pub const ORI: u8 = 24;
    pub const ORIS: u8 = 25;
    pub const XORI: u8 = 26;
    pub const XORIS: u8 = 27;
    pub const ANDI_DOT: u8 = 28;
    pub const ANDIS_DOT: u8 = 29;
    pub const X_FORM: u8 = 31; // Extended ops
    pub const LWZ: u8 = 32;
    pub const LWZU: u8 = 33;
    pub const LBZ: u8 = 34;
    pub const LBZU: u8 = 35;
    pub const STW: u8 = 36;
    pub const STWU: u8 = 37;
    pub const STB: u8 = 38;
    pub const STBU: u8 = 39;
    pub const LHZ: u8 = 40;
    pub const LHZU: u8 = 41;
    pub const LHA: u8 = 42;
    pub const LHAU: u8 = 43;
    pub const STH: u8 = 44;
    pub const STHU: u8 = 45;
    pub const LMW: u8 = 46;
    pub const STMW: u8 = 47;
    pub const LFS: u8 = 48;
    pub const LFSU: u8 = 49;
    pub const LFD: u8 = 50;
    pub const LFDU: u8 = 51;
    pub const STFS: u8 = 52;
    pub const STFSU: u8 = 53;
    pub const STFD: u8 = 54;
    pub const STFDU: u8 = 55;
    pub const LD_STD: u8 = 58; // LD, LDU, LWA
    pub const FP_SINGLE: u8 = 59;
    pub const STD: u8 = 62;
    pub const FP_DOUBLE: u8 = 63;
}

/// XL-form extended opcodes.
pub mod xl_xo {
    pub const BCLR: u16 = 16; // Branch conditional to LR
    pub const BCCTR: u16 = 528; // Branch conditional to CTR
    pub const CRAND: u16 = 257;
    pub const CRNAND: u16 = 225;
    pub const CROR: u16 = 449;
    pub const CRXOR: u16 = 193;
    pub const CRNOR: u16 = 33;
    pub const CREQV: u16 = 289;
    pub const CRANDC: u16 = 129;
    pub const CRORC: u16 = 417;
    pub const ISYNC: u16 = 150;
    pub const RFI: u16 = 50;
}

/// X-form extended opcodes (subset).
pub mod x_xo {
    pub const MFCR: u16 = 19;
    pub const MFMSR: u16 = 83;
    pub const MFSPR: u16 = 339;
    pub const MTSPR: u16 = 467;
    pub const SYNC: u16 = 598;
    pub const LWBRX: u16 = 534;
    pub const STWBRX: u16 = 662;
}

/// Common PowerPC patterns.
pub mod patterns {
    pub const NOP: u32 = 0x60000000; // ori 0,0,0
    pub const BLR: u32 = 0x4E800020; // blr
    pub const BCTR: u32 = 0x4E800420; // bctr
    pub const SC: u32 = 0x44000002; // sc
    pub const TRAP: u32 = 0x7FE00008; // trap
    pub const MFLR_R0: u32 = 0x7C0802A6; // mflr r0
    pub const MTLR_R0: u32 = 0x7C0803A6; // mtlr r0
}

/// Extract primary opcode.
pub fn get_opcode(instr: u32) -> u8 {
    ((instr >> 26) & 0x3F) as u8
}

/// Extract XO field (extended opcode).
pub fn get_xo(instr: u32) -> u16 {
    ((instr >> 1) & 0x3FF) as u16
}

/// Extract BO field (branch options).
pub fn get_bo(instr: u32) -> u8 {
    ((instr >> 21) & 0x1F) as u8
}

/// Extract BI field (branch condition index).
pub fn get_bi(instr: u32) -> u8 {
    ((instr >> 16) & 0x1F) as u8
}

/// Extract AA bit (absolute address).
pub fn get_aa(instr: u32) -> bool {
    (instr & 0x02) != 0
}

/// Extract LK bit (link register update).
pub fn get_lk(instr: u32) -> bool {
    (instr & 0x01) != 0
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    let op = get_opcode(instr);
    matches!(op, opcode::B | opcode::BC | opcode::XL_FORM)
}

/// Check if instruction is BL (branch with link).
pub fn is_bl(instr: u32) -> bool {
    let op = get_opcode(instr);
    if op == opcode::B {
        return get_lk(instr);
    }
    false
}

/// Check if instruction is BLR (return).
pub fn is_blr(instr: u32) -> bool {
    let op = get_opcode(instr);
    if op != opcode::XL_FORM {
        return false;
    }
    let xo = get_xo(instr);
    xo == xl_xo::BCLR && get_bo(instr) == 20 && get_bi(instr) == 0 && !get_lk(instr)
}

/// Check if instruction is SC (system call).
pub fn is_sc(instr: u32) -> bool {
    get_opcode(instr) == opcode::SC
}

/// Check if instruction is NOP.
pub fn is_nop(instr: u32) -> bool {
    instr == patterns::NOP
}

/// Score a single PPC instruction word.
fn score_word(word: u32) -> i64 {
    let mut score: i64 = 0;
    let op = get_opcode(word);

    // NOP (ori 0,0,0)
    if is_nop(word) {
        return 25;
    }

    // BLR (return)
    if is_blr(word) {
        return 30;
    }

    // BCTR
    if word == patterns::BCTR {
        return 20;
    }

    // SC (system call)
    if word == patterns::SC {
        return 20;
    }

    // TRAP
    if word == patterns::TRAP {
        return 15;
    }

    // MFLR r0 (save link register)
    if word == patterns::MFLR_R0 {
        return 25;
    }

    // MTLR r0 (restore link register)
    if word == patterns::MTLR_R0 {
        return 20;
    }

    // Check common opcodes
    match op {
        o if o == opcode::ADDI || o == opcode::ADDIS => score += 5,
        o if o == opcode::ORI || o == opcode::ORIS => score += 3,
        o if o == opcode::XORI || o == opcode::XORIS => score += 3,
        o if o == opcode::ANDI_DOT || o == opcode::ANDIS_DOT => score += 3,
        o if o == opcode::ADDIC || o == opcode::ADDIC_DOT => score += 3,
        o if o == opcode::SUBFIC => score += 3,
        o if o == opcode::MULLI => score += 3,
        o if o == opcode::CMPI || o == opcode::CMPLI => score += 4,
        o if o == opcode::BC => score += 5,
        o if o == opcode::B => score += 5,
        o if o == opcode::SC => score += 8,
        o if o == opcode::XL_FORM => score += 3,
        o if o == opcode::X_FORM => score += 3,
        o if o == opcode::RLWINM || o == opcode::RLWIMI => score += 4, // rotate/mask - distinctive
        o if o == opcode::RLWNM => score += 4,
        o if o == opcode::LWZ => score += 4,
        o if o == opcode::LWZU => score += 4,
        o if o == opcode::LBZ => score += 4,
        o if o == opcode::LBZU => score += 4,
        o if o == opcode::STW => score += 4,
        o if o == opcode::STWU => score += 5, // stwu r1,-N(r1) is PPC prologue - very common
        o if o == opcode::STB => score += 4,
        o if o == opcode::STBU => score += 4,
        o if o == opcode::LHZ => score += 4,
        o if o == opcode::LHZU => score += 4,
        o if o == opcode::LHA => score += 4,
        o if o == opcode::LHAU => score += 4,
        o if o == opcode::STH => score += 4,
        o if o == opcode::STHU => score += 4,
        o if o == opcode::LMW => score += 4,
        o if o == opcode::STMW => score += 4,
        o if o == opcode::LFS => score += 5,
        o if o == opcode::LFSU => score += 6,
        o if o == opcode::LFD => score += 5,
        o if o == opcode::LFDU => score += 6,
        o if o == opcode::STFS => score += 5,
        o if o == opcode::STFSU => score += 6,
        o if o == opcode::STFD => score += 5,
        o if o == opcode::STFDU => score += 6,
        o if o == opcode::LD_STD => score += 5, // 64-bit load/store
        o if o == opcode::STD => score += 5,    // 64-bit store
        o if o == opcode::FP_SINGLE => score += 5,
        o if o == opcode::FP_DOUBLE => score += 5,
        _ => {}
    }

    score
}

/// Internal: Score PPC code from pre-decoded words, applying structural requirements.
fn score_with_structural(data: &[u8], be: bool) -> i64 {
    let mut score: i64 = 0;
    let mut blr_count = 0u32;
    let mut bl_count = 0u32;
    let mut mflr_count = 0u32;
    let mut nop_count = 0u32;
    let mut zero_run = 0u32;

    let num_words = data.len() / 4;
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = if be {
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        } else {
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        };

        // Track zero padding (firmware often has long runs of 0x00000000 or 0xFFFFFFFF)
        if word == 0x00000000 || word == 0xFFFFFFFF {
            zero_run += 1;
            if zero_run <= 3 {
                score -= 1; // Minor penalty for occasional zeroes
            }
            continue;
        }
        if zero_run > 0 {
            zero_run = 0;
        }

        // Cross-architecture penalties for LE ISAs (when scoring BE PPC)
        if be {
            let le_word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            if le_word == 0xD65F03C0 {
                score -= 15;
                continue;
            } // AArch64 RET
            if le_word == 0xD503201F {
                score -= 12;
                continue;
            } // AArch64 NOP
            if le_word == 0xE12FFF1E {
                score -= 15;
                continue;
            } // ARM BX LR
            if le_word == 0xE1A00000 {
                score -= 10;
                continue;
            } // ARM NOP
            if le_word == 0x00008067 {
                score -= 12;
                continue;
            } // RISC-V RET
            if le_word == 0x00000013 {
                score -= 8;
                continue;
            } // RISC-V NOP
        }
        // Cross-architecture penalties for BE ISAs (when scoring LE PPC)
        if !be {
            let be_word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            if be_word == 0x01000000 {
                score -= 10;
                continue;
            } // SPARC NOP
            if be_word == 0x81C7E008 {
                score -= 15;
                continue;
            } // SPARC RET
            if be_word == 0x81C3E008 {
                score -= 15;
                continue;
            } // SPARC RETL
        }

        // Track distinctive patterns
        if is_nop(word) {
            nop_count += 1;
        }
        if is_blr(word) {
            blr_count += 1;
        }
        if is_bl(word) {
            bl_count += 1;
        }
        if word == patterns::MFLR_R0 || word == patterns::MTLR_R0 {
            mflr_count += 1;
        }

        // PPC64 prologue/epilogue bonus: STD r0,N(r1) / STDU r1,-N(r1)
        // These are very distinctive function setup patterns.
        if (word & 0xFFFF0003) == 0xF8010000 {
            score += 8;
        } // STD r0,N(r1) - save LR
        if (word & 0xFFFF0003) == 0xF8210001 {
            score += 10;
        } // STDU r1,-N(r1) - frame setup
        if (word & 0xFFFF0003) == 0xE8010000 {
            score += 8;
        } // LD r0,N(r1) - restore LR
          // PPC32 prologue: STWU r1,-N(r1) = 0x9421xxxx
        if (word & 0xFFFF0000) == 0x94210000 {
            score += 8;
        }

        score += score_word(word);
    }

    // Structural requirement: PPC opcode space has many valid-looking patterns.
    // B (opcode 18) alone covers 1/64 of the space (~1.56%), and most opcode
    // values 0-63 have valid mappings. Require distinctive PPC patterns.
    if num_words > 20 {
        let distinctive = blr_count + mflr_count + nop_count;
        if distinctive == 0 && bl_count == 0 {
            // No PPC-distinctive patterns at all
            score = (score as f64 * 0.15) as i64;
        } else if blr_count == 0 && mflr_count == 0 {
            // No returns or link register ops - suspicious
            score = (score as f64 * 0.40) as i64;
        }
    }

    score.max(0)
}

/// Score likelihood of PowerPC code (big-endian).
///
/// Analyzes raw bytes for patterns characteristic of PowerPC.
pub fn score(data: &[u8]) -> i64 {
    score_with_structural(data, true)
}

/// Score likelihood of PowerPC code (little-endian).
///
/// PPC64 LE (Power8+) uses little-endian instruction encoding.
pub fn score_le(data: &[u8]) -> i64 {
    score_with_structural(data, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_extraction() {
        assert_eq!(get_opcode(patterns::NOP), opcode::ORI);
        assert_eq!(get_opcode(patterns::BLR), opcode::XL_FORM);
    }

    #[test]
    fn test_blr_detection() {
        assert!(is_blr(patterns::BLR));
        assert!(!is_blr(patterns::NOP));
    }

    #[test]
    fn test_nop_detection() {
        assert!(is_nop(patterns::NOP));
    }

    #[test]
    fn test_score() {
        // PPC NOP (big-endian)
        let nop = patterns::NOP.to_be_bytes();
        assert!(score(&nop) > 0);
        // BLR
        let blr = patterns::BLR.to_be_bytes();
        assert!(score(&blr) > 0);
    }
}
