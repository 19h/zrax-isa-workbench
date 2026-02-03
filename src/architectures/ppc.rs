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

/// Score likelihood of PowerPC code.
///
/// Analyzes raw bytes for patterns characteristic of PowerPC.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;

    // PowerPC is big-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let op = get_opcode(word);

        // NOP (ori 0,0,0)
        if is_nop(word) {
            score += 25;
        }

        // BLR (return)
        if is_blr(word) {
            score += 30;
        }

        // SC (system call)
        if word == patterns::SC {
            score += 20;
        }

        // TRAP
        if word == patterns::TRAP {
            score += 15;
        }

        // MFLR r0 (save link register)
        if word == patterns::MFLR_R0 {
            score += 25;
        }

        // MTLR r0 (restore link register)
        if word == patterns::MTLR_R0 {
            score += 20;
        }

        // Check common opcodes
        match op {
            o if o == opcode::ADDI || o == opcode::ADDIS => score += 5,
            o if o == opcode::BC => score += 5,
            o if o == opcode::B => score += 5,
            o if o == opcode::XL_FORM => score += 3,
            o if o == opcode::X_FORM => score += 3,
            o if o == opcode::LWZ => score += 4,
            o if o == opcode::LWZU => score += 4,
            o if o == opcode::LBZ => score += 4,
            o if o == opcode::LBZU => score += 4,
            o if o == opcode::STW => score += 4,
            o if o == opcode::STWU => score += 4,
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
            o if o == opcode::LFS => score += 3,
            o if o == opcode::LFSU => score += 3,
            o if o == opcode::LFD => score += 3,
            o if o == opcode::LFDU => score += 3,
            o if o == opcode::STFS => score += 3,
            o if o == opcode::STFSU => score += 3,
            o if o == opcode::STFD => score += 3,
            o if o == opcode::STFDU => score += 3,
            _ => {}
        }

        // Invalid
        if word == 0x00000000 || word == 0xFFFFFFFF {
            score -= 5;
        }
    }

    score.max(0)
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
