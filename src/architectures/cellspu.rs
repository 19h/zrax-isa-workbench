//! Cell SPU (Synergistic Processing Unit) architecture analysis.
//!
//! The Cell SPU uses six fixed 32-bit instruction formats with a 128-bit SIMD architecture.
//! All 128 registers are 128 bits wide. Big-endian byte order.

/// Cell SPU opcode constants.
pub mod opcode {
    // Load/Store Instructions
    /// Load quadword d-form.
    pub const LQD: u8 = 0x34;
    /// Load quadword x-form.
    pub const LQX: u16 = 0x1C4;
    /// Load quadword a-form.
    pub const LQA: u16 = 0x061;
    /// Load quadword relative.
    pub const LQR: u16 = 0x067;
    /// Store quadword d-form.
    pub const STQD: u8 = 0x24;
    /// Store quadword x-form.
    pub const STQX: u16 = 0x144;
    /// Store quadword a-form.
    pub const STQA: u16 = 0x041;
    /// Store quadword relative.
    pub const STQR: u16 = 0x047;

    // Constant Formation
    /// Load word immediate.
    pub const IL: u16 = 0x081;
    /// Load halfword immediate.
    pub const ILH: u16 = 0x083;
    /// Load halfword upper immediate.
    pub const ILHU: u16 = 0x082;
    /// Load address (18-bit immediate).
    pub const ILA: u8 = 0x21;
    /// OR halfword lower immediate.
    pub const IOHL: u16 = 0x0C1;
    /// Form select mask bytes immediate.
    pub const FSMBI: u16 = 0x065;

    // Integer Arithmetic (RR format - 11-bit opcode)
    /// Add word.
    pub const A: u16 = 0x0C0;
    /// Add word immediate (RI10).
    pub const AI: u8 = 0x1C;
    /// Add halfword.
    pub const AH: u16 = 0x0C8;
    /// Add halfword immediate.
    pub const AHI: u8 = 0x1D;
    /// Subtract from word.
    pub const SF: u16 = 0x040;
    /// Subtract from word immediate.
    pub const SFI: u8 = 0x0C;
    /// Multiply.
    pub const MPY: u16 = 0x3C4;
    /// Multiply immediate.
    pub const MPYI: u8 = 0x74;
    /// Multiply and add (RRR format - 4-bit opcode).
    pub const MPYA: u8 = 0x0C;

    // Logical Operations (RR format)
    /// AND.
    pub const AND: u16 = 0x0C1;
    /// AND word immediate.
    pub const ANDI: u8 = 0x14;
    /// OR.
    pub const OR: u16 = 0x041;
    /// OR word immediate.
    pub const ORI: u8 = 0x04;
    /// XOR.
    pub const XOR: u16 = 0x241;
    /// XOR word immediate.
    pub const XORI: u8 = 0x44;
    /// NAND.
    pub const NAND: u16 = 0x0C9;
    /// NOR.
    pub const NOR: u16 = 0x049;
    /// Select bits (RRR format).
    pub const SELB: u8 = 0x08;
    /// Shuffle bytes (RRR format).
    pub const SHUFB: u8 = 0x0B;

    // Shift/Rotate (RR and RI7 formats)
    /// Shift left word.
    pub const SHL: u16 = 0x05B;
    /// Shift left word immediate.
    pub const SHLI: u16 = 0x07B;
    /// Rotate word.
    pub const ROT: u16 = 0x058;
    /// Rotate word immediate.
    pub const ROTI: u16 = 0x078;
    /// Rotate quadword by bytes.
    pub const ROTQBY: u16 = 0x1DC;
    /// Rotate quadword by bytes immediate.
    pub const ROTQBYI: u16 = 0x1FC;
    /// Shift left quadword by bytes.
    pub const SHLQBY: u16 = 0x1DF;
    /// Shift left quadword by bytes immediate.
    pub const SHLQBYI: u16 = 0x1FF;

    // Branch Instructions (RI16 and RR formats)
    /// Branch relative.
    pub const BR: u16 = 0x064;
    /// Branch absolute.
    pub const BRA: u16 = 0x060;
    /// Branch and set link.
    pub const BRSL: u16 = 0x066;
    /// Branch absolute and set link.
    pub const BRASL: u16 = 0x062;
    /// Branch indirect.
    pub const BI: u16 = 0x1A8;
    /// Branch indirect and set link.
    pub const BISL: u16 = 0x1A9;
    /// Branch if zero.
    pub const BRZ: u16 = 0x040;
    /// Branch if not zero.
    pub const BRNZ: u16 = 0x042;
    /// Branch indirect if zero.
    pub const BIZ: u16 = 0x128;
    /// Branch indirect if not zero.
    pub const BINZ: u16 = 0x129;

    // Floating-Point (RR and RRR formats)
    /// Floating add.
    pub const FA: u16 = 0x2C4;
    /// Floating subtract.
    pub const FS: u16 = 0x2C5;
    /// Floating multiply.
    pub const FM: u16 = 0x2C6;
    /// Floating multiply-add (RRR).
    pub const FMA: u8 = 0x0E;
    /// Floating multiply-subtract (RRR).
    pub const FMS: u8 = 0x0F;
    /// Floating negative multiply-subtract (RRR).
    pub const FNMS: u8 = 0x0D;
    /// Double floating add.
    pub const DFA: u16 = 0x2CC;
    /// Double floating multiply.
    pub const DFM: u16 = 0x2CE;
    /// Floating reciprocal estimate.
    pub const FREST: u16 = 0x1B8;
    /// Floating reciprocal sqrt estimate.
    pub const FRSQEST: u16 = 0x1B9;

    // Compare Instructions
    /// Compare equal word.
    pub const CEQ: u16 = 0x3C0;
    /// Compare equal word immediate.
    pub const CEQI: u8 = 0x7C;
    /// Compare greater than word.
    pub const CGT: u16 = 0x240;
    /// Compare greater than word immediate.
    pub const CGTI: u8 = 0x4C;

    // Channel Instructions
    /// Read channel.
    pub const RDCH: u16 = 0x00D;
    /// Write channel.
    pub const WRCH: u16 = 0x10D;
    /// Read channel count.
    pub const RCHCNT: u16 = 0x00F;

    // Stop and Signal
    /// Stop and signal.
    pub const STOP: u16 = 0x000;
    /// Stop with dependencies.
    pub const STOPD: u16 = 0x140;
    /// NOP (even pipeline).
    pub const NOP: u16 = 0x201;
    /// Load NOP (odd pipeline).
    pub const LNOP: u16 = 0x001;

    // Branch Hints
    /// Hint for branch.
    pub const HBR: u16 = 0x1AC;
}

/// Instruction format types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// RR format (Register-Register): 11-bit opcode.
    RR,
    /// RRR format (Three registers): 4-bit opcode.
    RRR,
    /// RI7 format (7-bit immediate): 11-bit opcode.
    RI7,
    /// RI10 format (10-bit immediate): 8-bit opcode.
    RI10,
    /// RI16 format (16-bit immediate): 9-bit opcode.
    RI16,
    /// RI18 format (18-bit immediate): 7-bit opcode.
    RI18,
    /// Invalid/unknown format.
    Unknown,
}

/// Extract RR/RI7 opcode (bits 0-10, 11 bits).
pub fn extract_opcode_11(instr: u32) -> u16 {
    ((instr >> 21) & 0x7FF) as u16
}

/// Extract RI10 opcode (bits 0-7, 8 bits).
pub fn extract_opcode_8(instr: u32) -> u8 {
    ((instr >> 24) & 0xFF) as u8
}

/// Extract RI16 opcode (bits 0-8, 9 bits).
pub fn extract_opcode_9(instr: u32) -> u16 {
    ((instr >> 23) & 0x1FF) as u16
}

/// Extract RI18 opcode (bits 0-6, 7 bits).
pub fn extract_opcode_7(instr: u32) -> u8 {
    ((instr >> 25) & 0x7F) as u8
}

/// Extract RRR opcode (bits 0-3, 4 bits).
pub fn extract_opcode_4(instr: u32) -> u8 {
    ((instr >> 28) & 0x0F) as u8
}

/// Extract RT (result register, bits 25-31).
pub fn extract_rt(instr: u32) -> u8 {
    (instr & 0x7F) as u8
}

/// Extract RA (first source, bits 18-24).
pub fn extract_ra(instr: u32) -> u8 {
    ((instr >> 7) & 0x7F) as u8
}

/// Extract RB (second source, bits 11-17).
pub fn extract_rb(instr: u32) -> u8 {
    ((instr >> 14) & 0x7F) as u8
}

/// Extract RC (third source for RRR, bits 25-31 at different position).
pub fn extract_rc(instr: u32) -> u8 {
    ((instr >> 21) & 0x7F) as u8
}

/// Extract I7 immediate (bits 11-17).
pub fn extract_i7(instr: u32) -> i8 {
    let val = ((instr >> 14) & 0x7F) as i8;
    // Sign extend from 7 bits
    if val & 0x40 != 0 {
        val | !0x7F_u8 as i8
    } else {
        val
    }
}

/// Extract I10 immediate (bits 8-17).
pub fn extract_i10(instr: u32) -> i16 {
    let val = ((instr >> 14) & 0x3FF) as i16;
    // Sign extend from 10 bits
    if val & 0x200 != 0 {
        val | !0x3FF_u16 as i16
    } else {
        val
    }
}

/// Extract I16 immediate (bits 9-24).
pub fn extract_i16(instr: u32) -> i16 {
    ((instr >> 7) & 0xFFFF) as i16
}

/// Extract I18 immediate (bits 7-24).
pub fn extract_i18(instr: u32) -> u32 {
    (instr >> 7) & 0x3FFFF
}

/// Determine instruction format from opcode patterns.
///
/// This checks opcode fields to identify the format.
pub fn determine_format(instr: u32) -> Format {
    // Check RRR format first (4-bit opcode in bits 28-31)
    let op4 = extract_opcode_4(instr);
    if matches!(
        op4,
        opcode::MPYA | opcode::SELB | opcode::SHUFB | opcode::FMA | opcode::FMS | opcode::FNMS
    ) {
        return Format::RRR;
    }

    // Check RI18 format (7-bit opcode)
    let op7 = extract_opcode_7(instr);
    if op7 == opcode::ILA {
        return Format::RI18;
    }

    // Check RI10 format (8-bit opcode)
    let op8 = extract_opcode_8(instr);
    if matches!(
        op8,
        opcode::LQD
            | opcode::STQD
            | opcode::AI
            | opcode::AHI
            | opcode::SFI
            | opcode::MPYI
            | opcode::ANDI
            | opcode::ORI
            | opcode::XORI
            | opcode::CEQI
            | opcode::CGTI
    ) {
        return Format::RI10;
    }

    // Check RI16 format (9-bit opcode)
    let op9 = extract_opcode_9(instr);
    if matches!(
        op9,
        0x061 | 0x067 | 0x041 | 0x047 | // LQA, LQR, STQA, STQR
        0x081 | 0x083 | 0x082 | 0x0C1 | 0x065 | // IL, ILH, ILHU, IOHL, FSMBI
        0x064 | 0x060 | 0x066 | 0x062 | // BR, BRA, BRSL, BRASL
        0x040 | 0x042 // BRZ, BRNZ
    ) {
        return Format::RI16;
    }

    // Check RR/RI7 format (11-bit opcode)
    let op11 = extract_opcode_11(instr);

    // RI7 format instructions
    if matches!(op11, 0x07B | 0x078 | 0x1FC | 0x1FF) {
        return Format::RI7;
    }

    // RR format instructions
    if matches!(
        op11,
        0x1C4 | 0x144 | // LQX, STQX
        0x0C0 | 0x0C8 | 0x040 | 0x3C4 | // A, AH, SF, MPY
        0x0C1 | 0x041 | 0x241 | 0x0C9 | 0x049 | // AND, OR, XOR, NAND, NOR
        0x05B | 0x058 | 0x1DC | 0x1DF | // SHL, ROT, ROTQBY, SHLQBY
        0x1A8 | 0x1A9 | 0x128 | 0x129 | // BI, BISL, BIZ, BINZ
        0x2C4 | 0x2C5 | 0x2C6 | 0x2CC | 0x2CE | // FA, FS, FM, DFA, DFM
        0x1B8 | 0x1B9 | // FREST, FRSQEST
        0x3C0 | 0x240 | // CEQ, CGT
        0x00D | 0x10D | 0x00F | // RDCH, WRCH, RCHCNT
        0x000 | 0x140 | 0x201 | 0x001 | // STOP, STOPD, NOP, LNOP
        0x1AC // HBR
    ) {
        return Format::RR;
    }

    // Check for NOP/LNOP patterns
    if op11 == opcode::NOP || op11 == opcode::LNOP {
        return Format::RR;
    }

    Format::Unknown
}

/// Check if instruction is a NOP.
pub fn is_nop(instr: u32) -> bool {
    let op11 = extract_opcode_11(instr);
    op11 == opcode::NOP || op11 == opcode::LNOP
}

/// Check if instruction is a branch.
pub fn is_branch(instr: u32) -> bool {
    let op9 = extract_opcode_9(instr);
    let op11 = extract_opcode_11(instr);

    // RI16 branches
    if matches!(
        op9,
        0x064 | 0x060 | 0x066 | 0x062 | 0x040 | 0x042
    ) {
        return true;
    }

    // RR branches
    matches!(op11, 0x1A8 | 0x1A9 | 0x128 | 0x129)
}

/// Check if instruction is a return (bi $lr).
pub fn is_return(instr: u32) -> bool {
    let op11 = extract_opcode_11(instr);
    if op11 == 0x1A8 {
        // BI instruction
        let ra = extract_ra(instr);
        // LR is register 0 on SPU
        return ra == 0;
    }
    false
}

/// Check if instruction is a load.
pub fn is_load(instr: u32) -> bool {
    let op8 = extract_opcode_8(instr);
    let op9 = extract_opcode_9(instr);
    let op11 = extract_opcode_11(instr);

    op8 == opcode::LQD || matches!(op9, 0x061 | 0x067) || op11 == 0x1C4
}

/// Check if instruction is a store.
pub fn is_store(instr: u32) -> bool {
    let op8 = extract_opcode_8(instr);
    let op9 = extract_opcode_9(instr);
    let op11 = extract_opcode_11(instr);

    op8 == opcode::STQD || matches!(op9, 0x041 | 0x047) || op11 == 0x144
}

/// Check if instruction is a floating-point operation.
pub fn is_fpu(instr: u32) -> bool {
    let op4 = extract_opcode_4(instr);
    let op11 = extract_opcode_11(instr);

    matches!(op4, opcode::FMA | opcode::FMS | opcode::FNMS)
        || matches!(op11, 0x2C4 | 0x2C5 | 0x2C6 | 0x2CC | 0x2CE | 0x1B8 | 0x1B9)
}

/// Check if instruction is a channel operation.
pub fn is_channel_op(instr: u32) -> bool {
    let op11 = extract_opcode_11(instr);
    matches!(op11, 0x00D | 0x10D | 0x00F)
}

/// Check if instruction is a SIMD shuffle/select.
pub fn is_simd_shuffle(instr: u32) -> bool {
    let op4 = extract_opcode_4(instr);
    matches!(op4, opcode::SELB | opcode::SHUFB)
}

/// Score likelihood of Cell SPU code.
///
/// Analyzes raw bytes for patterns characteristic of SPU:
/// - Fixed 32-bit instructions (big-endian)
/// - Valid opcode patterns across six formats
/// - SIMD/vector operation patterns
/// - Channel operation patterns
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 4 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;

    // SPU is big-endian, 4-byte aligned
    let mut i = 0;
    while i + 3 < data.len() {
        let instr = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let format = determine_format(instr);

        if format == Format::Unknown {
            // Check for NOP pattern
            if is_nop(instr) {
                valid_count += 1;
                total_score += 8;
            } else {
                invalid_count += 1;
            }
            i += 4;
            continue;
        }

        valid_count += 1;

        // Score based on instruction type
        if is_nop(instr) {
            total_score += 8;
        } else if is_return(instr) {
            total_score += 15; // Strong indicator
        } else if is_branch(instr) {
            total_score += 6;
            let op9 = extract_opcode_9(instr);
            if matches!(op9, 0x066 | 0x062) {
                // BRSL, BRASL - call instructions
                total_score += 4;
            }
        } else if is_load(instr) {
            total_score += 5;
        } else if is_store(instr) {
            total_score += 5;
        } else if is_fpu(instr) {
            total_score += 8;
            // FMA/FMS are very common and distinctive
            let op4 = extract_opcode_4(instr);
            if matches!(op4, opcode::FMA | opcode::FMS) {
                total_score += 4;
            }
        } else if is_channel_op(instr) {
            total_score += 12; // Channel ops are very SPU-specific
        } else if is_simd_shuffle(instr) {
            total_score += 10; // SIMD shuffles are distinctive
        } else {
            // General valid instruction
            match format {
                Format::RR => total_score += 4,
                Format::RRR => total_score += 6,
                Format::RI7 => total_score += 4,
                Format::RI10 => total_score += 4,
                Format::RI16 => total_score += 5,
                Format::RI18 => total_score += 5,
                Format::Unknown => {}
            }
        }

        // Check for common constant loading patterns
        let op9 = extract_opcode_9(instr);
        if matches!(op9, 0x081 | 0x083 | 0x082 | 0x0C1) {
            // IL, ILH, ILHU, IOHL
            total_score += 3;
        }

        i += 4;
    }

    // Adjust based on validity ratio
    if valid_count + invalid_count > 0 {
        let validity_ratio = valid_count as f64 / (valid_count + invalid_count) as f64;
        total_score = (total_score as f64 * validity_ratio) as i64;

        // Bonus for high validity
        if validity_ratio > 0.80 && valid_count > 10 {
            total_score += 15;
        }
    }

    total_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_format() {
        // NOP instruction (11-bit opcode 0x201)
        let nop: u32 = 0x201 << 21;
        let nop_be = nop.swap_bytes();
        assert_eq!(determine_format(nop), Format::RR);
    }

    #[test]
    fn test_is_nop() {
        let nop: u32 = opcode::NOP as u32;
        // NOP opcode in bits 21-31 (11-bit)
        let instr = nop << 21;
        assert!(is_nop(instr));

        let lnop: u32 = opcode::LNOP as u32;
        let instr2 = lnop << 21;
        assert!(is_nop(instr2));
    }

    #[test]
    fn test_extract_registers() {
        // Create instruction with known register values
        // RT in bits 0-6, RA in bits 7-13, RB in bits 14-20
        let rt: u32 = 5;
        let ra: u32 = 10;
        let rb: u32 = 15;
        let instr = rt | (ra << 7) | (rb << 14);

        assert_eq!(extract_rt(instr), 5);
        assert_eq!(extract_ra(instr), 10);
        assert_eq!(extract_rb(instr), 15);
    }

    #[test]
    fn test_score_basic() {
        // Create some valid SPU instructions (big-endian)
        let mut code = Vec::new();

        // NOP (opcode 0x201 in bits 21-31)
        let nop: u32 = (opcode::NOP as u32) << 21;
        code.extend_from_slice(&nop.to_be_bytes());

        // LNOP
        let lnop: u32 = (opcode::LNOP as u32) << 21;
        code.extend_from_slice(&lnop.to_be_bytes());

        let s = score(&code);
        assert!(s > 0, "Valid SPU code should score positive");
    }

    #[test]
    fn test_score_branch() {
        // BR instruction (9-bit opcode 0x064)
        let mut code = Vec::new();
        let br: u32 = 0x064 << 23;
        code.extend_from_slice(&br.to_be_bytes());

        let s = score(&code);
        assert!(s > 0, "Branch instruction should score positive");
    }

    #[test]
    fn test_is_branch() {
        // BR instruction
        let br: u32 = 0x064 << 23;
        assert!(is_branch(br));

        // BI instruction (11-bit opcode 0x1A8)
        let bi: u32 = 0x1A8 << 21;
        assert!(is_branch(bi));
    }
}
