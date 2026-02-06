//! IBM s390x (z/Architecture) analysis.
//!
//! s390x uses variable-length instructions (2, 4, or 6 bytes).
//! Instruction length is determined by the first two bits of the first byte.

/// Instruction length detection based on first byte.
pub mod length {
    /// Determine instruction length from first byte.
    /// Bits [7:6] of the first byte encode the length:
    /// - 00 = 2 bytes
    /// - 01 = 4 bytes
    /// - 10 = 4 bytes
    /// - 11 = 6 bytes
    pub fn from_first_byte(byte: u8) -> usize {
        match (byte >> 6) & 0x03 {
            0b00 => 2,
            0b01 => 4,
            0b10 => 4,
            0b11 => 6,
            _ => unreachable!(),
        }
    }
}

/// 2-byte RR-format opcodes.
pub mod opcode_rr {
    pub const SPM: u8 = 0x04; // Set Program Mask
    pub const BALR: u8 = 0x05; // Branch and Link Register
    pub const BCTR: u8 = 0x06; // Branch on Count Register
    pub const BCR: u8 = 0x07; // Branch on Condition Register
    pub const SVC: u8 = 0x0A; // Supervisor Call
    pub const BSM: u8 = 0x0B; // Branch and Set Mode
    pub const BASSM: u8 = 0x0C; // Branch and Save and Set Mode
    pub const BASR: u8 = 0x0D; // Branch and Save Register
    pub const MVCL: u8 = 0x0E; // Move Long
    pub const CLCL: u8 = 0x0F; // Compare Logical Long
    pub const LPR: u8 = 0x10; // Load Positive Register
    pub const LNR: u8 = 0x11; // Load Negative Register
    pub const LTR: u8 = 0x12; // Load and Test Register
    pub const LCR: u8 = 0x13; // Load Complement Register
    pub const NR: u8 = 0x14; // AND Register
    pub const CLR: u8 = 0x15; // Compare Logical Register
    pub const OR: u8 = 0x16; // OR Register
    pub const XR: u8 = 0x17; // XOR Register
    pub const LR: u8 = 0x18; // Load Register
    pub const CR: u8 = 0x19; // Compare Register
    pub const AR: u8 = 0x1A; // Add Register
    pub const SR: u8 = 0x1B; // Subtract Register
    pub const MR: u8 = 0x1C; // Multiply Register
    pub const DR: u8 = 0x1D; // Divide Register
    pub const ALR: u8 = 0x1E; // Add Logical Register
    pub const SLR: u8 = 0x1F; // Subtract Logical Register
}

/// 4-byte RX-format opcodes.
pub mod opcode_rx {
    pub const LA: u8 = 0x41; // Load Address
    pub const STC: u8 = 0x42; // Store Character
    pub const IC: u8 = 0x43; // Insert Character
    pub const EX: u8 = 0x44; // Execute
    pub const BAL: u8 = 0x45; // Branch and Link
    pub const BCT: u8 = 0x46; // Branch on Count
    pub const BC: u8 = 0x47; // Branch on Condition
    pub const LH: u8 = 0x48; // Load Halfword
    pub const CH: u8 = 0x49; // Compare Halfword
    pub const AH: u8 = 0x4A; // Add Halfword
    pub const SH: u8 = 0x4B; // Subtract Halfword
    pub const MH: u8 = 0x4C; // Multiply Halfword
    pub const BAS: u8 = 0x4D; // Branch and Save
    pub const CVD: u8 = 0x4E; // Convert to Decimal
    pub const CVB: u8 = 0x4F; // Convert to Binary
    pub const ST: u8 = 0x50; // Store
    pub const LAE: u8 = 0x51; // Load Address Extended
    pub const N: u8 = 0x54; // AND
    pub const CL: u8 = 0x55; // Compare Logical
    pub const O: u8 = 0x56; // OR
    pub const X: u8 = 0x57; // XOR
    pub const L: u8 = 0x58; // Load
    pub const C: u8 = 0x59; // Compare
    pub const A: u8 = 0x5A; // Add
    pub const S: u8 = 0x5B; // Subtract
    pub const M: u8 = 0x5C; // Multiply
    pub const D: u8 = 0x5D; // Divide
    pub const AL: u8 = 0x5E; // Add Logical
    pub const SL: u8 = 0x5F; // Subtract Logical
    pub const STD: u8 = 0x60; // Store (Long)
    pub const LD: u8 = 0x68; // Load (Long)
    pub const CD: u8 = 0x69; // Compare (Long)
    pub const AD: u8 = 0x6A; // Add Normalized (Long)
    pub const SD: u8 = 0x6B; // Subtract Normalized (Long)
    pub const MD: u8 = 0x6C; // Multiply (Long)
    pub const DD: u8 = 0x6D; // Divide (Long)
    pub const STE: u8 = 0x70; // Store (Short)
    pub const LE: u8 = 0x78; // Load (Short)
    pub const CE: u8 = 0x79; // Compare (Short)
    pub const AE: u8 = 0x7A; // Add Normalized (Short)
    pub const SE: u8 = 0x7B; // Subtract Normalized (Short)
    pub const ME: u8 = 0x7C; // Multiply (Short)
    pub const DE: u8 = 0x7D; // Divide (Short)
}

/// 6-byte RXY-format extended opcodes (E3xx prefix).
pub mod opcode_e3 {
    pub const LG: u8 = 0x04; // Load (64)
    pub const LRAG: u8 = 0x03; // Load Real Address (64)
    pub const LGF: u8 = 0x14; // Load (64 <- 32)
    pub const LGHI: u8 = 0x15; // Load Halfword Immediate (64)
    pub const STG: u8 = 0x24; // Store (64)
    pub const LTGF: u8 = 0x32; // Load and Test (64 <- 32)
    pub const LGH: u8 = 0x15; // Load Halfword (64)
    pub const LLGF: u8 = 0x16; // Load Logical (64 <- 32)
    pub const LLGT: u8 = 0x17; // Load Logical Thirty One Bits
    pub const AGF: u8 = 0x18; // Add (64 <- 32)
    pub const SGF: u8 = 0x19; // Subtract (64 <- 32)
    pub const ALGF: u8 = 0x1A; // Add Logical (64 <- 32)
    pub const SLGF: u8 = 0x1B; // Subtract Logical (64 <- 32)
    pub const MSG: u8 = 0x0C; // Multiply Single (64)
    pub const DSG: u8 = 0x0D; // Divide Single (64)
    pub const LY: u8 = 0x58; // Load (Long Displacement)
    pub const LAY: u8 = 0x71; // Load Address (Long Displacement)
    pub const STCY: u8 = 0x72; // Store Character (Long Displacement)
    pub const ICY: u8 = 0x73; // Insert Character (Long Displacement)
    pub const LAEY: u8 = 0x75; // Load Address Extended (Long Displacement)
    pub const STY: u8 = 0x50; // Store (Long Displacement)
    pub const LLGC: u8 = 0x90; // Load Logical Character (64)
    pub const LLGH: u8 = 0x91; // Load Logical Halfword (64)
}

/// 6-byte RIE-format extended opcodes (ECxx prefix).
pub mod opcode_ec {
    pub const RNSBG: u8 = 0x54; // Rotate Then AND Selected Bits
    pub const RISBG: u8 = 0x55; // Rotate Then Insert Selected Bits
    pub const ROSBG: u8 = 0x56; // Rotate Then OR Selected Bits
    pub const RXSBG: u8 = 0x57; // Rotate Then XOR Selected Bits
    pub const RISBGN: u8 = 0x59; // Rotate Then Insert Selected Bits (No CC)
    pub const RISBHG: u8 = 0x5D; // Rotate Then Insert Selected Bits High
    pub const RISBLG: u8 = 0x51; // Rotate Then Insert Selected Bits Low
}

/// 6-byte RXE-format extended opcodes (EDxx prefix) - Floating point.
pub mod opcode_ed {
    pub const LDEB: u8 = 0x04; // Load Lengthened (Short to Long)
    pub const LXDB: u8 = 0x05; // Load Lengthened (Long to Extended)
    pub const LXEB: u8 = 0x06; // Load Lengthened (Short to Extended)
    pub const SQEB: u8 = 0x14; // Square Root (Short)
    pub const SQDB: u8 = 0x15; // Square Root (Long)
    pub const MEEB: u8 = 0x17; // Multiply (Short)
    pub const MAEB: u8 = 0x0E; // Multiply and Add (Short)
    pub const MSEB: u8 = 0x0F; // Multiply and Subtract (Short)
    pub const MADB: u8 = 0x1E; // Multiply and Add (Long)
    pub const MSDB: u8 = 0x1F; // Multiply and Subtract (Long)
}

/// Common s390x instruction patterns.
pub mod patterns {
    /// 2-byte NOP (BCR 0,0).
    pub const NOP_2B: u16 = 0x0700;

    /// 4-byte NOP (BC 0,0).
    pub const NOP_4B: u32 = 0x47000000;

    /// BR R14 - Return (BCR 15, R14).
    pub const BR_R14: u16 = 0x07FE;

    /// NOPR R7 - Explicit no-op.
    pub const NOPR_R7: u16 = 0x0707;

    /// SVC 0 - Supervisor call.
    pub const SVC_0: u16 = 0x0A00;
}

/// Condition codes for BCR/BC instructions.
pub mod condition {
    pub const NEVER: u8 = 0; // Never branch (NOP)
    pub const OVERFLOW: u8 = 1; // Overflow
    pub const HIGH: u8 = 2; // High (>)
    pub const LOW: u8 = 4; // Low (<)
    pub const NOT_HIGH: u8 = 13; // Not high (<=)
    pub const NOT_LOW: u8 = 11; // Not low (>=)
    pub const EQUAL: u8 = 8; // Equal (==)
    pub const NOT_EQUAL: u8 = 7; // Not equal (!=)
    pub const ALWAYS: u8 = 15; // Always branch
}

/// Extract opcode from first byte (2-byte instructions).
pub fn get_opcode_2b(instr: u16) -> u8 {
    (instr >> 8) as u8
}

/// Extract R1 field from RR-format instruction.
pub fn get_r1_rr(instr: u16) -> u8 {
    ((instr >> 4) & 0x0F) as u8
}

/// Extract R2 field from RR-format instruction.
pub fn get_r2_rr(instr: u16) -> u8 {
    (instr & 0x0F) as u8
}

/// Extract mask field from RR-format instruction (for BCR).
pub fn get_mask_rr(instr: u16) -> u8 {
    get_r1_rr(instr)
}

/// Extract opcode from first byte (4-byte instructions).
pub fn get_opcode_4b(instr: u32) -> u8 {
    (instr >> 24) as u8
}

/// Extract R1 field from RX-format instruction.
pub fn get_r1_rx(instr: u32) -> u8 {
    ((instr >> 20) & 0x0F) as u8
}

/// Extract X2 field from RX-format instruction.
pub fn get_x2_rx(instr: u32) -> u8 {
    ((instr >> 16) & 0x0F) as u8
}

/// Extract B2 field from RX-format instruction.
pub fn get_b2_rx(instr: u32) -> u8 {
    ((instr >> 12) & 0x0F) as u8
}

/// Extract D2 field from RX-format instruction.
pub fn get_d2_rx(instr: u32) -> u16 {
    (instr & 0x0FFF) as u16
}

/// Check if instruction is a 2-byte NOP.
pub fn is_nop_2b(instr: u16) -> bool {
    // BCR 0,R (any R) or BCR M,0 where M != 15
    let op = get_opcode_2b(instr);
    if op != opcode_rr::BCR {
        return false;
    }
    let mask = get_mask_rr(instr);
    let r2 = get_r2_rr(instr);
    mask == 0 || (r2 == 0 && mask != condition::ALWAYS)
}

/// Check if instruction is a 4-byte NOP.
pub fn is_nop_4b(instr: u32) -> bool {
    // BC 0,D(X,B) where mask is 0
    let op = get_opcode_4b(instr);
    if op != opcode_rx::BC {
        return false;
    }
    let mask = get_r1_rx(instr);
    mask == 0
}

/// Check if instruction is BR R14 (return).
pub fn is_return(instr: u16) -> bool {
    // BCR 15,14 (unconditional branch to R14)
    instr == patterns::BR_R14
}

/// Check if instruction is a supervisor call.
pub fn is_svc(instr: u16) -> bool {
    get_opcode_2b(instr) == opcode_rr::SVC
}

/// Extract SVC number from instruction.
pub fn get_svc_number(instr: u16) -> u8 {
    (instr & 0xFF) as u8
}

/// Check if instruction is a branch (BCR or BC).
pub fn is_branch(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let op = data[0];
    op == opcode_rr::BCR || op == opcode_rx::BC
}

/// Check if instruction is a call (BALR, BAL, BAS, BASR).
pub fn is_call(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let op = data[0];
    matches!(
        op,
        opcode_rr::BALR | opcode_rr::BASR | opcode_rx::BAL | opcode_rx::BAS
    )
}

/// Check if instruction is a load.
pub fn is_load(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let op = data[0];
    matches!(
        op,
        opcode_rr::LR
            | opcode_rx::L
            | opcode_rx::LH
            | opcode_rx::LA
            | opcode_rx::LD
            | opcode_rx::LE
            | opcode_rx::IC
    )
}

/// Check if instruction is a store.
pub fn is_store(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let op = data[0];
    matches!(
        op,
        opcode_rx::ST | opcode_rx::STD | opcode_rx::STE | opcode_rx::STC
    )
}

/// Determine instruction length from raw bytes.
pub fn instruction_length(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    Some(length::from_first_byte(data[0]))
}

/// Valid 2-byte opcodes for heuristic detection.
pub const VALID_2B_OPCODES: &[u8] = &[
    opcode_rr::SPM,
    opcode_rr::BALR,
    opcode_rr::BCTR,
    opcode_rr::BCR,
    opcode_rr::SVC,
    opcode_rr::BSM,
    opcode_rr::BASSM,
    opcode_rr::BASR,
    opcode_rr::MVCL,
    opcode_rr::CLCL,
    opcode_rr::LPR,
    opcode_rr::LNR,
    opcode_rr::LTR,
    opcode_rr::LCR,
    opcode_rr::NR,
    opcode_rr::CLR,
    opcode_rr::OR,
    opcode_rr::XR,
    opcode_rr::LR,
    opcode_rr::CR,
    opcode_rr::AR,
    opcode_rr::SR,
    opcode_rr::MR,
    opcode_rr::DR,
    opcode_rr::ALR,
    opcode_rr::SLR,
];

/// Valid 4-byte opcodes for heuristic detection.
pub const VALID_4B_OPCODES: &[u8] = &[
    opcode_rx::LA,
    opcode_rx::STC,
    opcode_rx::IC,
    opcode_rx::EX,
    opcode_rx::BAL,
    opcode_rx::BCT,
    opcode_rx::BC,
    opcode_rx::LH,
    opcode_rx::CH,
    opcode_rx::AH,
    opcode_rx::SH,
    opcode_rx::MH,
    opcode_rx::BAS,
    opcode_rx::CVD,
    opcode_rx::CVB,
    opcode_rx::ST,
    opcode_rx::N,
    opcode_rx::CL,
    opcode_rx::O,
    opcode_rx::X,
    opcode_rx::L,
    opcode_rx::C,
    opcode_rx::A,
    opcode_rx::S,
    opcode_rx::M,
    opcode_rx::D,
    opcode_rx::AL,
    opcode_rx::SL,
    opcode_rx::STD,
    opcode_rx::LD,
    opcode_rx::STE,
    opcode_rx::LE,
];

/// Score likelihood of s390x code.
///
/// Analyzes raw bytes for patterns characteristic of s390x.
pub fn score(data: &[u8]) -> i64 {
    let mut score: i64 = 0;
    let mut valid_count = 0u32;
    let mut total_count = 0u32;
    let mut i = 0;

    while i < data.len() {
        let first = data[i];
        let len = length::from_first_byte(first);

        if i + len > data.len() {
            break;
        }

        total_count += 1;

        // 2-byte instructions (first 2 bits = 00)
        if len == 2 && i + 2 <= data.len() {
            let half = u16::from_be_bytes([data[i], data[i + 1]]);

            // NOP (BCR 0,0)
            if half == patterns::NOP_2B {
                score += 20;
                valid_count += 1;
                i += len;
                continue;
            }

            // BR r14 (return)
            if is_return(half) {
                score += 30;
                valid_count += 1;
                i += len;
                continue;
            }

            // NOPR R7
            if half == patterns::NOPR_R7 {
                score += 15;
                valid_count += 1;
                i += len;
                continue;
            }

            // SVC
            if is_svc(half) {
                score += 15;
                valid_count += 1;
                i += len;
                continue;
            }

            // Common RR instructions
            let op = get_opcode_2b(half);
            if VALID_2B_OPCODES.contains(&op) {
                score += 4;
                valid_count += 1;
            }
        }

        // 4-byte instructions (first 2 bits = 01 or 10)
        if len == 4 && i + 4 <= data.len() {
            let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

            // NOP (BC 0,0)
            if word == patterns::NOP_4B {
                score += 20;
                valid_count += 1;
                i += len;
                continue;
            }

            let op = get_opcode_4b(word);
            if VALID_4B_OPCODES.contains(&op) {
                // Score based on specificity
                match op {
                    o if o == opcode_rx::LA => score += 5,
                    o if o == opcode_rx::BC => score += 5,
                    o if o == opcode_rx::ST => score += 5,
                    o if o == opcode_rx::L => score += 5,
                    o if o == opcode_rx::BAL || o == opcode_rx::BAS => score += 5,
                    o if o == opcode_rx::LH || o == opcode_rx::STD || o == opcode_rx::LD => score += 4,
                    _ => score += 3,
                }
                valid_count += 1;
            } else {
                // Check 4-byte RI/RS/SI format opcodes (0x80-0xBF range)
                // These include: STM(0x90), LM(0x98), SLL(0x89), SRL(0x88), SLA(0x8B), etc.
                // Also: A7xx (RI format: TMHH, TMHL, TMLH, TMLL, BRC, AGHI, etc.)
                match op {
                    0x88 | 0x89 | 0x8A | 0x8B => { score += 3; valid_count += 1; } // shifts
                    0x90 | 0x91 | 0x92 | 0x93 => { score += 4; valid_count += 1; } // STM, TM, MVI, TS
                    0x94 | 0x95 | 0x96 | 0x97 => { score += 3; valid_count += 1; } // NI, CLI, OI, XI
                    0x98 | 0x99 | 0x9A | 0x9B => { score += 4; valid_count += 1; } // LM, TRACE, etc
                    0xA7 => { // RI format - very common in z/Arch
                        let ri_op = ((word >> 16) & 0x0F) as u8;
                        match ri_op {
                            0x04 => { score += 5; valid_count += 1; } // BRC (branch)
                            0x08 => { score += 5; valid_count += 1; } // LHI (load halfword imm)
                            0x09 => { score += 5; valid_count += 1; } // LGHI
                            0x0A => { score += 4; valid_count += 1; } // AGHI (add halfword imm)
                            0x0B => { score += 4; valid_count += 1; } // MGHI (multiply)
                            0x0C => { score += 4; valid_count += 1; } // MHI
                            0x0E => { score += 4; valid_count += 1; } // CHI (compare)
                            0x0F => { score += 4; valid_count += 1; } // CGHI
                            _ => { score += 2; valid_count += 1; }
                        }
                    }
                    0xB2 | 0xB3 | 0xB9 => { score += 3; valid_count += 1; } // Extended RRE/RRF
                    _ => {}
                }
            }
        }

        // 6-byte instructions (first 2 bits = 11)
        if len == 6 && i + 6 <= data.len() {
            let op = first;
            let op2 = data[i + 5]; // Last byte contains extended opcode
            valid_count += 1;

            match op {
                0xC0 => {
                    // RIL format: LARL, BRCL, LGFI, etc.
                    let ril_op = ((data[i + 1] >> 4) & 0x0F) as u8;
                    match ril_op {
                        0x00 => score += 6, // LARL (very common)
                        0x04 => score += 5, // BRCL
                        0x05 => score += 5, // BRASL (call)
                        0x0E => score += 4, // LLIHF
                        0x0F => score += 4, // LLILF
                        _ => score += 3,
                    }
                }
                0xC4 => score += 4, // RIL: LRL, STRL etc.
                0xC6 => score += 4, // RIL: EXRL, etc.
                0xE3 => {
                    // RXY format: LG, STG, LGF, etc. Very common in 64-bit code
                    match op2 {
                        0x04 => score += 6, // LG
                        0x24 => score += 6, // STG
                        0x14 | 0x16 | 0x17 => score += 5, // LGF, LLGF, LLGT
                        0x58 | 0x50 => score += 5, // LY, STY
                        0x71 => score += 5, // LAY
                        _ => score += 3,
                    }
                }
                0xEB => {
                    // RSY format: STMG, LMG, SLLG, SRLG etc.
                    match op2 {
                        0x04 => score += 6, // LMG (load multiple)
                        0x24 => score += 6, // STMG (store multiple)
                        0x0C | 0x0D => score += 4, // SRLG, SLLG
                        _ => score += 3,
                    }
                }
                0xEC => {
                    // RIE format: RISBG, CIJ, CGIJ, etc.
                    match op2 {
                        0x55 => score += 5, // RISBG (very common bit manipulation)
                        0x64 | 0x65 | 0x76 | 0x7C | 0x7D => score += 4, // comparisons
                        _ => score += 3,
                    }
                }
                0xED => score += 3, // RXE: FP operations
                0xE5 => score += 3, // SSE format
                _ => { valid_count -= 1; } // Not a recognized 6-byte
            }
        }

        i += len;
    }

    // Validity ratio bonus - but require a reasonable amount of recognized instructions
    if total_count > 10 {
        let ratio = valid_count as f64 / total_count as f64;
        if ratio > 0.7 && valid_count > 15 {
            score += 15;
        } else if ratio > 0.5 && valid_count > 10 {
            score += 8;
        }

        // Cross-check: real s390x code should have a mix of instruction lengths.
        // If nearly everything is 2-byte, it's likely not real s390x.
        // (MSP430 data tends to map to 2-byte RR instructions)
        // Count 2-byte vs 4/6-byte instructions
        let mut len2_count = 0u32;
        let mut j = 0;
        while j < data.len() {
            let len_check = length::from_first_byte(data[j]);
            if len_check == 2 { len2_count += 1; }
            if j + len_check > data.len() { break; }
            j += len_check;
        }
        let total_instrs = total_count;
        if total_instrs > 10 {
            let len2_ratio = len2_count as f64 / total_instrs as f64;
            // If >80% of instructions are 2-byte, penalize heavily
            // Real s390x code has a healthy mix of 2/4/6-byte instructions
            if len2_ratio > 0.8 {
                score = (score as f64 * 0.3) as i64;
            } else if len2_ratio > 0.6 {
                score = (score as f64 * 0.6) as i64;
            }
        }
    }

    score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_length() {
        // 2-byte: first bits 00
        assert_eq!(length::from_first_byte(0x07), 2); // BCR
        assert_eq!(length::from_first_byte(0x0A), 2); // SVC
        assert_eq!(length::from_first_byte(0x18), 2); // LR

        // 4-byte: first bits 01 or 10
        assert_eq!(length::from_first_byte(0x41), 4); // LA
        assert_eq!(length::from_first_byte(0x58), 4); // L
        assert_eq!(length::from_first_byte(0x90), 4); // STM
        assert_eq!(length::from_first_byte(0xA7), 4); // Various

        // 6-byte: first bits 11
        assert_eq!(length::from_first_byte(0xC0), 6); // LARL etc
        assert_eq!(length::from_first_byte(0xE3), 6); // RXY format
        assert_eq!(length::from_first_byte(0xEC), 6); // RIE format
        assert_eq!(length::from_first_byte(0xED), 6); // RXE format
    }

    #[test]
    fn test_nop_detection() {
        assert!(is_nop_2b(patterns::NOP_2B));
        assert!(is_nop_4b(patterns::NOP_4B));
    }

    #[test]
    fn test_return_detection() {
        assert!(is_return(patterns::BR_R14));
        assert!(!is_return(patterns::NOP_2B));
    }

    #[test]
    fn test_svc_detection() {
        assert!(is_svc(patterns::SVC_0));
        assert_eq!(get_svc_number(0x0A01), 1);
    }

    #[test]
    fn test_rr_field_extraction() {
        // LR R1,R2 = 0x1812
        let instr: u16 = 0x1812;
        assert_eq!(get_opcode_2b(instr), opcode_rr::LR);
        assert_eq!(get_r1_rr(instr), 1);
        assert_eq!(get_r2_rr(instr), 2);
    }

    #[test]
    fn test_rx_field_extraction() {
        // L R1,D2(X2,B2) = 0x5810F004 (L R1,4(,R15))
        let instr: u32 = 0x5810F004;
        assert_eq!(get_opcode_4b(instr), opcode_rx::L);
        assert_eq!(get_r1_rx(instr), 1);
        assert_eq!(get_x2_rx(instr), 0);
        assert_eq!(get_b2_rx(instr), 15);
        assert_eq!(get_d2_rx(instr), 4);
    }

    #[test]
    fn test_score() {
        // s390x NOP (big-endian)
        let nop = patterns::NOP_2B.to_be_bytes();
        assert!(score(&nop) > 0);
    }
}
