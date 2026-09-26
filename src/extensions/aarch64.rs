//! AArch64 extension evidence.
//!
//! A64 instructions are 32-bit little-endian words (in both data byte
//! orders). Code regions start at 1 KB-aligned file offsets, so they are
//! word aligned. Each word is classified by exact encoding masks, dispatched
//! on the top-level `op0` field (bits 28:25):
//!
//! * `0000` with bit 31 clear, `0001`, `0011` are unallocated/UDF: invalid.
//! * `0000` with bit 31 set is the SME space; `0010` is the SVE space.
//!
//! Beyond `op0`, every word is checked against a bitmap of the encodings
//! LLVM's AArch64 decoder (LLVM 23, `-mattr=+all`) accepts, keyed by bits
//! 31:21 and 15:10 (`aarch64_valid.bin`, 2^17 bits): a key is valid if any
//! sample of the remaining bits decodes (every combination of bits 20:16 and
//! 4:0 with bits 9:5 = 0 or 31, plus random samples). 57% of the keys are
//! unallocated.
//! Over 43.6M words of executable sections of Debian arm64 binaries the only
//! words rejected are literal data (addresses, floating-point constants).
//!
//! SVE is reported only together with at least one instruction that every
//! use of SVE needs to set up predicates or vector lengths (PTRUE, WHILE*,
//! CNT*/INC*/DEC*, RDVL, ADDVL, ADDPL); SME likewise needs SMSTART/SMSTOP,
//! RDSVL, ADDSVL or ADDSPL.

use super::{bit_of, ExtDef, Tally};
use crate::types::{Endianness, ExtensionCategory::*, Isa};

const SVE_SETUP_IDX: usize = 0;
const SME_SETUP_IDX: usize = 1;

pub(super) const EXTS: &[ExtDef] = &[
    ExtDef::hidden("sve-setup"),
    ExtDef::hidden("sme-setup"),
    ExtDef::new("NEON", Simd),
    ExtDef::new("SVE", Simd).anchored(SVE_SETUP_IDX),
    ExtDef::new("SME", Simd).anchored(SME_SETUP_IDX),
    ExtDef::narrow("DOTPROD", Simd),
    ExtDef::new("FP16", Simd),
    ExtDef::narrow("BF16", Simd),
    ExtDef::narrow("I8MM", Simd),
    ExtDef::narrow("RDM", Simd),
    ExtDef::narrow("FHM", Simd),
    ExtDef::narrow("FCMA", Simd),
    ExtDef::narrow("FRINTTS", Simd),
    ExtDef::narrow("AES", Crypto),
    ExtDef::narrow("PMULL", Crypto),
    ExtDef::narrow("SHA1", Crypto),
    ExtDef::narrow("SHA256", Crypto),
    ExtDef::narrow("SHA512", Crypto),
    ExtDef::narrow("SHA3", Crypto),
    ExtDef::narrow("SM3", Crypto),
    ExtDef::narrow("SM4", Crypto),
    ExtDef::narrow("LSE", Atomic),
    ExtDef::narrow("LRCPC", Atomic),
    ExtDef::new("LRCPC2", Atomic),
    ExtDef::narrow("PAC", Security),
    ExtDef::narrow("BTI", Security),
    ExtDef::new("MTE", Security),
    ExtDef::narrow("RNG", Security),
    ExtDef::narrow("SB", Security),
    ExtDef::narrow("DPB", System),
    ExtDef::narrow("DPB2", System),
    ExtDef::narrow("WFxT", System),
    ExtDef::narrow("CRC32", Other),
    ExtDef::narrow("JSCVT", Other),
    ExtDef::narrow("FlagM", Other),
    ExtDef::narrow("FlagM2", Other),
    ExtDef::narrow("MOPS", Other),
    ExtDef::narrow("CSSC", Other),
    ExtDef::new("HBC", Other),
];

const fn b(name: &str) -> u64 {
    bit_of(EXTS, name)
}
const SVE_SETUP: u64 = b("sve-setup");
const SME_SETUP: u64 = b("sme-setup");
const NEON: u64 = b("NEON");
const SVE: u64 = b("SVE");
const SME: u64 = b("SME");
const DOTPROD: u64 = b("DOTPROD");
const FP16: u64 = b("FP16");
const BF16: u64 = b("BF16");
const I8MM: u64 = b("I8MM");
const RDM: u64 = b("RDM");
const FHM: u64 = b("FHM");
const FCMA: u64 = b("FCMA");
const FRINTTS: u64 = b("FRINTTS");
const AES: u64 = b("AES");
const PMULL: u64 = b("PMULL");
const SHA1: u64 = b("SHA1");
const SHA256: u64 = b("SHA256");
const SHA512: u64 = b("SHA512");
const SHA3: u64 = b("SHA3");
const SM3: u64 = b("SM3");
const SM4: u64 = b("SM4");
const LSE: u64 = b("LSE");
const LRCPC: u64 = b("LRCPC");
const LRCPC2: u64 = b("LRCPC2");
const PAC: u64 = b("PAC");
const BTI: u64 = b("BTI");
const MTE: u64 = b("MTE");
const RNG: u64 = b("RNG");
const SB: u64 = b("SB");
const DPB: u64 = b("DPB");
const DPB2: u64 = b("DPB2");
const WFXT: u64 = b("WFxT");
const CRC32: u64 = b("CRC32");
const JSCVT: u64 = b("JSCVT");
const FLAGM: u64 = b("FlagM");
const FLAGM2: u64 = b("FlagM2");
const MOPS: u64 = b("MOPS");
const CSSC: u64 = b("CSSC");
const HBC: u64 = b("HBC");

pub(super) fn scan(code: &[u8], _isa: Isa, _e: Endianness, t: &mut Tally) {
    for c in code.chunks_exact(4) {
        let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        match classify(w) {
            Some(m) => t.insn(m),
            None => t.invalid(),
        }
    }
}

/// Allocation bitmap, bit `(w >> 21) << 6 | (w >> 10) & 63`.
static VALID: &[u8; 16384] = include_bytes!("aarch64_valid.bin");

/// Evidence bits of one instruction word; `None` if the word is unallocated.
pub(crate) fn classify(w: u32) -> Option<u64> {
    let key = ((w >> 21) << 6 | (w >> 10) & 63) as usize;
    if VALID[key >> 3] >> (key & 7) & 1 == 0 {
        return None;
    }
    let op0 = (w >> 25) & 0xF;
    Some(match op0 {
        0b0000 => {
            if w >> 31 == 1 {
                SME
            } else {
                return None; // UDF / reserved
            }
        }
        0b0001 | 0b0011 => return None,
        0b0010 => sve_space(w),
        0b1000 | 0b1001 => dp_imm(w),
        0b1010 | 0b1011 => branch_sys(w),
        0b0101 | 0b1101 => dp_reg(w),
        0b0111 | 0b1111 => simd_fp(w),
        _ => ldst(w), // x1x0
    })
}

fn sve_space(w: u32) -> u64 {
    // SME instructions that live in the SVE encoding space.
    if w & 0xFFFF_F800 == 0x04BF_5800 // RDSVL
        || w & 0xFFE0_F800 == 0x0420_5800 // ADDSVL
        || w & 0xFFE0_F800 == 0x0460_5800
    // ADDSPL
    {
        return SME | SME_SETUP;
    }
    let setup = w & 0xFF3E_FC10 == 0x2518_E000 // PTRUE / PTRUES
        || w & 0xFF20_E000 == 0x2520_0000 // WHILE* (scalar)
        || (w & 0xFF20_F800 == 0x0420_E000 && (w >> 20 & 1 == 1 || w >> 10 & 1 == 0)) // CNT* / INC* / DEC*
        || w & 0xFFFF_F800 == 0x04BF_5000 // RDVL
        || w & 0xFFE0_F800 == 0x0420_5000 // ADDVL
        || w & 0xFFE0_F800 == 0x0460_5000; // ADDPL
    if setup {
        SVE | SVE_SETUP
    } else {
        SVE
    }
}

fn dp_imm(w: u32) -> u64 {
    if w & 0xBFC0_C000 == 0x9180_0000 {
        return MTE; // ADDG / SUBG
    }
    if w & 0x7FF0_0000 == 0x11C0_0000 {
        return CSSC; // SMAX/UMAX/SMIN/UMIN (immediate)
    }
    0
}

fn branch_sys(w: u32) -> u64 {
    if w & 0xFFFF_F01F == 0xD503_201F {
        // HINT space.
        return match (w >> 5) & 0x7F {
            7 | 8 | 10 | 12 | 14 | 24..=31 => PAC, // XPACLRI, PAC*/AUT* 1716/Z/SP
            32 | 34 | 36 | 38 => BTI,
            _ => 0,
        };
    }
    match w {
        0xD503_30FF => return SB,
        0xD500_401F => return FLAGM,           // CFINV
        0xD500_403F | 0xD500_405F => return FLAGM2, // XAFLAG, AXFLAG
        _ => {}
    }
    if w & 0xFFFF_FFC0 == 0xD53B_2400 {
        return RNG; // MRS Xt, RNDR / RNDRRS
    }
    if w & 0xFFFF_FFE0 == 0xD50B_7C20 {
        return DPB; // DC CVAP
    }
    if w & 0xFFFF_FFE0 == 0xD50B_7D20 {
        return DPB2; // DC CVADP
    }
    if w & 0xFFFF_FFC0 == 0xD503_1000 {
        return WFXT; // WFET / WFIT
    }
    if w & 0xFFFF_F0FF == 0xD503_407F && matches!((w >> 8) & 0xF, 2..=7) {
        return SME | SME_SETUP; // MSR SVCRSM/SVCRZA/SVCRSMZA (SMSTART / SMSTOP)
    }
    if w & 0xFE9F_F800 == 0xD61F_0800 {
        return PAC; // BRAA/BRAB/BLRAA/BLRAB/RETAA/RETAB/ERETAA/ERETAB (+Z)
    }
    if w & 0xFF00_0010 == 0x5400_0010 {
        return HBC; // BC.cond
    }
    0
}

fn dp_reg(w: u32) -> u64 {
    // CRC32{B,H,W,X}, CRC32C{B,H,W,X}: the X forms need sf = 1, the others sf = 0.
    if w & 0x7FE0_E000 == 0x1AC0_4000 && (w >> 10 & 3 == 3) == (w >> 31 == 1) {
        return CRC32;
    }
    match w & 0xFFE0_FC00 {
        0x9AC0_1000 | 0x9AC0_1400 | 0x9AC0_0000 | 0xBAC0_0000 => return MTE, // IRG, GMI, SUBP, SUBPS
        0x9AC0_3000 => return PAC, // PACGA
        _ => {}
    }
    if w & 0xFFFF_C000 == 0xDAC1_0000 || w & 0xFFFF_FBE0 == 0xDAC1_43E0 {
        return PAC; // PACIA.. AUTDB, PACIZA.., XPACI / XPACD
    }
    if matches!(w & 0x7FFF_FC00, 0x5AC0_1800 | 0x5AC0_1C00 | 0x5AC0_2000) {
        return CSSC; // CTZ, CNT, ABS
    }
    if w & 0x7FE0_F000 == 0x1AC0_6000 {
        return CSSC; // SMAX/UMAX/SMIN/UMIN (register)
    }
    if w & 0xFFE0_7C10 == 0xBA00_0400 || w & 0xFFFF_BC1F == 0x3A00_080D {
        return FLAGM; // RMIF, SETF8/SETF16
    }
    0
}

fn ldst(w: u32) -> u64 {
    if w & 0x3FA0_7C00 == 0x08A0_7C00 {
        return LSE; // CAS*
    }
    if w & 0xBFA0_7C00 == 0x0820_7C00 && w & 0x0001_0001 == 0 {
        return LSE; // CASP* (even register pairs)
    }
    if w & 0x3F20_8C00 == 0x3820_0000 || w & 0x3F20_FC00 == 0x3820_8000 {
        return LSE; // LDADD/LDCLR/LDEOR/LDSET/LD{S,U}{MAX,MIN} (+ST aliases), SWP
    }
    if w & 0x3FFF_FC00 == 0x38BF_C000 {
        return LRCPC; // LDAPR{B,H}
    }
    if w & 0x3F20_0C00 == 0x1900_0000 && !matches!((w >> 30, w >> 22 & 3), (2, 3) | (3, 2) | (3, 3)) {
        return LRCPC2; // LDAPUR*/STLUR*
    }
    // CPYF*/CPY*/SET*/SETG* (SET*: option bits 15:14 = 11 unallocated)
    if w & 0xFB20_0C00 == 0x1900_0400 && !(w >> 22 & 3 == 3 && w >> 14 & 3 == 3) {
        return MOPS;
    }
    if w & 0xFF20_0000 == 0xD920_0000 {
        // STG/STZG/ST2G/STZ2G/LDG; STGM/STZGM/LDGM (op2 = 00, opc != 01) take no offset.
        let tag_multiple = w >> 10 & 3 == 0 && w >> 22 & 3 != 1;
        if !tag_multiple || w >> 12 & 0x1FF == 0 {
            return MTE;
        }
        return 0;
    }
    if matches!(w & 0xFFC0_0000, 0x6880_0000 | 0x6900_0000 | 0x6980_0000) {
        return MTE; // STGP
    }
    if w & 0xFF20_0400 == 0xF820_0400 {
        return PAC; // LDRAA / LDRAB
    }
    0
}

fn simd_fp(w: u32) -> u64 {
    let mut m = 0;
    if w & 0x9E00_0000 == 0x0E00_0000 {
        m |= NEON; // Advanced SIMD (vector), incl. AES
    }
    if w >> 24 == 0xCE {
        return m | ce_space(w);
    }
    if w & 0xFFFF_CC00 == 0x4E28_4800 {
        return m | AES; // AESE/AESD/AESMC/AESIMC
    }
    if w & 0xFFE0_8C00 == 0x5E00_0000 {
        return match (w >> 12) & 7 {
            0..=3 => SHA1,   // SHA1C/P/M/SU0
            4..=6 => SHA256, // SHA256H/H2/SU1
            _ => 0,
        };
    }
    match w & 0xFFFF_FC00 {
        0x5E28_0800 | 0x5E28_1800 => return SHA1, // SHA1H, SHA1SU1
        0x5E28_2800 => return SHA256,             // SHA256SU0
        0x1E63_4000 => return BF16,               // BFCVT
        0x1E7E_0000 => return JSCVT,              // FJCVTZS
        _ => {}
    }
    if w & 0xBFE0_FC00 == 0x0EE0_E000 {
        return m | PMULL; // PMULL{2} .1Q
    }
    if w & 0x9FE0_FC00 == 0x0E80_9400 || w & 0x9FC0_F400 == 0x0F80_E000 {
        return m | DOTPROD; // SDOT/UDOT (vector, by element)
    }
    // Half-precision arithmetic (scalar 2-source, fused multiply-add, vector three-same).
    if (w & 0xFFE0_0C00 == 0x1EE0_0800 && (w >> 12) & 0xF <= 8)
        || w & 0xFFC0_0000 == 0x1FC0_0000
        || (w & 0x9F60_C400 == 0x0E40_0400 && FP16_3SAME >> ((w >> 29 & 1) << 4 | (w >> 23 & 1) << 3 | (w >> 11 & 7)) & 1 != 0)
    {
        return m | FP16;
    }
    if w & 0xBFE0_FC00 == 0x2E40_FC00 // BFDOT (vector)
        || w & 0xFFE0_FC00 == 0x6E40_EC00 // BFMMLA
        || w & 0xBFE0_FC00 == 0x2EC0_FC00 // BFMLALB/T
        || w & 0xBFFF_FC00 == 0x0EA1_6800 // BFCVTN{2}
        || w & 0xBFC0_F400 == 0x0F40_F000 // BFDOT (element)
        || w & 0xBFC0_F400 == 0x0FC0_F000
    // BFMLALB/T (element)
    {
        return m | BF16;
    }
    if matches!(w & 0xFFE0_FC00, 0x4E80_A400 | 0x6E80_A400 | 0x4E80_AC00) // SMMLA/UMMLA/USMMLA
        || w & 0xBFE0_FC00 == 0x0E80_9C00 // USDOT (vector)
        || matches!(w & 0xBFC0_F400, 0x0F80_F000 | 0x0F00_F000)
    // USDOT/SUDOT (element)
    {
        return m | I8MM;
    }
    let size = w >> 22 & 3;
    let q = w >> 30 & 1;
    if (w & 0xBF20_F400 == 0x2E00_8400 // SQRDMLAH/SQRDMLSH (vector)
        || w & 0xFF20_F400 == 0x7E00_8400 // (scalar)
        || w & 0xBF00_D400 == 0x2F00_D000 // (vector, element)
        || w & 0xFF00_D400 == 0x7F00_D000) // (scalar, element)
        && (size == 1 || size == 2)
    {
        return m | RDM;
    }
    if w & 0xBF60_FC00 == 0x0E20_EC00 // FMLAL/FMLSL (vector)
        || w & 0xBF60_FC00 == 0x2E20_CC00 // FMLAL2/FMLSL2 (vector)
        || w & 0xBFC0_B400 == 0x0F80_0000 // FMLAL/FMLSL (element)
        || w & 0xBFC0_B400 == 0x2F80_8000
    // FMLAL2/FMLSL2 (element)
    {
        return m | FHM;
    }
    let vector_sizes = size != 0 && !(size == 3 && q == 0);
    if ((w & 0xBF20_E400 == 0x2E00_C400 || w & 0xBF20_EC00 == 0x2E00_E400) && vector_sizes) // FCMLA, FCADD
        || (w & 0xBF00_9400 == 0x2F00_1000 && (size == 1 || (size == 2 && q == 1)))
    // FCMLA (element)
    {
        return m | FCMA;
    }
    if w & 0xFFBE_7C00 == 0x1E28_4000 || (w & 0x9FBF_EC00 == 0x0E21_E800 && !(w >> 22 & 1 == 1 && q == 0)) {
        return m | FRINTTS; // FRINT32Z/32X/64Z/64X (scalar, vector)
    }
    m
}

/// Allocated half-precision three-same opcodes: bit `U << 4 | a << 3 | opcode`
/// (U = bit 29, a = bit 23, opcode = bits 13:11).
const FP16_3SAME: u32 = {
    // U=0 a=0: FMAXNM FMLA FADD FMULX FCMEQ - FMAX FRECPS
    // U=0 a=1: FMINNM FMLS FSUB - - - FMIN FRSQRTS
    // U=1 a=0: FMAXNMP - FADDP FMUL FCMGE FACGE FMAXP FDIV
    // U=1 a=1: FMINNMP - FABD - FCMGT FACGT FMINP -
    0b1101_1111 | 0b1100_0111 << 8 | 0b1111_1101 << 16 | 0b0111_0101 << 24
};

/// Cryptographic three/four-register space `0xCExxxxxx`.
fn ce_space(w: u32) -> u64 {
    if w & 0xFFE0_F000 == 0xCE60_8000 {
        return if (w >> 10) & 3 == 3 { SHA3 } else { SHA512 }; // SHA512H/H2/SU1, RAX1
    }
    match w & 0xFFFF_FC00 {
        0xCEC0_8000 => return SHA512, // SHA512SU0
        0xCEC0_8400 => return SM4,    // SM4E
        _ => {}
    }
    if matches!(w & 0xFFE0_8000, 0xCE00_0000 | 0xCE20_0000) || w & 0xFFE0_0000 == 0xCE80_0000 {
        return SHA3; // EOR3, BCAX, XAR
    }
    if w & 0xFFE0_8000 == 0xCE40_0000 || w & 0xFFE0_C000 == 0xCE40_8000 || w & 0xFFE0_F800 == 0xCE60_C000 {
        return SM3; // SM3SS1, SM3TT*, SM3PARTW1/2
    }
    if w & 0xFFE0_FC00 == 0xCE60_C800 {
        return SM4; // SM4EKEY
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::test_util::{detect, le_words};

    #[test]
    fn anchors_are_hidden_entries() {
        assert_eq!(EXTS[SVE_SETUP_IDX].name, "sve-setup");
        assert_eq!(EXTS[SME_SETUP_IDX].name, "sme-setup");
        assert!(EXTS[SVE_SETUP_IDX].hidden && EXTS[SME_SETUP_IDX].hidden);
    }

    /// Encodings from `llvm-mc -triple=aarch64 -mattr=+all -show-encoding`.
    #[rustfmt::skip]
    const WORDS: &[(u32, u64)] = &[
        (0x88A07C41, LSE),     // cas w0, w1, [x2]
        (0xC8E0FC41, LSE),     // casal x0, x1, [x2]
        (0x08A07C41, LSE),     // casb
        (0x4860FC82, LSE),     // caspal x0, x1, x2, x3, [x4]
        (0x08207C82, LSE),     // casp w0, w1, w2, w3, [x4]
        (0xB8200041, LSE),     // ldadd w0, w1, [x2]
        (0xF8E00041, LSE),     // ldaddal
        (0x38201041, LSE),     // ldclrb
        (0x78202041, LSE),     // ldeorh
        (0xF8203041, LSE),     // ldset
        (0xB8204041, LSE),     // ldsmax
        (0xF8207041, LSE),     // ldumin
        (0xB8208041, LSE),     // swp
        (0xF8E08041, LSE),     // swpal
        (0xB820005F, LSE),     // stadd w0, [x2]
        (0xB8BFC020, LRCPC),   // ldapr w0, [x1]
        (0x38BFC020, LRCPC),   // ldaprb
        (0x99404020, LRCPC2),  // ldapur w0, [x1, #4]
        (0x195FF020, LRCPC2),  // ldapurb w0, [x1, #-1]
        (0xD9008020, LRCPC2),  // stlur x0, [x1, #8]
        (0x1AC24020, CRC32),   // crc32b w0, w1, w2
        (0x9AC25C20, CRC32),   // crc32cx w0, w1, x2
        (0x4E284820, NEON | AES),  // aese v0.16b, v1.16b
        (0x4E287820, NEON | AES),  // aesimc
        (0x5E020020, SHA1),    // sha1c q0, s1, v2.4s
        (0x5E023020, SHA1),    // sha1su0
        (0x5E024020, SHA256),  // sha256h
        (0x5E026020, SHA256),  // sha256su1
        (0x5E280820, SHA1),    // sha1h
        (0x5E281820, SHA1),    // sha1su1
        (0x5E282820, SHA256),  // sha256su0
        (0xCE628020, SHA512),  // sha512h
        (0xCEC08020, SHA512),  // sha512su0
        (0xCE628820, SHA512),  // sha512su1
        (0xCE020C20, SHA3),    // eor3
        (0xCE220C20, SHA3),    // bcax
        (0xCE820C20, SHA3),    // xar
        (0xCE628C20, SHA3),    // rax1
        (0xCE420C20, SM3),     // sm3ss1
        (0xCE429020, SM3),     // sm3tt1a
        (0xCE62C020, SM3),     // sm3partw1
        (0xCEC08420, SM4),     // sm4e
        (0xCE62C820, SM4),     // sm4ekey
        (0x0EE2E020, NEON | PMULL), // pmull v0.1q, v1.1d, v2.1d
        (0x4EE2E020, NEON | PMULL), // pmull2
        (0x0E22E020, NEON),    // pmull v0.8h, v1.8b, v2.8b (base)
        (0x4E829420, NEON | DOTPROD), // sdot v0.4s, v1.16b, v2.16b
        (0x2E829420, NEON | DOTPROD), // udot v0.2s
        (0x4FA2E020, NEON | DOTPROD), // sdot (element)
        (0x6FA2E820, NEON | DOTPROD), // udot (element)
        (0x1EE22820, FP16),    // fadd h0, h1, h2
        (0x1EE20820, FP16),    // fmul h0, h1, h2
        (0x4E421420, NEON | FP16), // fadd v0.8h
        (0x4E420C20, NEON | FP16), // fmla v0.8h
        (0x1FC20C20, FP16),    // fmadd h0, h1, h2, h3
        (0x1EE24020, 0),       // fcvt s0, h1 (base ARMv8)
        (0x1E23C020, 0),       // fcvt h0, s1 (base ARMv8)
        (0x6E42FC20, NEON | BF16), // bfdot
        (0x6E42EC20, NEON | BF16), // bfmmla
        (0x2EC2FC20, NEON | BF16), // bfmlalb
        (0x1E634020, BF16),    // bfcvt h0, s1
        (0x0EA16820, NEON | BF16), // bfcvtn
        (0x4E82A420, NEON | I8MM), // smmla
        (0x6E82A420, NEON | I8MM), // ummla
        (0x4E82AC20, NEON | I8MM), // usmmla
        (0x4E829C20, NEON | I8MM), // usdot (vector)
        (0x4F82F020, NEON | I8MM), // usdot (element)
        (0x4F02F020, NEON | I8MM), // sudot (element)
        (0xD503233F, PAC),     // paciasp
        (0xD503237F, PAC),     // pacibsp
        (0xD50323BF, PAC),     // autiasp
        (0xD50323FF, PAC),     // autibsp
        (0xD503231F, PAC),     // paciaz
        (0xD65F0BFF, PAC),     // retaa
        (0xD65F0FFF, PAC),     // retab
        (0xD71F0801, PAC),     // braa x0, x1
        (0xD61F081F, PAC),     // braaz x0
        (0xD73F0801, PAC),     // blraa x0, x1
        (0xD63F081F, PAC),     // blraaz x0
        (0xDAC10020, PAC),     // pacia x0, x1
        (0xDAC11820, PAC),     // autda x0, x1
        (0xDAC127E0, PAC),     // pacizb x0
        (0xDAC143E0, PAC),     // xpaci x0
        (0xD50320FF, PAC),     // xpaclri
        (0xF8200420, PAC),     // ldraa x0, [x1]
        (0xF8A01C20, PAC),     // ldrab x0, [x1, #8]!
        (0xD65F03C0, 0),       // ret
        (0xD61F0000, 0),       // br x0
        (0xD503201F, 0),       // nop
        (0xD503241F, BTI),     // bti
        (0xD503245F, BTI),     // bti c
        (0xD503249F, BTI),     // bti j
        (0xD50324DF, BTI),     // bti jc
        (0x9ADF1020, MTE),     // irg x0, x1
        (0x9AC21420, MTE),     // gmi x0, x1, x2
        (0x91810420, MTE),     // addg x0, x1, #16, #1
        (0xD1810420, MTE),     // subg
        (0xD9200820, MTE),     // stg x0, [x1]
        (0xD9601C20, MTE),     // stzg x0, [x1, #16]!
        (0xD9A01420, MTE),     // st2g x0, [x1], #16
        (0xD9600020, MTE),     // ldg x0, [x1]
        (0x69000440, MTE),     // stgp x0, x1, [x2]
        (0x9AC20020, MTE),     // subp x0, x1, x2
        (0x1E7E0020, JSCVT),   // fjcvtzs w0, d1
        (0x1E284020, FRINTTS), // frint32z s0, s1
        (0x1E69C020, FRINTTS), // frint64x d0, d1
        (0x6E21E820, NEON | FRINTTS), // frint32x v0.4s
        (0x4E61F820, NEON | FRINTTS), // frint64z v0.2d
        (0x6E828420, NEON | RDM), // sqrdmlah v0.4s
        (0x6E428C20, NEON | RDM), // sqrdmlsh v0.8h
        (0x7E828420, RDM),     // sqrdmlah s0, s1, s2
        (0x6FA2D020, NEON | RDM), // sqrdmlah (element)
        (0x0E22EC20, NEON | FHM), // fmlal v0.2s
        (0x4EA2EC20, NEON | FHM), // fmlsl v0.4s
        (0x2E22CC20, NEON | FHM), // fmlal2
        (0x4FB20020, NEON | FHM), // fmlal (element)
        (0x6E82CC20, NEON | FCMA), // fcmla
        (0x6E82E420, NEON | FCMA), // fcadd
        (0x6F823820, NEON | FCMA), // fcmla (element)
        (0xD50330FF, SB),      // sb
        (0xD53B2400, RNG),     // mrs x0, rndr
        (0xD53B2421, RNG),     // mrs x1, rndrrs
        (0xD50B7C20, DPB),     // dc cvap, x0
        (0xD50B7D21, DPB2),    // dc cvadp, x1
        (0xD500401F, FLAGM),   // cfinv
        (0xBA018402, FLAGM),   // rmif x0, #3, #2
        (0x3A00080D, FLAGM),   // setf8 w0
        (0xD500405F, FLAGM2),  // axflag
        (0xD500403F, FLAGM2),  // xaflag
        (0xD5031000, WFXT),    // wfet x0
        (0xD5031021, WFXT),    // wfit x1
        (0xD503477F, SME | SME_SETUP), // smstart
        (0xD503467F, SME | SME_SETUP), // smstop
        (0xD503437F, SME | SME_SETUP), // smstart sm
        (0xD503447F, SME | SME_SETUP), // smstop za
        (0x04BF5820, SME | SME_SETUP), // rdsvl x0, #1
        (0x043F583F, SME | SME_SETUP), // addsvl sp, sp, #1
        (0x80812000, SME),     // fmopa za0.s, p0/m, p1/m, z0.s, z1.s
        (0xC00800FF, SME),     // zero {za}
        (0xE09F0000, SME),     // ld1w {za0h.s[w12, 0]}, p0/z, [x0]
        (0x2518E3E0, SVE | SVE_SETUP), // ptrue p0.b
        (0x2598E101, SVE | SVE_SETUP), // ptrue p1.s, vl8
        (0x25D9E3E2, SVE | SVE_SETUP), // ptrues p2.d
        (0x25A11C00, SVE | SVE_SETUP), // whilelo p0.s, x0, x1
        (0x25230441, SVE | SVE_SETUP), // whilelt p1.b, w2, w3
        (0x0420E3E0, SVE | SVE_SETUP), // cntb x0
        (0x04E1E3E2, SVE | SVE_SETUP), // cntd x2, all, mul #2
        (0x04B0E3E0, SVE | SVE_SETUP), // incw x0
        (0x0430E7E0, SVE | SVE_SETUP), // decb x0
        (0x04BF5020, SVE | SVE_SETUP), // rdvl x0, #1
        (0x043F57DF, SVE | SVE_SETUP), // addvl sp, sp, #-2
        (0x04615060, SVE | SVE_SETUP), // addpl x0, x1, #3
        (0xA5414000, SVE),     // ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
        (0xE5414000, SVE),     // st1w
        (0x65A20020, SVE),     // fmla z0.s, p0/m, z1.s, z2.s
        (0x04A20020, SVE),     // add z0.s, z1.s, z2.s
        (0x19010440, MOPS),    // cpyfp [x0]!, [x1]!, x2!
        (0x19410440, MOPS),    // cpyfm
        (0x1D010440, MOPS),    // cpyp
        (0x19C20420, MOPS),    // setp [x0]!, x1!, x2
        (0x1DC20420, MOPS),    // setgp
        (0xDAC02020, CSSC),    // abs x0, x1
        (0x5AC01C20, CSSC),    // cnt w0, w1
        (0xDAC01820, CSSC),    // ctz x0, x1
        (0x9AC26020, CSSC),    // smax x0, x1, x2
        (0x1AC26C20, CSSC),    // umin w0, w1, w2
        (0x91C00C20, CSSC),    // smax x0, x1, #3
        (0x11CC0C20, CSSC),    // umin w0, w1, #3
        (0x54000010, HBC),     // bc.eq
        (0x54000000, 0),       // b.eq
        (0x5AC01020, 0),       // clz w0, w1
        (0x91000420, 0),       // add x0, x1, #1
        (0xF9400020, 0),       // ldr x0, [x1]
        (0xA9BF7BFD, 0),       // stp x29, x30, [sp, #-16]!
        (0x4E208400, NEON),    // add v0.16b, v0.16b, v0.16b
        (0x1E222820, 0),       // fadd s0, s1, s2
        (0x3DC00020, 0),       // ldr q0, [x1]
    ];

    #[test]
    fn aarch64_encodings() {
        for &(w, want) in WORDS {
            assert_eq!(classify(w), Some(want), "{w:#010X}");
        }
    }

    #[test]
    fn unallocated_words() {
        for w in [0x0000_0000u32, 0x0000_1234, 0x0200_0000, 0x0600_0000, 0x7E00_0000 & !0x1E00_0000 | 0x0200_0000] {
            assert_eq!(classify(w), None, "{w:#010X}");
        }
    }

    fn function(body: &[u32]) -> Vec<u32> {
        // stp x29, x30, [sp,#-16]!; mov x29, sp; <body>; ldp x29, x30, [sp],#16; ret
        let mut v = vec![0xA9BF7BFD, 0x910003FD];
        v.extend_from_slice(body);
        v.extend_from_slice(&[0xA8C17BFD, 0xD65F03C0]);
        v
    }

    #[test]
    fn sve_needs_setup_instructions() {
        // SVE data processing without any predicate / vector length setup.
        let body: Vec<u32> = [0xA5414000u32, 0x65A20020, 0xE5414000, 0x91001000].repeat(8);
        let code = le_words(&function(&body).repeat(64));
        assert!(!detect(&code, Isa::AArch64, Endianness::Little).contains(&"SVE".to_string()));
        // With whilelo + incw it is SVE.
        let mut body = vec![0x25A11C00u32, 0x04B0E3E0];
        body.extend([0xA5414000u32, 0x65A20020, 0xE5414000].repeat(4));
        let code = le_words(&function(&body).repeat(64));
        assert_eq!(detect(&code, Isa::AArch64, Endianness::Little), vec!["SVE"]);
    }

    #[test]
    fn pac_bti_lse_program() {
        let f = [
            0xD503233F, // paciasp
            0xA9BF7BFD, // stp
            0xB8E00041, // ldaddal w0, w1, [x2]
            0x88A07C41, // cas
            0xA8C17BFD, // ldp
            0xD50323BF, // autiasp
            0xD65F03C0, // ret
            0xD503245F, // bti c
            0x91000420, // add
            0xD65F03C0, // ret
        ];
        let code = le_words(&f.repeat(200));
        assert_eq!(detect(&code, Isa::AArch64, Endianness::Little), vec!["LSE", "PAC", "BTI"]);
    }

    #[test]
    fn random_words_produce_nothing() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let words: Vec<u32> = (0..1 << 18)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u32
            })
            .collect();
        assert!(detect(&le_words(&words), Isa::AArch64, Endianness::Little).is_empty());
    }
}
