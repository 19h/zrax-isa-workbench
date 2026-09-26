//! DEC Alpha extension evidence: BWX, CIX, MVI, FIX.
//!
//! Instructions are 32-bit little-endian words; the primary opcode is bits
//! 31:26. Encodings from the Alpha Architecture Handbook (v4):
//!
//! * BWX: LDBU (0x0A), LDWU (0x0C), STW (0x0D), STB (0x0E); SEXTB/SEXTW
//!   (0x1C, function 0x00/0x01).
//! * CIX: CTPOP, CTLZ, CTTZ (0x1C, functions 0x30, 0x32, 0x33).
//! * MVI: PERR, UNPKBW, UNPKBL, PKWB, PKLB, MIN/MAX{SB8,SW4,UB8,UW4}
//!   (0x1C, functions 0x31, 0x34-0x3F).
//! * FIX: FTOIT/FTOIS (0x1C, functions 0x70/0x78) and the whole ITFP opcode
//!   0x14 (ITOFS/ITOFF/ITOFT, SQRTF/SQRTG/SQRTS/SQRTT with qualifiers).
//!
//! Invalid for gating: reserved opcodes 0x01-0x07, the PALmode-only opcodes
//! 0x19/0x1B/0x1D/0x1E/0x1F, privileged CALL_PAL functions (including the
//! all-zero word), and undefined functions of opcodes 0x1C and 0x14.
//! None of these occur in the .text of 200 Debian alpha binaries (12M words).

use super::{bit_of, ExtDef, Tally};
use crate::types::{Endianness, ExtensionCategory::*, Isa};

pub(super) const EXTS: &[ExtDef] = &[
    ExtDef::narrow("BWX", Other),
    ExtDef::narrow("CIX", BitManip),
    ExtDef::narrow("MVI", Simd),
    ExtDef::narrow("FIX", FloatingPoint),
];

const BWX: u64 = bit_of(EXTS, "BWX");
const CIX: u64 = bit_of(EXTS, "CIX");
const MVI: u64 = bit_of(EXTS, "MVI");
const FIX: u64 = bit_of(EXTS, "FIX");

pub(super) fn scan(code: &[u8], _isa: Isa, _e: Endianness, t: &mut Tally) {
    for c in code.chunks_exact(4) {
        match classify(u32::from_le_bytes([c[0], c[1], c[2], c[3]])) {
            Some(m) => t.insn(m),
            None => t.invalid(),
        }
    }
}

/// Evidence bits of one instruction word; `None` if invalid in user code.
pub(crate) fn classify(w: u32) -> Option<u64> {
    let op = w >> 26;
    Some(match op {
        // CALL_PAL: only the unprivileged functions 0x80-0xBF.
        0x00 => {
            if (0x80..=0xBF).contains(&(w & 0x03FF_FFFF)) {
                0
            } else {
                return None;
            }
        }
        0x01..=0x07 | 0x19 | 0x1B | 0x1D..=0x1F => return None,
        0x0A | 0x0C | 0x0D | 0x0E => BWX,
        0x1C => match (w >> 5) & 0x7F {
            0x00 | 0x01 => BWX,
            0x30 | 0x32 | 0x33 => CIX,
            0x31 | 0x34..=0x3F => MVI,
            0x70 | 0x78 => FIX,
            _ => return None,
        },
        0x14 => {
            let f = (w >> 5) & 0x7FF;
            if matches!(f, 0x004 | 0x014 | 0x024) || matches!(f & 0x3F, 0x0A | 0x0B | 0x2A | 0x2B) {
                FIX
            } else {
                return None;
            }
        }
        _ => 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::test_util::{detect, le_words};

    /// op << 26 | ra << 21 | rb << 16 | ... (memory format: disp in 15:0;
    /// operate format: function in 11:5).
    const fn mem(op: u32, ra: u32, rb: u32, disp: u32) -> u32 {
        op << 26 | ra << 21 | rb << 16 | (disp & 0xFFFF)
    }
    const fn opr(op: u32, ra: u32, rb: u32, func: u32, rc: u32) -> u32 {
        op << 26 | ra << 21 | rb << 16 | func << 5 | rc
    }

    #[test]
    fn alpha_encodings() {
        assert_eq!(classify(mem(0x0A, 1, 2, 0)), Some(BWX)); // ldbu $1, 0($2)
        assert_eq!(classify(mem(0x0C, 1, 2, 2)), Some(BWX)); // ldwu $1, 2($2)
        assert_eq!(classify(mem(0x0D, 1, 2, 2)), Some(BWX)); // stw
        assert_eq!(classify(mem(0x0E, 1, 2, 1)), Some(BWX)); // stb
        assert_eq!(classify(opr(0x1C, 31, 1, 0x00, 2)), Some(BWX)); // sextb $1, $2
        assert_eq!(classify(opr(0x1C, 31, 1, 0x30, 2)), Some(CIX)); // ctpop $1, $2
        assert_eq!(classify(opr(0x1C, 31, 1, 0x32, 2)), Some(CIX)); // ctlz
        assert_eq!(classify(opr(0x1C, 1, 2, 0x3E, 3)), Some(MVI)); // maxsb8
        assert_eq!(classify(opr(0x1C, 1, 2, 0x31, 3)), Some(MVI)); // perr
        assert_eq!(classify(opr(0x1C, 1, 31, 0x70, 3)), Some(FIX)); // ftoit $f1, $3
        assert_eq!(classify(opr(0x14, 1, 31, 0x004, 3)), Some(FIX)); // itofs $1, $f3
        assert_eq!(classify(0x5000_0000 | 31 << 21 | 2 << 16 | 0x0AB << 5 | 3), Some(FIX)); // sqrtt $f2, $f3
        assert_eq!(classify(mem(0x29, 1, 30, 8)), Some(0)); // ldq $1, 8($30)
        assert_eq!(classify(opr(0x10, 1, 2, 0x20, 3)), Some(0)); // addq
        assert_eq!(classify(0x6BFA_8001), Some(0)); // ret
        assert_eq!(classify(0x0000_0083), Some(0)); // callsys
        assert_eq!(classify(0), None); // halt / zero fill
        assert_eq!(classify(mem(0x03, 1, 2, 0)), None);
        assert_eq!(classify(opr(0x1C, 1, 2, 0x10, 3)), None);
    }

    #[test]
    fn bwx_program() {
        // ldbu; addq; stb; lda; bne
        let f = [mem(0x0A, 1, 16, 0), opr(0x10, 1, 2, 0x20, 1), mem(0x0E, 1, 17, 0), mem(0x08, 16, 16, 1), 0xF61F_FFFB];
        assert_eq!(detect(&le_words(&f.repeat(500)), Isa::Alpha, Endianness::Little), vec!["BWX"]);
        let g = [mem(0x29, 1, 16, 0), opr(0x10, 1, 2, 0x20, 1), mem(0x2D, 1, 17, 0), mem(0x08, 16, 16, 8), 0xF61F_FFFB];
        assert!(detect(&le_words(&g.repeat(500)), Isa::Alpha, Endianness::Little).is_empty());
    }
}
