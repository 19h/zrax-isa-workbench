//! MIPS extension evidence: MSA (MIPS SIMD Architecture).
//!
//! Instructions are 32-bit words in the data byte order. MSA uses major
//! opcode `011110` (0x1E) exclusively (in pre-R5 cores it is unallocated) plus
//! the COP1 branches BZ.V/BNZ.V/BZ.df/BNZ.df. Which (bits 25:21, minor
//! opcode) combinations of major 0x1E are valid MSA instructions was
//! generated from LLVM's MIPS decoder (LLVM 23, mips32r5/r6 and mips64r5/r6
//! with `+msa`); the others are invalid.
//!
//! Every major opcode is valid in *some* MIPS revision, so data words cannot
//! be recognised reliably; MSA evidence is therefore made robust in two more
//! ways: an MSA instruction only counts inside a run (at least three MSA
//! instructions within nine words), and MSA is reported only together with
//! MSA vector loads/stores (LD.df / ST.df), which any use of MSA needs.

use super::{bit_of, ExtDef, Tally};
use crate::types::{Endianness, ExtensionCategory::*, Isa};

const MSA_MEM_IDX: usize = 0;

pub(super) const EXTS: &[ExtDef] =
    &[ExtDef::hidden("msa-mem"), ExtDef::new("MSA", Simd).anchored(MSA_MEM_IDX)];

const MSA_MEM: u64 = bit_of(EXTS, "msa-mem");
const MSA: u64 = bit_of(EXTS, "MSA");

/// Valid major-0x1E keys `(bits 25:21) << 6 | (bits 5:0)`.
#[rustfmt::skip]
const MSA_KEYS: [u64; 32] = [
    0x000000FF4E37E6C7, 0x000000FF4E3FE6C7, 0x000000FF5E3FE6C7, 0x000000FF5E3FE6C7,
    0x000000FF5E376647, 0x000000FF5E3F6647, 0x000000FF5E3F6647, 0x000000FF1E3F6647,
    0x000000FF1E37E6C7, 0x000000FF1E3FE6C7, 0x000000FF1E3FE6C7, 0x000000FF1E3FE6C7,
    0x000000FF1413E6C7, 0x000000FF141BE6C7, 0x000000FF0C1BE6C7, 0x000000FF0C1BE6C7,
    0x000000FF0C17E2C7, 0x000000FF0C3FE2C7, 0x000000FF143FE2C7, 0x000000FF143FE2C7,
    0x000000FF1C17E2C7, 0x000000FF1C3FE2C7, 0x000000FF143FE2C7, 0x000000FF143FE2C7,
    0x000000FF5C156281, 0x000000FF5C356281, 0x000000FF1C356281, 0x000000FF1C356281,
    0x000000FF1C156201, 0x000000FF1C356201, 0x000000FF0C356201, 0x000000FF0C356201,
];

/// Window (in words) in which three MSA instructions must fall to count.
const RUN: u32 = 9;

pub(super) fn scan(code: &[u8], _isa: Isa, e: Endianness, t: &mut Tally) {
    let be = e == Endianness::Big;
    // Bit i set: the word i positions back was an MSA instruction.
    let mut recent = 0u32;
    for c in code.chunks_exact(4) {
        let a = [c[0], c[1], c[2], c[3]];
        let w = if be { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) };
        let r = classify(w);
        let is_msa = matches!(r, Some(m) if m & MSA != 0);
        let in_run = is_msa && (recent & ((1 << (RUN - 1)) - 1)).count_ones() >= 2;
        recent = (recent << 1) | u32::from(is_msa);
        match r {
            Some(m) if in_run || !is_msa => t.insn(m),
            Some(_) => t.insn(0),
            None => t.invalid(),
        }
    }
}

/// Evidence bits of one word; `None` if certainly invalid.
pub(crate) fn classify(w: u32) -> Option<u64> {
    let major = w >> 26;
    match major {
        0x1E => {
            let key = (((w >> 21) & 0x1F) << 6 | (w & 0x3F)) as usize;
            if MSA_KEYS[key / 64] >> (key % 64) & 1 == 0 {
                return None;
            }
            Some(if (0x20..=0x27).contains(&(w & 0x3F)) { MSA | MSA_MEM } else { MSA })
        }
        // COP1: BZ.V, BNZ.V, BZ.df, BNZ.df.
        0x11 if matches!((w >> 21) & 0x1F, 11 | 15 | 24..=31) => Some(MSA),
        // SPECIAL: functs reserved in every revision; three-register ALU
        // operations with a non-zero shift amount.
        0x00 => {
            let funct = w & 0x3F;
            if matches!(funct, 40 | 41 | 57 | 61) || (matches!(funct, 32..=39 | 42..=47) && (w >> 6) & 0x1F != 0) {
                None
            } else {
                Some(0)
            }
        }
        _ => Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::test_util::{be_words, detect, le_words};

    /// Encodings from `llvm-mc -triple=mips64el -mattr=+msa,+mips64r6 -show-encoding`.
    #[rustfmt::skip]
    const WORDS: &[(u32, Option<u64>)] = &[
        (0x78042022, Some(MSA | MSA_MEM)), // ld.w $w0, 16($4)
        (0x78002826, Some(MSA | MSA_MEM)), // st.w $w0, 0($5)
        (0x7842080E, Some(MSA)),       // addv.w $w0, $w1, $w2
        (0x7902081B, Some(MSA)),       // fmadd.w $w0, $w1, $w2
        (0x7B02201E, Some(MSA)),       // fill.w $w0, $4
        (0x78710819, Some(MSA)),       // splati.w $w0, $w1[1]
        (0x7B402807, Some(MSA)),       // ldi.w $w0, 5
        (0x45600002, Some(MSA)),       // bz.v $w0, 8
        (0x47C10002, Some(MSA)),       // bnz.w $w1, 8
        (0x78B10119, Some(MSA)),       // copy_s.w $4, $w0[1]
        (0x7802081E, Some(MSA)),       // and.v $w0, $w1, $w2
        (0x00851021, Some(0)),         // addu $2, $4, $5
        (0x8C820000, Some(0)),         // lw $2, 0($4)
        (0x03E00009, Some(0)),         // jr $ra (R6: jalr $zero, $ra)
        (0x7800000C, None),            // major 0x1E, undefined minor
        (0x00851061, None),            // addu with shamt 1
    ];

    #[test]
    fn mips_encodings() {
        for &(w, want) in WORDS {
            assert_eq!(classify(w), want, "{w:#010X}");
        }
    }

    #[test]
    fn msa_loop_and_isolated_words() {
        // ld.w; addv.w; fmadd.w; st.w; addiu; bne
        let f = [0x78042022u32, 0x7842080E, 0x7902081B, 0x78002826, 0x24840010, 0x1485FFFA];
        let code = le_words(&f.repeat(500));
        assert_eq!(detect(&code, Isa::Mips, Endianness::Little), vec!["MSA"]);
        let code = be_words(&f.repeat(500));
        assert_eq!(detect(&code, Isa::Mips, Endianness::Big), vec!["MSA"]);
        // The same MSA words scattered among scalar code do not count.
        let mut g = Vec::new();
        for _ in 0..300 {
            g.extend([0x78042022u32, 0x24840010, 0x00851021, 0x8C820000, 0x00851021, 0x8C820000, 0x24840010, 0x00851021, 0x8C820000, 0x24840010, 0x7902081B]);
        }
        assert!(detect(&le_words(&g), Isa::Mips, Endianness::Little).is_empty());
    }
}
