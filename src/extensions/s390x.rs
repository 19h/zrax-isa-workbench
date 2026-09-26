//! IBM z/Architecture (s390x, and s390 31-bit code) extension evidence.
//!
//! Instructions are 2, 4 or 6 bytes long, as given by the top two bits of the
//! first byte; they are swept linearly. Validity of the opcode (first byte,
//! plus the extended opcode in byte 1, the low nibble of byte 1, or byte 5,
//! depending on the format) comes from tables generated with LLVM's SystemZ
//! decoder (LLVM 23, `-mcpu=arch15`), sampling every opcode with zeroed and
//! random operand fields.
//!
//! * VX: vector facility instructions, opcodes `E7xx..xx` and `E6xx..xx`
//!   (vector enhancements, vector packed decimal, NNP assist).
//! * MSA: CPACF message-security-assist instructions (KM, KMC, KIMD, KLMD,
//!   KMAC, KMCTR, KMF, KMO, PCC, PCKMO, KMA, KDSA, PRNO).
//! * TX: transactional execution (TBEGIN, TBEGINC, TEND, TABORT, ETND).

use super::{bit_of, ExtDef, Tally};
use crate::types::{Endianness, ExtensionCategory::*, Isa};

pub(super) const EXTS: &[ExtDef] = &[
    ExtDef::new("VX", Simd),
    ExtDef::narrow("MSA", Crypto),
    ExtDef::narrow("TX", Transactional),
];

const VX: u64 = bit_of(EXTS, "VX");
const MSA: u64 = bit_of(EXTS, "MSA");
const TX: u64 = bit_of(EXTS, "TX");

/// Region starts are halfword aligned but may fall inside an instruction.
const WARMUP: usize = 4;

/// First bytes that start at least one valid instruction.
#[rustfmt::skip]
const FIRST: [u64; 4] = [0xFFFFFFFFFFFFFCF2, 0xFF03FF81FFF3FFFF, 0xEECEF3A00FFFFFFD, 0x3F0FFFEEFEFF11F5];

/// First bytes whose extended opcode is the low nibble of byte 1.
const NIB1_OPS: [u8; 8] = [0xA5, 0xA7, 0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCC];
/// Valid extended opcodes (bit per nibble value) of `NIB1_OPS`.
#[rustfmt::skip]
const NIB1: [u16; 8] = [0xFFFF, 0xFFFF, 0xFFF3, 0xFF33, 0xF9F4, 0xF5F5, 0x80F7, 0xAD40];

/// First bytes whose extended opcode is byte 1.
const BYTE1_OPS: [u8; 5] = [0x01, 0xB2, 0xB3, 0xB9, 0xE5];
#[rustfmt::skip]
const BYTE1: [[u64; 4]; 5] = [
    [0x0000000000007C96, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000], // 01
    [0x1FFFFFFE07172FF7, 0x33D0000865B5FFF3, 0x230700E03200C0F1, 0x9500313300000000], // B2
    [0xFFC0C070FFFFFFFF, 0x80FF02EF8B8B3FFF, 0x0770777777771030, 0xFEFEBFBFFFFF2772], // B3
    [0xDF03FFE3FFDFFFFF, 0x00FC33F30E0E0E4E, 0xE00FD406EFFFEFFF, 0x2FF53FFFAF00AF01], // B9
    [0x000000000000C407, 0x0000000333301110, 0x0000000000000000, 0x0000000000000000], // E5
];

/// First bytes whose extended opcode is byte 5.
const BYTE5_OPS: [u8; 6] = [0xE3, 0xE6, 0xE7, 0xEB, 0xEC, 0xED];
#[rustfmt::skip]
const BYTE5: [[u64; 4]; 6] = [
    [0xDF57C473FFFCFF5C, 0x1FEF03FFDFFB33C0, 0x00000000B3F3C3FF, 0x000000000000ADDD], // E3
    [0xB0B000000000CEFE, 0xFFBF0000FF774600, 0x0000000000000000, 0x0000000000000000], // E6
    [0xC5C900860C0C4FFF, 0xF5BDFFF7905D247F, 0xBB1FFEFEC0B0FFF7, 0xFBAFCDACCBF05CBF], // E7
    [0x4003B87B3050BC10, 0x4402440000F61030, 0x000000000D41C003, 0x05DC05DFF0000001], // EB
    [0x0000000000000000, 0xF0CF003022F24074, 0x0000000000000000, 0xF0C000300F000000], // EC
    [0xFFB0C070FFB7FFF0, 0x000000F003330303, 0x0000FF0000000000, 0x0000000000000000], // ED
];

fn has(bits: &[u64; 4], op: u8) -> bool {
    bits[usize::from(op >> 6)] >> (op & 63) & 1 != 0
}

/// Instruction length from the first byte.
fn ilen(b0: u8) -> usize {
    match b0 >> 6 {
        0 => 2,
        3 => 6,
        _ => 4,
    }
}

pub(super) fn scan(code: &[u8], _isa: Isa, _e: Endianness, t: &mut Tally) {
    let mut pos = 0usize;
    let mut n = 0usize;
    while pos + 2 <= code.len() {
        let len = ilen(code[pos]);
        if pos + len > code.len() {
            break;
        }
        let r = classify(&code[pos..pos + len]);
        if n >= WARMUP {
            match r {
                Some(m) => t.insn(m),
                None => t.invalid(),
            }
        }
        n += 1;
        pos += if r.is_some() { len } else { 2 };
    }
}

/// Evidence bits of the instruction `b` (exactly its length); `None` if invalid.
pub(crate) fn classify(b: &[u8]) -> Option<u64> {
    let b0 = b[0];
    if !has(&FIRST, b0) {
        return None;
    }
    if let Some(i) = NIB1_OPS.iter().position(|&x| x == b0) {
        return (NIB1[i] >> (b[1] & 0xF) & 1 != 0).then_some(0);
    }
    if let Some(i) = BYTE1_OPS.iter().position(|&x| x == b0) {
        let op = b[1];
        if !has(&BYTE1[i], op) {
            return None;
        }
        return Some(match (b0, op) {
            (0xB9, 0x1E | 0x28..=0x2F | 0x3A | 0x3C | 0x3E | 0x3F) => MSA,
            (0xE5, 0x60 | 0x61) | (0xB2, 0xF8 | 0xFC | 0xEC) => TX,
            _ => 0,
        });
    }
    if let Some(i) = BYTE5_OPS.iter().position(|&x| x == b0) {
        if !has(&BYTE5[i], b[5]) {
            return None;
        }
        return Some(if b0 == 0xE7 || b0 == 0xE6 { VX } else { 0 });
    }
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::test_util::detect;

    fn cls(hex: &str) -> Option<u64> {
        let b: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect();
        assert_eq!(b.len(), ilen(b[0]), "{hex}");
        classify(&b)
    }

    /// Encodings from `llvm-mc -triple=s390x -mcpu=z16 -show-encoding`.
    #[test]
    fn s390x_encodings() {
        assert_eq!(cls("e70010000006"), Some(VX)); // vl %v0, 0(%r1)
        assert_eq!(cls("e7001000000e"), Some(VX)); // vst %v0, 0(%r1)
        assert_eq!(cls("e71230000cf3"), Some(VX)); // vab %v17, %v18, %v3
        assert_eq!(cls("e70100000856"), Some(VX)); // vlr %v0, %v1
        assert_eq!(cls("e60010000006"), Some(VX)); // vlbr %v0, 0(%r1), 0
        assert_eq!(cls("b92e0024"), Some(MSA)); // km %r2, %r4
        assert_eq!(cls("b93e0002"), Some(MSA)); // kimd %r0, %r2
        assert_eq!(cls("e56000000000"), Some(TX)); // tbegin 0, 0
        assert_eq!(cls("b2f80000"), Some(TX)); // tend
        assert_eq!(cls("1812"), Some(0)); // lr %r1, %r2
        assert_eq!(cls("07fe"), Some(0)); // br %r14
        assert_eq!(cls("e31020000004"), Some(0)); // lg %r1, 0(%r2)
        assert_eq!(cls("eb6ff0300024"), Some(0)); // stmg %r6, %r15, 48(%r15)
        assert_eq!(cls("a7f40010"), Some(0)); // j +32
        assert_eq!(cls("c0e500000000"), Some(0)); // brasl %r14, .
        assert_eq!(cls("b9040012"), Some(0)); // lgr %r1, %r2
        assert_eq!(cls("0000"), None);
        assert_eq!(cls("e7000000000c"), None); // undefined vector opcode
        assert_eq!(cls("b9ff0000"), None);
    }

    #[test]
    fn vector_loop() {
        // vl; vl; vaf; vst; aghi %r1, 16; brctg %r3, -20
        let unit = "e70010000006e71010100006e70010000cf3e7001020000ea71b0010a737fff6";
        let b: Vec<u8> = (0..unit.len() / 2).map(|i| u8::from_str_radix(&unit[2 * i..2 * i + 2], 16).unwrap()).collect();
        let code = b.repeat(400);
        assert_eq!(detect(&code, Isa::S390x, Endianness::Big), vec!["VX"]);
    }
}
