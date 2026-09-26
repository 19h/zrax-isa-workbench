//! 32-bit ARM (A32 and T32/Thumb) extension evidence.
//!
//! Thumb and Thumb-2 are instruction set *states*, not extensions, and are
//! not reported. The instruction set of each code region is decided from
//! the code itself: A32 code has the condition field `1110` (always) in the
//! large majority of words, which neither Thumb code nor data has; the byte
//! order of A32 words is chosen the same way, the byte order of Thumb
//! halfwords by counting PUSH {.., lr} / POP {.., pc} / BX LR.
//!
//! * VFP: coprocessor 10/11 data processing, register transfers and
//!   loads/stores (A32 `cond 1110 .... 101x`, `cond 110x .... 101x`; T32
//!   `EExx/FExx`, `ECxx/EDxx` with coprocessor 10/11).
//! * NEON: A32 `F2xx/F3xx` data processing and `F4xx` (bit 20 clear)
//!   element/structure loads/stores; T32 `EFxx/FFxx` and `F9xx`.
//! * ARMv8 AArch32 CRC32, AES, SHA1, SHA256, PMULL (VMULL.P64); SDIV/UDIV.
//!
//! Literal pools sit between functions in ARM code. Words loaded by
//! PC-relative loads (LDR/LDRD/VLDR literal, in both states) are marked as
//! data when the load is decoded and skipped when the sweep reaches them.
//! A32 regions are further gated per chunk of words: a chunk in which fewer
//! than half of the words are unconditional-or-always is not code and is
//! discarded. Thumb has no such redundancy; there, 32-bit words with an
//! all-ones halfword (small negative literals) and Advanced SIMD candidates
//! whose second halfword is below 0x100 (small positive literals such as
//! `0x0000EFxx`) are treated as data. In both states a VFP or NEON
//! instruction only counts if another one of the same kind was seen within
//! the previous `CLUSTER` instructions: real FP/SIMD code comes in runs.

use super::{bit_of, ExtDef, Tally};
use crate::types::{Endianness, ExtensionCategory::*, Isa};

pub(super) const EXTS: &[ExtDef] = &[
    ExtDef::new("VFP", FloatingPoint),
    ExtDef::new("NEON", Simd),
    ExtDef::narrow("CRC32", Other),
    ExtDef::narrow("AES", Crypto),
    ExtDef::narrow("SHA1", Crypto),
    ExtDef::narrow("SHA256", Crypto),
    ExtDef::narrow("PMULL", Crypto),
    ExtDef::narrow("IDIV", Other),
];

const fn b(name: &str) -> u64 {
    bit_of(EXTS, name)
}
const VFP: u64 = b("VFP");
const NEON: u64 = b("NEON");
const CRC32: u64 = b("CRC32");
const AES: u64 = b("AES");
const SHA1: u64 = b("SHA1");
const SHA256: u64 = b("SHA256");
const PMULL: u64 = b("PMULL");
const IDIV: u64 = b("IDIV");

/// Words per A32 gating chunk (also the tally block length).
pub(super) const CHUNK: usize = 32;
/// Maximum distance (in instructions) between two VFP/NEON hits that count.
const CLUSTER: usize = 16;
/// Classes that need a neighbour to count.
const CLUSTERED: u64 = VFP | NEON;

pub(super) fn scan(code: &[u8], _isa: Isa, endianness: Endianness, t: &mut Tally) {
    let words_le = cond_al_share(code, false);
    let words_be = cond_al_share(code, true);
    if words_le.max(words_be) >= 0.4 {
        scan_a32(code, words_be > words_le, t);
    } else {
        let be = thumb_is_big_endian(code, endianness);
        scan_t32(code, be, t);
    }
}

fn word(c: &[u8], be: bool) -> u32 {
    let a = [c[0], c[1], c[2], c[3]];
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

/// Share of words whose condition field is `1110`.
fn cond_al_share(code: &[u8], be: bool) -> f64 {
    let n = code.len() / 4;
    if n == 0 {
        return 0.0;
    }
    let al = code.chunks_exact(4).filter(|c| word(c, be) >> 28 == 0xE).count();
    al as f64 / n as f64
}

/// Byte order of Thumb halfwords: PUSH {.., lr}, POP {.., pc}, BX LR and
/// BL/BLX pairs are counted in both orders; the declared byte order is only
/// overridden by a clear majority (a region without calls or returns must
/// not be flipped by one stray byte pair).
fn thumb_is_big_endian(code: &[u8], endianness: Endianness) -> bool {
    let score = |be: bool| {
        let h: Vec<u16> = code
            .chunks_exact(2)
            .map(|c| if be { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) })
            .collect();
        let frames = h.iter().filter(|&&x| x & 0xFF00 == 0xB500 || x & 0xFF00 == 0xBD00 || x == 0x4770).count();
        let calls = h.windows(2).filter(|p| p[0] & 0xF800 == 0xF000 && p[1] & 0xC000 == 0xC000).count();
        frames + calls
    };
    let (le, be) = (score(false), score(true));
    if endianness == Endianness::Big {
        le <= 2 * be + 4
    } else {
        be > 2 * le + 4
    }
}

/// Keeps VFP/NEON hits only when they come in runs: a VFP instruction needs
/// another one within the previous `CLUSTER` instructions, a NEON
/// instruction two more within the previous `NEON_RUN` (Advanced SIMD code
/// is dense; Thumb literal data that happens to fall into the Advanced SIMD
/// space is not).
struct Cluster {
    last_vfp: usize,
    neon_hist: u32,
    prev_idx: usize,
}

/// Window for NEON runs (instructions before the current one).
const NEON_RUN: u32 = 8;

impl Cluster {
    fn new() -> Self {
        Self { last_vfp: usize::MAX, neon_hist: 0, prev_idx: 0 }
    }

    fn filter(&mut self, idx: usize, mask: u64) -> u64 {
        let mut out = mask & !CLUSTERED;
        if mask & VFP != 0 {
            if self.last_vfp != usize::MAX && idx - self.last_vfp <= CLUSTER {
                out |= VFP;
            }
            self.last_vfp = idx;
        }
        // Shift the NEON history by the instructions since the last call.
        let gap = idx.saturating_sub(self.prev_idx).min(32) as u32;
        self.neon_hist = if gap >= 32 { 0 } else { self.neon_hist << gap };
        self.prev_idx = idx;
        if mask & NEON != 0 {
            if (self.neon_hist & ((1 << NEON_RUN) - 1) & !1).count_ones() >= 2 {
                out |= NEON;
            }
            self.neon_hist |= 1;
        }
        out
    }
}

/// Halfword-granular set of literal-pool positions in a region.
struct Pool(Vec<u64>);

impl Pool {
    fn new(len: usize) -> Self {
        Self(vec![0; len / 128 + 1])
    }

    /// Mark `bytes` bytes at byte offset `at` (if inside the region).
    fn mark(&mut self, at: i64, bytes: usize) {
        for h in 0..bytes / 2 {
            let i = at + 2 * h as i64;
            if i >= 0 && ((i as usize) / 2) < self.0.len() * 64 {
                let k = i as usize / 2;
                self.0[k / 64] |= 1 << (k % 64);
            }
        }
    }

    fn has(&self, at: usize) -> bool {
        let k = at / 2;
        self.0.get(k / 64).map_or(false, |w| w >> (k % 64) & 1 != 0)
    }
}

/// Literal loaded by an A32 instruction at byte offset `pc`: (offset, bytes).
fn a32_literal(w: u32, pc: usize) -> Option<(i64, usize)> {
    if w >> 28 == 0xF {
        return None;
    }
    let up = w >> 23 & 1 == 1;
    let (off, bytes) = if w & 0x0F7F_0000 == 0x051F_0000 {
        (w & 0xFFF, 4) // LDR Rt, [PC, #+/-imm12]
    } else if w & 0x0F7F_00F0 == 0x014F_00D0 {
        ((w >> 4 & 0xF0) | (w & 0xF), 8) // LDRD Rt, Rt2, [PC, #+/-imm8]
    } else if w & 0x0F3F_0E00 == 0x0D1F_0A00 {
        ((w & 0xFF) * 4, if w >> 8 & 1 == 1 { 8 } else { 4 }) // VLDR
    } else {
        return None;
    };
    let base = (pc as i64 & !3) + 8;
    Some((if up { base + i64::from(off) } else { base - i64::from(off) }, bytes))
}

fn scan_a32(code: &[u8], be: bool, t: &mut Tally) {
    let mut cl = Cluster::new();
    let mut pool = Pool::new(code.len());
    let mut idx = 0usize;
    for (ci, chunk) in code.chunks(CHUNK * 4).enumerate() {
        let start = ci * CHUNK * 4;
        let words: Vec<(usize, u32)> = chunk
            .chunks_exact(4)
            .enumerate()
            .map(|(i, c)| (start + 4 * i, word(c, be)))
            .collect();
        for &(pc, w) in &words {
            if let Some((at, n)) = a32_literal(w, pc) {
                pool.mark(at, n);
            }
        }
        let insns: Vec<u32> = words.iter().filter(|(pc, _)| !pool.has(*pc)).map(|&(_, w)| w).collect();
        let plausible = insns.iter().filter(|&&w| w >> 28 >= 0xE).count();
        let is_code = plausible * 2 >= insns.len();
        for &w in &insns {
            let m = cl.filter(idx, classify_a32(w));
            idx += 1;
            if is_code {
                t.insn(m);
            } else {
                t.invalid();
            }
        }
        t.flush();
    }
}

/// Literal loaded by a T32 instruction at byte offset `pc`: (offset, bytes).
fn t32_literal(hw1: u16, hw2: Option<u16>, pc: usize) -> Option<(i64, usize)> {
    let base = ((pc as i64 + 4) & !3) as i64;
    let Some(hw2) = hw2 else {
        // LDR Rt, [PC, #imm8 * 4]
        return (hw1 & 0xF800 == 0x4800).then(|| (base + i64::from(hw1 & 0xFF) * 4, 4));
    };
    let up = hw1 >> 7 & 1 == 1;
    let (off, bytes) = match hw1 & 0xFF7F {
        0xF85F => (u32::from(hw2 & 0xFFF), 4),                    // LDR.W Rt, [PC, #+/-imm12]
        0xE95F => (u32::from(hw2 & 0xFF) * 4, 8),                 // LDRD Rt, Rt2, [PC, #+/-imm8*4]
        0xED1F if hw2 >> 9 & 7 == 5 => (u32::from(hw2 & 0xFF) * 4, if hw2 >> 8 & 1 == 1 { 8 } else { 4 }), // VLDR
        _ => return None,
    };
    Some((if up { base + i64::from(off) } else { base - i64::from(off) }, bytes))
}

fn scan_t32(code: &[u8], be: bool, t: &mut Tally) {
    let half = |i: usize| -> u16 {
        let a = [code[i], code[i + 1]];
        if be {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    };
    let mut cl = Cluster::new();
    let mut pool = Pool::new(code.len());
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos + 2 <= code.len() {
        if pool.has(pos) {
            pos += 2;
            continue;
        }
        let hw1 = half(pos);
        if matches!(hw1 >> 11, 0b11101 | 0b11110 | 0b11111) {
            if pos + 4 > code.len() {
                break;
            }
            let hw2 = half(pos + 2);
            if let Some((at, n)) = t32_literal(hw1, Some(hw2), pos) {
                pool.mark(at, n);
            }
            let t32 = u32::from(hw1) << 16 | u32::from(hw2);
            let m = classify_t32(t32);
            if hw1 == 0xFFFF || hw2 == 0xFFFF || (m & NEON != 0 && hw2 < 0x100) {
                // Literal data: small negative numbers (all-ones half) or
                // small positive ones read as Advanced SIMD with Vd = d0 and
                // opcode 0.
                t.invalid();
            } else {
                t.insn(cl.filter(idx, m));
            }
            pos += 4;
        } else {
            if let Some((at, n)) = t32_literal(hw1, None, pos) {
                pool.mark(at, n);
            }
            t.insn(0);
            pos += 2;
        }
        idx += 1;
    }
}

/// ARMv8 AArch32 crypto instructions (A32 Advanced SIMD encoding space).
fn crypto_a32(w: u32) -> u64 {
    if w & 0xFFBF_0F10 == 0xF3B0_0300 {
        return AES; // AESE/AESD/AESMC/AESIMC
    }
    match w & 0xFFBF_0FD0 {
        0xF3B9_02C0 | 0xF3BA_0380 => return SHA1, // SHA1H, SHA1SU1
        0xF3BA_03C0 => return SHA256,             // SHA256SU0
        _ => {}
    }
    match w & 0xFF80_0F50 {
        0xF200_0C40 => return SHA1, // SHA1C/P/M/SU0
        0xF300_0C40 if (w >> 20) & 3 != 3 => return SHA256, // SHA256H/H2/SU1
        _ => {}
    }
    if w & 0xFFB0_0F50 == 0xF2A0_0E00 {
        return PMULL; // VMULL.P64
    }
    0
}

/// Evidence bits of one A32 word.
pub(crate) fn classify_a32(w: u32) -> u64 {
    let cond = w >> 28;
    if cond == 0xF {
        if w & 0xFE00_0000 == 0xF200_0000 {
            return NEON | crypto_a32(w);
        }
        if w & 0xFF10_0000 == 0xF400_0000 {
            return NEON;
        }
        if w & 0x0F00_0E10 == 0x0E00_0A00 {
            return VFP; // ARMv8 VSEL/VMAXNM/VMINNM/VRINT*/VCVT{A,N,P,M}
        }
        return 0;
    }
    if w & 0x0F00_0E00 == 0x0E00_0A00 || w & 0x0E00_0E00 == 0x0C00_0A00 {
        return VFP; // cp10/cp11: data processing, transfers, loads/stores
    }
    if w & 0x0F90_0DF0 == 0x0100_0040 && (w >> 21) & 3 != 3 {
        return CRC32;
    }
    if matches!(w & 0x0FF0_F0F0, 0x0710_F010 | 0x0730_F010) {
        return IDIV; // SDIV, UDIV
    }
    0
}

/// Evidence bits of one 32-bit T32 instruction (`hw1 << 16 | hw2`).
pub(crate) fn classify_t32(t: u32) -> u64 {
    if t & 0xEF00_0000 == 0xEF00_0000 {
        // Advanced SIMD data processing: same fields as A32 with U moved to bit 28.
        let a32 = 0xF200_0000 | ((t >> 4) & 0x0100_0000) | (t & 0x00FF_FFFF);
        return NEON | crypto_a32(a32);
    }
    if t & 0xFF10_0000 == 0xF900_0000 {
        return NEON; // element/structure loads/stores
    }
    if t & 0xEF00_0E00 == 0xEE00_0A00 || t & 0xFE00_0E00 == 0xEC00_0A00 {
        return VFP;
    }
    if t & 0xFFE0_F0C0 == 0xFAC0_F080 && (t >> 4) & 3 != 3 {
        return CRC32;
    }
    if matches!(t & 0xFFF0_F0F0, 0xFB90_F0F0 | 0xFBB0_F0F0) {
        return IDIV;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::test_util::{be_words, detect, le_words};

    /// Encodings from `llvm-mc -triple=armv8a -mattr=+crypto,+crc,+neon,+vfp4,+hwdiv-arm`.
    #[rustfmt::skip]
    const A32: &[(u32, u64)] = &[
        (0xEE300A81, VFP), (0xEE310B02, VFP), (0xEE200A81, VFP), (0xEE100A90, VFP), // vadd.f32 vadd.f64 vmul vmov r0,s1
        (0xEE000A90, VFP), (0xEC510B12, VFP), (0xEEF1FA10, VFP), (0xED900B02, VFP), // vmov s1,r0 vmov r0,r1,d2 vmrs vldr
        (0xED810A00, VFP), (0xED2D8B04, VFP), (0xECBD8B04, VFP), (0xECB00B08, VFP), // vstr vpush vpop vldmia
        (0xEEBD0AC0, VFP), (0xEEB70A00, VFP), (0xEEA00A81, VFP), (0xEEB40A60, VFP), // vcvt vmov.f32 imm vfma vcmp
        (0xEEA00B10, VFP), (0xEE200B10, VFP),                                         // vdup.32, vmov.32 d0[1]
        (0xFE300A81, VFP), (0xFE800A81, VFP), (0xFEB80A60, VFP),                      // vselgt vmaxnm vrinta
        (0xF2220844, NEON), (0xF3020D54, NEON), (0xF4200A8D, NEON), (0xF401070F, NEON), // vadd.i32 vmul.f32 vld1 vst1
        (0xF3000150, NEON), (0xF2800050, NEON), (0xF2B20344, NEON),                   // veor vmov.i32 vext
        (0xE1010042, CRC32), (0xE1410242, CRC32),                                     // crc32b crc32cw
        (0xF3B00302, NEON | AES), (0xF3B00342, NEON | AES), (0xF3B00382, NEON | AES), (0xF3B003C2, NEON | AES),
        (0xF2020C44, NEON | SHA1), (0xF3B902C2, NEON | SHA1), (0xF2320C44, NEON | SHA1), (0xF3BA0382, NEON | SHA1),
        (0xF3020C44, NEON | SHA256), (0xF3120C44, NEON | SHA256), (0xF3BA03C2, NEON | SHA256), (0xF3220C44, NEON | SHA256),
        (0xF2A10E02, NEON | PMULL), (0xF2810E02, NEON),                               // vmull.p64, vmull.p8
        (0xE710F211, IDIV), (0xE730F211, IDIV),                                       // sdiv udiv
        (0xE0810002, 0), (0xE5910004, 0), (0xE92D4010, 0), (0xE8BD8010, 0),           // add ldr push pop
        (0xE12FFF1E, 0), (0xF57FF05B, 0), (0xF5D0F000, 0),                            // bx lr, dmb, pld
    ];

    /// Same instructions from `-triple=thumbv8a` (hw1 << 16 | hw2).
    #[rustfmt::skip]
    const T32: &[(u32, u64)] = &[
        (0xEE300A81, VFP), (0xEE310B02, VFP), (0xEE100A90, VFP), (0xEC510B12, VFP),
        (0xEEF1FA10, VFP), (0xED900B02, VFP), (0xED2D8B04, VFP), (0xECBD8B04, VFP),
        (0xEEA00B10, VFP), (0xFE300A81, VFP), (0xFEB80A60, VFP),
        (0xEF220844, NEON), (0xFF020D54, NEON), (0xF9200A8D, NEON), (0xF901070F, NEON),
        (0xFF000150, NEON), (0xEF800050, NEON), (0xEFB20344, NEON),
        (0xFAC1F082, CRC32), (0xFAD1F0A2, CRC32),
        (0xFFB00302, NEON | AES), (0xFFB003C2, NEON | AES),
        (0xEF020C44, NEON | SHA1), (0xFFB902C2, NEON | SHA1), (0xFFBA0382, NEON | SHA1),
        (0xFF020C44, NEON | SHA256), (0xFFBA03C2, NEON | SHA256), (0xFF220C44, NEON | SHA256),
        (0xEFA10E02, NEON | PMULL), (0xEF810E02, NEON),
        (0xFB91F0F2, IDIV), (0xFBB1F0F2, IDIV),
        (0xEB010002, 0), (0xF3BF8F5B, 0), (0xF890F000, 0),                            // add.w, dmb, pld
    ];

    #[test]
    fn a32_encodings() {
        for &(w, want) in A32 {
            assert_eq!(classify_a32(w), want, "{w:#010X}");
        }
    }

    #[test]
    fn t32_encodings() {
        for &(w, want) in T32 {
            assert_eq!(classify_t32(w), want, "{w:#010X}");
        }
    }

    #[test]
    fn a32_fp_function_both_byte_orders() {
        // push; vldr; vldr; vadd.f64; vmul.f64; vstr; add; pop
        let f = [0xE92D4010, 0xED900B02, 0xED901B04, 0xEE300B01, 0xEE200B01, 0xED810B00, 0xE0810002, 0xE8BD8010];
        let words: Vec<u32> = f.repeat(512);
        assert_eq!(detect(&le_words(&words), Isa::Arm, Endianness::Little), vec!["VFP"]);
        assert_eq!(detect(&be_words(&words), Isa::Arm, Endianness::Big), vec!["VFP"]);
    }

    #[test]
    fn thumb_is_not_an_extension_and_isolated_matches_do_not_count() {
        // push {r4,lr}; ldr; adds; bl; pop {r4,pc}; a literal word that looks like vldr.
        let mut code = Vec::new();
        for _ in 0..1000 {
            for h in [0xB510u16, 0x6848, 0x1840, 0xF7FF, 0xFFFE, 0xBD10] {
                code.extend(h.to_le_bytes());
            }
            code.extend([0xED90u16, 0x0B02].iter().flat_map(|h| h.to_le_bytes()));
            for _ in 0..20 {
                code.extend(0x1840u16.to_le_bytes());
            }
        }
        assert!(detect(&code, Isa::Arm, Endianness::Little).is_empty());
    }

    #[test]
    fn thumb2_neon_loop() {
        // vld1.32; vadd.i32; vmul.f32; vst1.8; subs; bne
        let mut code = Vec::new();
        for _ in 0..1000 {
            for h in [0xF920u16, 0x0A8D, 0xEF22, 0x0844, 0xFF02, 0x0D54, 0xF901, 0x070F, 0x3901, 0xD1F6] {
                code.extend(h.to_le_bytes());
            }
        }
        assert_eq!(detect(&code, Isa::Arm, Endianness::Little), vec!["NEON"]);
    }
}
