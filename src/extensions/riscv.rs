//! RISC-V extension evidence.
//!
//! The instruction stream is a sequence of little-endian 16-bit parcels: a
//! parcel whose low two bits are not `11` is a compressed (16-bit)
//! instruction, `xxx11` with bits 4:2 != `111` starts a 32-bit instruction,
//! longer encodings are not used by any ratified extension and count as
//! invalid. 32-bit instructions are classified by major opcode, funct3,
//! funct7 / funct6 / funct5, fmt, and for a few by rs2 or the full
//! immediate. Reserved major opcodes and reserved funct3 values of the base
//! ISA are invalid.
//!
//! * C: compressed instructions must make up at least 5% of the stream
//!   (compilers emit them for 40-60% of instructions when C is enabled).
//! * V: needs `vsetvli` / `vsetivli` / `vsetvl` (every vector loop sets vtype).

use super::{bit_of, ExtDef, Tally};
use crate::types::{Endianness, ExtensionCategory::*, Isa};

const V_SETUP_IDX: usize = 0;

pub(super) const EXTS: &[ExtDef] = &[
    ExtDef::hidden("v-setup"),
    ExtDef::narrow("M", Other),
    ExtDef::narrow("A", Atomic),
    ExtDef::new("F", FloatingPoint),
    ExtDef::new("D", FloatingPoint),
    ExtDef::new("Q", FloatingPoint),
    ExtDef::new("Zfh", FloatingPoint),
    ExtDef::new("Zfhmin", FloatingPoint),
    ExtDef::new("C", Compressed).rule(16, 20),
    ExtDef::new("V", Simd).anchored(V_SETUP_IDX),
    ExtDef::narrow("Zicsr", System),
    ExtDef::narrow("Zifencei", System),
    ExtDef::narrow("Zba", BitManip),
    ExtDef::narrow("Zbb", BitManip),
    ExtDef::narrow("Zbs", BitManip),
    ExtDef::narrow("Zbc", BitManip),
    ExtDef::narrow("Zicond", Other),
    ExtDef::narrow("Zknh", Crypto),
    ExtDef::narrow("Zkne", Crypto),
    ExtDef::narrow("Zknd", Crypto),
    ExtDef::narrow("Zksh", Crypto),
    ExtDef::narrow("H", Virtualization),
];

const fn b(name: &str) -> u64 {
    bit_of(EXTS, name)
}
const V_SETUP: u64 = b("v-setup");
const M: u64 = b("M");
const A: u64 = b("A");
const F: u64 = b("F");
const D: u64 = b("D");
const Q: u64 = b("Q");
const ZFH: u64 = b("Zfh");
const ZFHMIN: u64 = b("Zfhmin");
const C: u64 = b("C");
const V: u64 = b("V");
const ZICSR: u64 = b("Zicsr");
const ZIFENCEI: u64 = b("Zifencei");
const ZBA: u64 = b("Zba");
const ZBB: u64 = b("Zbb");
const ZBS: u64 = b("Zbs");
const ZBC: u64 = b("Zbc");
const ZICOND: u64 = b("Zicond");
const ZKNH: u64 = b("Zknh");
const ZKNE: u64 = b("Zkne");
const ZKND: u64 = b("Zknd");
const ZKSH: u64 = b("Zksh");
const H: u64 = b("H");

/// Region starts are parcel aligned but may fall in the middle of a 32-bit
/// instruction; skip a couple of instructions.
const WARMUP: usize = 2;

pub(super) fn scan(code: &[u8], isa: Isa, _e: Endianness, t: &mut Tally) {
    let rv64 = isa != Isa::RiscV32;
    let mut pos = 0usize;
    let mut n = 0usize;
    while pos + 2 <= code.len() {
        let lo = u16::from_le_bytes([code[pos], code[pos + 1]]);
        let (len, r) = if lo & 3 != 3 {
            (2, classify16(lo, rv64))
        } else if lo & 0x1C != 0x1C {
            if pos + 4 > code.len() {
                break;
            }
            let w = u32::from_le_bytes([code[pos], code[pos + 1], code[pos + 2], code[pos + 3]]);
            (4, classify32(w, rv64))
        } else {
            (2, None)
        };
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

/// Evidence bits of a compressed instruction; `None` if reserved.
pub(crate) fn classify16(h: u16, rv64: bool) -> Option<u64> {
    let q = h & 3;
    let f3 = h >> 13;
    let rd = (h >> 7) & 0x1F;
    let ext = match (q, f3) {
        // c.addi4spn with a zero immediate (includes the all-zero illegal instruction).
        (0, 0) if (h >> 5) & 0xFF == 0 => return None,
        (0, 1) | (0, 5) | (2, 1) | (2, 5) => D, // c.fld, c.fsd, c.fldsp, c.fsdsp
        (0, 3) | (0, 7) | (2, 3) | (2, 7) if !rv64 => F, // c.flw, c.fsw, c.flwsp, c.fswsp
        (1, 3) if (h >> 2) & 0x1F == 0 && (h >> 12) & 1 == 0 => return None, // c.lui/c.addi16sp, imm 0
        (1, 1) if rv64 && rd == 0 => return None, // c.addiw x0
        (2, 2) if rd == 0 => return None,            // c.lwsp x0
        (2, 3) if rv64 && rd == 0 => return None,    // c.ldsp x0
        (2, 4) if h & 0x1FFC == 0 => return None,    // c.jr x0
        _ => 0,
    };
    Some(ext | C)
}

/// Evidence bits of a 32-bit instruction; `None` if reserved.
pub(crate) fn classify32(w: u32, rv64: bool) -> Option<u64> {
    let opc = w & 0x7F;
    let rd = (w >> 7) & 0x1F;
    let f3 = (w >> 12) & 7;
    let rs2 = (w >> 20) & 0x1F;
    let f7 = w >> 25;
    Some(match opc {
        0x03 => match f3 {
            0 | 1 | 2 | 4 | 5 => 0,
            3 | 6 if rv64 => 0,
            _ => return None,
        },
        0x07 | 0x27 => match f3 {
            1 => ZFHMIN, // flh / fsh
            2 => F,
            3 => D,
            4 => Q,
            _ if (w >> 28) & 1 == 0 => V, // vector loads/stores (width 0, 5, 6, 7), mew = 0
            _ => return None,
        },
        0x0F => match f3 {
            0 => 0, // fence, fence.tso, pause
            1 => ZIFENCEI,
            2 => 0, // cbo.*
            _ => return None,
        },
        0x13 => op_imm(w, rv64),
        0x17 | 0x37 | 0x6F => 0,
        0x1B if rv64 => op_imm32(w)?,
        0x23 => match f3 {
            0..=2 => 0,
            3 if rv64 => 0,
            _ => return None,
        },
        0x2F => amo(w, rv64)?,
        0x33 => op(w, rv64)?,
        0x3B if rv64 => op32(w)?,
        0x43 | 0x47 | 0x4B | 0x4F => fmt_bit((w >> 25) & 3, false),
        0x53 => op_fp(w)?,
        0x57 => {
            if f3 == 7 {
                let setup = w >> 31 == 0 || w >> 30 == 0b11 || f7 == 0b100_0000;
                if !setup {
                    return None;
                }
                V | V_SETUP
            } else {
                V
            }
        }
        0x63 => match f3 {
            2 | 3 => return None,
            _ => 0,
        },
        0x67 => match f3 {
            0 => 0,
            _ => return None,
        },
        0x73 => system(w, rd, f3, rs2, f7)?,
        0x0B | 0x2B | 0x5B | 0x7B => 0, // custom-0..3 (vendor extensions)
        _ => return None,
    })
}

/// Precision bit of an FP `fmt` field (0 S, 1 D, 2 H, 3 Q).
fn fmt_bit(fmt: u32, min: bool) -> u64 {
    match fmt {
        0 => F,
        1 => D,
        2 => {
            if min {
                ZFHMIN
            } else {
                ZFH
            }
        }
        _ => Q,
    }
}

fn op_imm(w: u32, rv64: bool) -> u64 {
    let f3 = (w >> 12) & 7;
    let imm12 = w >> 20;
    let f6 = imm12 >> 6;
    match f3 {
        1 => match imm12 {
            0x600 | 0x601 | 0x602 | 0x604 | 0x605 => ZBB, // clz, ctz, cpop, sext.b, sext.h
            0x100..=0x103 => ZKNH,                       // sha256sum0/1, sig0/1
            0x104..=0x107 if rv64 => ZKNH,               // sha512sum0/1, sig0/1
            0x108 | 0x109 => ZKSH,                       // sm3p0, sm3p1
            0x300 if rv64 => ZKND,                       // aes64im
            _ => match f6 {
                0b010010 | 0b011010 | 0b001010 => ZBS, // bclri, binvi, bseti
                _ => 0,
            },
        },
        5 => match imm12 {
            0x287 => ZBB,                   // orc.b
            0x6B8 if rv64 => ZBB,           // rev8 (RV64)
            0x698 if !rv64 => ZBB,          // rev8 (RV32)
            _ => match f6 {
                0b011000 => ZBB, // rori
                0b010010 => ZBS, // bexti
                _ => 0,
            },
        },
        _ => 0,
    }
}

fn op_imm32(w: u32) -> Option<u64> {
    let f3 = (w >> 12) & 7;
    let f7 = w >> 25;
    let rs2 = (w >> 20) & 0x1F;
    Some(match f3 {
        0 => 0, // addiw
        1 => match f7 {
            0 => 0, // slliw
            0b011_0000 if rs2 <= 2 => ZBB, // clzw, ctzw, cpopw
            _ if w >> 26 == 0b000010 => ZBA, // slli.uw
            _ => return None,
        },
        5 => match f7 {
            0 | 0b010_0000 => 0, // srliw, sraiw
            0b011_0000 => ZBB,   // roriw
            _ => return None,
        },
        _ => return None,
    })
}

fn op(w: u32, rv64: bool) -> Option<u64> {
    let f3 = (w >> 12) & 7;
    let f7 = w >> 25;
    let rs2 = (w >> 20) & 0x1F;
    Some(match (f7, f3) {
        (0, _) => 0,
        (0b010_0000, 0 | 5) => 0,         // sub, sra
        (0b010_0000, 4 | 6 | 7) => ZBB,   // xnor, orn, andn
        (0b000_0001, _) => M,
        (0b001_0000, 2 | 4 | 6) => ZBA,   // sh1add, sh2add, sh3add
        (0b000_0101, 4..=7) => ZBB,       // min, minu, max, maxu
        (0b000_0101, 1..=3) => ZBC,       // clmul, clmulr, clmulh
        (0b011_0000, 1 | 5) => ZBB,       // rol, ror
        (0b000_0100, 4) if !rv64 && rs2 == 0 => ZBB, // zext.h (RV32)
        (0b000_0100, 4 | 7) => 0,         // pack, packh (Zbkb)
        (0b010_0100, 1 | 5) => ZBS,       // bclr, bext
        (0b011_0100, 1) => ZBS,           // binv
        (0b001_0100, 1) => ZBS,           // bset
        (0b001_0100, 2 | 4) => 0,         // xperm4, xperm8 (Zbkx)
        (0b000_0111, 5 | 7) => ZICOND,    // czero.eqz, czero.nez
        (0b001_1001 | 0b001_1011, 0) if rv64 => ZKNE, // aes64es, aes64esm
        (0b001_1101 | 0b001_1111, 0) if rv64 => ZKND, // aes64ds, aes64dsm
        (0b011_1111, 0) if rv64 => 0,     // aes64ks2
        (_, 0) if !rv64 && matches!(f7 & 0x1F, 0b10001 | 0b10011 | 0b10101 | 0b10111 | 0b11000 | 0b11010) => 0, // RV32 AES / SM4
        _ => return None,
    })
}

fn op32(w: u32) -> Option<u64> {
    let f3 = (w >> 12) & 7;
    let f7 = w >> 25;
    let rs2 = (w >> 20) & 0x1F;
    Some(match (f7, f3) {
        (0, 0 | 1 | 5) => 0,              // addw, sllw, srlw
        (0b010_0000, 0 | 5) => 0,         // subw, sraw
        (0b000_0001, 0 | 4..=7) => M,     // mulw, divw, divuw, remw, remuw
        (0b000_0100, 0) => ZBA,           // add.uw
        (0b000_0100, 4) if rs2 == 0 => ZBB, // zext.h (RV64)
        (0b000_0100, 4) => 0,             // packw (Zbkb)
        (0b001_0000, 2 | 4 | 6) => ZBA,   // sh1add.uw, sh2add.uw, sh3add.uw
        (0b011_0000, 1 | 5) => ZBB,       // rolw, rorw
        _ => return None,
    })
}

fn amo(w: u32, rv64: bool) -> Option<u64> {
    let f3 = (w >> 12) & 7;
    let f5 = w >> 27;
    let rs2 = (w >> 20) & 0x1F;
    match f3 {
        2 => {}
        3 if rv64 => {}
        0 | 1 | 4 => return Some(0), // Zabha (byte/half), Zacas (quad)
        _ => return None,
    }
    Some(match f5 {
        0b00010 if rs2 == 0 => A, // lr
        0b00010 => return None,
        0b00011 | 0b00001 | 0b00000 | 0b00100 | 0b01100 | 0b01000 | 0b10000 | 0b10100 | 0b11000
        | 0b11100 => A, // sc, amoswap, amoadd, amoxor, amoand, amoor, amomin[u], amomax[u]
        0b00101 => 0, // amocas (Zacas)
        _ => return None,
    })
}

fn op_fp(w: u32) -> Option<u64> {
    let fmt = (w >> 25) & 3;
    let f5 = w >> 27;
    let rs2 = (w >> 20) & 0x1F;
    let rm = (w >> 12) & 7;
    let arith = fmt_bit(fmt, false);
    Some(match f5 {
        0b00000..=0b00011 => arith,                 // fadd, fsub, fmul, fdiv
        0b01011 if rs2 == 0 => arith,               // fsqrt
        0b00100 if rm <= 2 => arith,                // fsgnj, fsgnjn, fsgnjx
        0b00101 if rm <= 1 => arith,                // fmin, fmax
        0b10100 if rm <= 2 => arith,                // fle, flt, feq
        0b11000 | 0b11010 if rs2 <= 3 => arith,     // fcvt int <-> fp
        0b11100 if rs2 == 0 && rm == 1 => arith,    // fclass
        0b11100 | 0b11110 if rs2 == 0 && rm == 0 => fmt_bit(fmt, true), // fmv.x.*, fmv.*.x
        0b01000 if rs2 <= 3 && rs2 != fmt => fmt_bit(fmt, true) | fmt_bit(rs2, true), // fcvt fp <-> fp
        // Zfa (fli, fminm/fmaxm, fround, fcvtmod, fmvh/fmvp, fleq/fltq): valid, not reported.
        0b11110 if rs2 == 1 && rm == 0 => 0,
        0b00101 if rm == 2 || rm == 3 => 0,
        0b01000 if rs2 == 4 || rs2 == 5 => 0,
        0b11000 if rs2 == 8 => 0,
        0b11100 if rs2 == 1 && rm == 0 => 0,
        0b10110 if rm == 0 => 0,
        0b10100 if rm == 4 || rm == 5 => 0,
        _ => return None,
    })
}

fn system(w: u32, rd: u32, f3: u32, rs2: u32, f7: u32) -> Option<u64> {
    Some(match f3 {
        0 => match f7 {
            0b001_0001 | 0b011_0001 if rd == 0 => H, // hfence.vvma, hfence.gvma
            _ => 0, // ecall, ebreak, xret, wfi, sfence.vma, ...
        },
        1 | 2 | 3 | 5 | 6 | 7 => ZICSR,
        _ => match f7 {
            // hlv.b/bu, hlv.h/hu, hlvx.hu, hlv.w/wu, hlvx.wu, hlv.d
            0b011_0000 | 0b011_0110 if rs2 <= 1 && (f7 == 0b011_0000 || rs2 == 0) => H,
            0b011_0010 | 0b011_0100 if matches!(rs2, 0 | 1 | 3) => H,
            // hsv.b/h/w/d
            0b011_0001 | 0b011_0011 | 0b011_0101 | 0b011_0111 if rd == 0 => H,
            _ if w >> 31 == 1 => 0, // Zimop may-be-operations (incl. Zicfiss)
            _ => return None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::test_util::{detect, le_words};

    #[test]
    fn anchor_is_hidden() {
        assert_eq!(EXTS[V_SETUP_IDX].name, "v-setup");
        assert!(EXTS[V_SETUP_IDX].hidden);
    }

    /// Encodings from `llvm-mc -triple=riscv64 -show-encoding` with the relevant `-mattr`.
    #[rustfmt::skip]
    const WORDS: &[(u32, u64)] = &[
        (0x02C58533, M), (0x02C59533, M), (0x02C5D533, M), (0x02C5F533, M), // mul mulh divu remu
        (0x02C5853B, M), (0x02C5C53B, M), (0x02C5F53B, M),                  // mulw divw remuw
        (0x1005A52F, A), (0x18C5B52F, A), (0x08C5A52F, A), (0x06C5B52F, A), // lr.w sc.d amoswap.w amoadd.d
        (0x20C5A52F, A), (0x60C5A52F, A), (0x40C5A52F, A), (0x80C5A52F, A), // amoxor amoand amoor amomin
        (0xA0C5A52F, A), (0xC0C5B52F, A), (0xE0C5B52F, A),                  // amomax amominu amomaxu
        (0x0085A507, F), (0x0085C507, Q), (0x00859507, ZFHMIN), (0x00A5A427, F), // flw flq flh fsw
        (0x0085B507, D), (0x00A5B427, D),                                   // fld fsd
        (0x00C5F553, F), (0x02C5F553, D), (0x04C5F553, ZFH), (0x06C5F553, Q), // fadd.s/d/h/q
        (0x68C5F543, F), (0x6AC5F543, D),                                   // fmadd.s/d
        (0x4015F553, F | D), (0x42058553, D | F),                           // fcvt.s.d, fcvt.d.s
        (0xC005F553, F), (0xD225F553, D), (0xE2058553, D), (0xF0058553, F), // fcvt.w.s fcvt.d.l fmv.x.d fmv.w.x
        (0x22C58553, D), (0xA2C5A553, D), (0xE2059553, D), (0x5A05F553, D), // fsgnj.d feq.d fclass.d fsqrt.d
        (0x2CC58553, ZFH), (0x40258553, F | ZFHMIN), (0xE4058553, ZFHMIN),  // fmin.h fcvt.s.h fmv.x.h
        (0x0D05F557, V | V_SETUP), (0xCD047557, V | V_SETUP), (0x80C5F557, V | V_SETUP), // vsetvli vsetivli vsetvl
        (0x02056087, V), (0x020560A7, V), (0x02050087, V), (0x02057087, V), // vle32 vse32 vle8 vle64
        (0x0AB56087, V), (0x06256087, V), (0x02850087, V),                  // vlse32 vluxei32 vl1re8
        (0x022180D7, V), (0x022550D7, V), (0x5E0540D7, V), (0x0221A0D7, V), // vadd.vv vfadd.vf vmv.v.x vredsum.vs
        (0x00102573, ZICSR), (0x00359573, ZICSR), (0x0030D573, ZICSR), (0xC0002573, ZICSR),
        (0x0000100F, ZIFENCEI), (0x0330000F, 0),                            // fence.i, fence rw,rw
        (0x20C5A533, ZBA), (0x20C5C533, ZBA), (0x20C5E533, ZBA),            // sh1add sh2add sh3add
        (0x08C5853B, ZBA), (0x20C5A53B, ZBA), (0x20C5E53B, ZBA), (0x0835951B, ZBA), // add.uw sh1add.uw sh3add.uw slli.uw
        (0x40C5F533, ZBB), (0x40C5E533, ZBB), (0x40C5C533, ZBB),            // andn orn xnor
        (0x60059513, ZBB), (0x60159513, ZBB), (0x60259513, ZBB), (0x60459513, ZBB), (0x60559513, ZBB),
        (0x6005951B, ZBB), (0x6015951B, ZBB), (0x6025951B, ZBB),            // clzw ctzw cpopw
        (0x0AC5E533, ZBB), (0x0AC5F533, ZBB), (0x0AC5C533, ZBB), (0x0AC5D533, ZBB), // max maxu min minu
        (0x2875D513, ZBB), (0x6B85D513, ZBB),                               // orc.b rev8
        (0x60C59533, ZBB), (0x60C5D533, ZBB), (0x60C5953B, ZBB), (0x60C5D53B, ZBB), // rol ror rolw rorw
        (0x6035D513, ZBB), (0x6035D51B, ZBB), (0x0805C53B, ZBB),            // rori roriw zext.h
        (0x48C59533, ZBS), (0x48C5D533, ZBS), (0x68C59533, ZBS), (0x28C59533, ZBS), // bclr bext binv bset
        (0x4A159513, ZBS), (0x4835D513, ZBS), (0x68359513, ZBS), (0x28359513, ZBS), // bclri bexti binvi bseti
        (0x0AC59533, ZBC), (0x0AC5A533, ZBC), (0x0AC5B533, ZBC),            // clmul clmulr clmulh
        (0x0EC5D533, ZICOND), (0x0EC5F533, ZICOND),                         // czero.eqz czero.nez
        (0x22B50073, H), (0x62B50073, H),                                   // hfence.vvma hfence.gvma
        (0x6005C573, H), (0x6815C573, H), (0x6435C573, H), (0x6C05C573, H), // hlv.b hlv.wu hlvx.hu hlv.d
        (0x62A5C073, H), (0x6EA5C073, H),                                   // hsv.b hsv.d
        (0x10259513, ZKNH), (0x10159513, ZKNH), (0x10659513, ZKNH), (0x10559513, ZKNH),
        (0x32C58533, ZKNE), (0x36C58533, ZKNE),                             // aes64es aes64esm
        (0x3AC58533, ZKND), (0x3EC58533, ZKND), (0x30059513, ZKND),         // aes64ds aes64dsm aes64im
        (0x31359513, 0), (0x7EC58533, 0),                                   // aes64ks1i aes64ks2
        (0x10859513, ZKSH),                                                 // sm3p0
        (0x00B50533, 0), (0x40B50533, 0), (0x00A58593, 0), (0x00008067, 0), // add sub addi ret
        (0x0085B503, 0), (0x00A5B423, 0), (0xFE0508E3, 0), (0x0000006F, 0), // ld sd beqz j
        (0x00000073, 0), (0x00100073, 0), (0x10500073, 0),                  // ecall ebreak wfi
    ];

    #[test]
    fn riscv64_encodings() {
        for &(w, want) in WORDS {
            assert_eq!(classify32(w, true), Some(want), "{w:#010X}");
        }
    }

    #[test]
    fn reserved_encodings() {
        for w in [0x0000_706Bu32, 0x0000_0077, 0x0000_7003, 0x0000_2063, 0x0000_1067, 0x1000_7087] {
            assert_eq!(classify32(w, true), None, "{w:#010X}");
        }
        assert_eq!(classify32(0x0000_001B, false), None, "OP-IMM-32 on RV32");
        assert_eq!(classify16(0x0000, true), None);
        assert_eq!(classify16(0x4501, true), Some(C)); // c.li a0, 0
        assert_eq!(classify16(0x2588, true), Some(C | D)); // c.fld fa0, 8(a1)
        assert_eq!(classify16(0x6588, true), Some(C)); // c.ld a0, 8(a1)
        assert_eq!(classify16(0x6588, false), Some(C | F)); // c.flw fa0, 8(a1)
    }

    fn stream(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn rv64gc_vs_rv64g() {
        // A loop body: c.li, mul, fadd.d, c.addi, bnez, c.ld, amoadd.w
        let body = stream(&[
            &0x4501u16.to_le_bytes(),
            &0x02C58533u32.to_le_bytes(),
            &0x02C5F553u32.to_le_bytes(),
            &0x0505u16.to_le_bytes(),
            &0x6588u16.to_le_bytes(),
            &0x00C5A52Fu32.to_le_bytes(),
            &0xFE051EE3u32.to_le_bytes(),
        ]);
        let code = body.repeat(2000);
        assert_eq!(detect(&code, Isa::RiscV64, Endianness::Little), vec!["M", "A", "D", "C"]);
        // Without compressed instructions there is no C.
        let body = le_words(&[0x00A58593, 0x02C58533, 0x02C5F553, 0x00C5A52F, 0xFE051EE3]);
        let code = body.repeat(2000);
        assert_eq!(detect(&code, Isa::RiscV64, Endianness::Little), vec!["M", "A", "D"]);
    }

    #[test]
    fn vector_needs_vsetvl() {
        // vle32.v, vadd.vv, vse32.v without vsetvli: not V.
        let body = le_words(&[0x02056087, 0x022180D7, 0x020560A7, 0x00A58593]);
        let code = body.repeat(2000);
        assert!(!detect(&code, Isa::RiscV64, Endianness::Little).contains(&"V".to_string()));
        let body = le_words(&[0x0D05F557, 0x02056087, 0x022180D7, 0x020560A7, 0x00A58593]);
        let code = body.repeat(2000);
        assert_eq!(detect(&code, Isa::RiscV64, Endianness::Little), vec!["V"]);
    }
}
