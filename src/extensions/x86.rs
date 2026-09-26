//! x86 / x86-64 extension evidence.
//!
//! A linear sweep over each code region with an instruction *length decoder*
//! (legacy prefixes, REX, REX2, VEX2/VEX3, EVEX, XOP, the 1-byte, 0F, 0F38
//! and 0F3A opcode maps, ModRM/SIB/displacement and immediate sizes, 3DNow!
//! suffix bytes). Every decoded instruction is classified by (mandatory
//! prefix, opcode map, opcode, VEX/EVEX L/W/pp, ModRM) into the extension it
//! belongs to. Encodings that cannot occur in valid code (opcodes invalid in
//! the current mode, undefined prefix/opcode combinations, misplaced LOCK,
//! VEX after REX/66/F2/F3, ...) are reported as invalid, which discards the
//! surrounding block (see [`super::Tally`]).
//!
//! Mode rules that matter for the classification:
//! * 32-bit mode: `C4`/`C5` are VEX only if the next byte has its top two
//!   bits set, otherwise LES/LDS; `62` is EVEX only under the same condition,
//!   otherwise BOUND.
//! * 64-bit mode: `D5` is the APX REX2 prefix (AAD is invalid there).
//!
//! `F3 0F BC` (TZCNT) is *not* evidence for BMI1: compilers emit it as
//! `rep bsf` for generic targets because it executes as BSF on older CPUs.

use super::{bit_of, ExtDef, Tally};
use crate::types::{Endianness, ExtensionCategory::*, Isa};

/// Evidence classes (at most 64).
pub(super) const EXTS: &[ExtDef] = &[
    ExtDef::new("MMX", Simd),
    ExtDef::new("SSE", Simd),
    ExtDef::new("SSE2", Simd),
    ExtDef::new("SSE3", Simd),
    ExtDef::new("SSSE3", Simd),
    ExtDef::new("SSE4.1", Simd),
    ExtDef::narrow("SSE4.2", Simd),
    ExtDef::new("AVX", Simd),
    ExtDef::new("AVX2", Simd),
    ExtDef::new("FMA", Simd),
    ExtDef::new("F16C", Simd),
    ExtDef::new("AVX-VNNI", MachineLearning),
    ExtDef::new("AVX-512", Simd),
    ExtDef::new("AMX", MachineLearning),
    ExtDef::narrow("AES-NI", Crypto),
    ExtDef::narrow("PCLMULQDQ", Crypto),
    ExtDef::new("VAES", Crypto),
    ExtDef::new("VPCLMULQDQ", Crypto),
    ExtDef::new("GFNI", Crypto),
    ExtDef::narrow("SHA", Crypto),
    ExtDef::narrow("POPCNT", BitManip),
    ExtDef::narrow("LZCNT", BitManip),
    ExtDef::narrow("BMI1", BitManip),
    ExtDef::narrow("BMI2", BitManip),
    ExtDef::narrow("ADX", BitManip),
    ExtDef::narrow("MOVBE", Other),
    ExtDef::narrow("RDRAND", Security),
    ExtDef::narrow("RDSEED", Security),
    ExtDef::narrow("CET", Security),
    ExtDef::narrow("TSX", Transactional),
    // REX2 and EVEX-with-extended-GPR encodings. Code built for APX uses
    // r16-r31 all over the place, so demand a lot: 32 hits and 0.5% of all
    // instructions (a non-APX binary produces none in clean blocks).
    ExtDef::new("APX", System).rule(32, 200),
];

const fn b(name: &str) -> u64 {
    bit_of(EXTS, name)
}
const MMX: u64 = b("MMX");
const SSE: u64 = b("SSE");
const SSE2: u64 = b("SSE2");
const SSE3: u64 = b("SSE3");
const SSSE3: u64 = b("SSSE3");
const SSE41: u64 = b("SSE4.1");
const SSE42: u64 = b("SSE4.2");
const AVX: u64 = b("AVX");
const AVX2: u64 = b("AVX2");
const FMA: u64 = b("FMA");
const F16C: u64 = b("F16C");
const AVXVNNI: u64 = b("AVX-VNNI");
const AVX512: u64 = b("AVX-512");
const AMX: u64 = b("AMX");
const AES: u64 = b("AES-NI");
const PCLMUL: u64 = b("PCLMULQDQ");
const VAES: u64 = b("VAES");
const VPCLMUL: u64 = b("VPCLMULQDQ");
const GFNI: u64 = b("GFNI");
const SHA: u64 = b("SHA");
const POPCNT: u64 = b("POPCNT");
const LZCNT: u64 = b("LZCNT");
const BMI1: u64 = b("BMI1");
const BMI2: u64 = b("BMI2");
const ADX: u64 = b("ADX");
const MOVBE: u64 = b("MOVBE");
const RDRAND: u64 = b("RDRAND");
const RDSEED: u64 = b("RDSEED");
const CET: u64 = b("CET");
const TSX: u64 = b("TSX");
const APX: u64 = b("APX");

/// Instructions decoded after a region start before evidence is counted: a
/// region may start inside an instruction, and x86 linear sweeps need a few
/// instructions to fall back onto real boundaries.
const WARMUP: usize = 8;

/// Architectural maximum instruction length.
const MAX_LEN: usize = 15;

/// Marks a valid instruction that ordinary compiled code does not contain
/// (BCD arithmetic, ARPL/BOUND/LES/LDS, far pointers, segment register
/// moves, port I/O, privileged system instructions, ES/SS overrides). It is
/// decoded with its proper length, but it ends a clean block like an invalid
/// encoding: random bytes run into one of these every few instructions.
const ODD: u64 = 1 << 63;

/// Result of decoding at one position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decoded {
    /// A valid instruction of `len` bytes carrying evidence bits `ext`.
    Insn { len: usize, ext: u64 },
    /// No valid instruction starts here.
    Invalid,
    /// The instruction runs past the end of the input.
    Truncated,
}

pub(super) fn scan(code: &[u8], isa: Isa, _e: Endianness, t: &mut Tally) {
    let m64 = isa == Isa::X86_64;
    let mut pos = 0usize;
    let mut n = 0usize;
    while pos < code.len() {
        match decode(&code[pos..], m64) {
            Decoded::Insn { len, ext } => {
                if n >= WARMUP {
                    if ext & ODD != 0 {
                        t.invalid();
                    } else {
                        t.insn(ext);
                    }
                }
                n += 1;
                pos += len;
            }
            Decoded::Invalid => {
                if n >= WARMUP {
                    t.invalid();
                }
                n += 1;
                pos += 1;
            }
            Decoded::Truncated => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Opcode tables
// ---------------------------------------------------------------------------

/// ModRM follows the opcode.
const M: u8 = 0x01;
/// 8-bit immediate.
const I8: u8 = 0x02;
/// 16/32-bit immediate (operand size).
const IZ: u8 = 0x04;
/// 16-bit immediate.
const I16: u8 = 0x08;
/// Handled explicitly in the decoder.
const S: u8 = 0x10;
/// Invalid in 64-bit mode.
const N64: u8 = 0x20;
/// Invalid (or a prefix, which cannot appear at the opcode position).
const X: u8 = 0x40;
/// Valid but not found in ordinary compiled code (see [`ODD`]).
const R: u8 = 0x80;

/// One-byte opcode map.
#[rustfmt::skip]
const MAP0: [u8; 256] = [
    // 0x00 (06/07/0E: PUSH/POP ES, PUSH CS)
    M, M, M, M, I8, IZ, N64 | R, N64 | R, M, M, M, M, I8, IZ, N64 | R, S,
    // 0x10 (16/17/1E/1F: PUSH/POP SS, DS)
    M, M, M, M, I8, IZ, N64 | R, N64 | R, M, M, M, M, I8, IZ, N64 | R, N64 | R,
    // 0x20 (26, 2E: segment prefixes; 27, 2F: DAA, DAS)
    M, M, M, M, I8, IZ, X, N64 | R, M, M, M, M, I8, IZ, X, N64 | R,
    // 0x30 (36, 3E: segment prefixes; 37, 3F: AAA, AAS)
    M, M, M, M, I8, IZ, X, N64 | R, M, M, M, M, I8, IZ, X, N64 | R,
    // 0x40 INC/DEC (REX in 64-bit mode, consumed as a prefix)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0x50 PUSH/POP
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0x60 (62: BOUND/EVEX, 63: ARPL/MOVSXD, 64-67: prefixes, 6C-6F: INS/OUTS)
    N64 | R, N64 | R, S, M, X, X, X, X, IZ, M | IZ, I8, M | I8, R, R, R, R,
    // 0x70 Jcc rel8
    I8, I8, I8, I8, I8, I8, I8, I8, I8, I8, I8, I8, I8, I8, I8, I8,
    // 0x80 (8F /0: POP r/m; 8F with reg != 0 is XOP, handled before the table)
    M | I8, M | IZ, M | I8 | N64, M | I8, M, M, M, M, M, M, M, M, M | R, M, M | R, M,
    // 0x90 (9A: CALLF ptr)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, S | N64 | R, 0, 0, 0, 0, 0,
    // 0xA0 (A0-A3: moffs)
    S, S, S, S, 0, 0, 0, 0, I8, IZ, 0, 0, 0, 0, 0, 0,
    // 0xB0 (B8-BF: MOV r, imm16/32/64)
    I8, I8, I8, I8, I8, I8, I8, I8, S, S, S, S, S, S, S, S,
    // 0xC0 (C4/C5: LES/LDS or VEX, C8: ENTER, CA/CB: RETF, CE: INTO, CF: IRET)
    M | I8, M | I8, I16, 0, S, S, M | I8, M | IZ, S, 0, I16 | R, R, 0, I8, N64 | R, R,
    // 0xD0 (D4/D5: AAM/AAD or REX2, D6: SALC)
    M, M, M, M, I8 | N64 | R, I8 | N64 | R, X, 0, M, M, M, M, M, M, M, M,
    // 0xE0 (E4-E7, EC-EF: IN/OUT; E8/E9: rel16/32; EA: JMPF ptr)
    I8, I8, I8, I8, I8 | R, I8 | R, I8 | R, I8 | R, S, S, S | N64 | R, I8, R, R, R, R,
    // 0xF0 (F0, F2, F3: prefixes; F1: INT1; F4: HLT; F6/F7: group 3; FA/FB: CLI/STI)
    X, R, X, X, R, 0, S, S, 0, 0, R, R, 0, 0, M, M,
];

/// Two-byte opcode map (0F xx).
#[rustfmt::skip]
const MAP1: [u8; 256] = [
    // 0x00 (0F 0F: 3DNow!; 00-03, 06-09: system)
    M | R, M, M | R, M | R, X, 0, R, R, R, R, X, 0, X, M, 0, S,
    // 0x10
    M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    // 0x20 (20-23: MOV CR/DR)
    M | R, M | R, M | R, M | R, X, X, X, X, M, M, M, M, M, M, M, M,
    // 0x30 (38, 3A: escapes; WRMSR, RDMSR, RDPMC, SYSENTER, SYSEXIT, GETSEC)
    R, 0, R, R, R, R, X, R, S, X, S, X, X, X, X, X,
    // 0x40 CMOVcc
    M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    // 0x50
    M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    // 0x60
    M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    // 0x70 (77: EMMS; 78: VMREAD / EXTRQ / INSERTQ)
    M | I8, M | I8, M | I8, M | I8, M, M, M, 0, S, M, X, X, M, M, M, M,
    // 0x80 Jcc rel16/32
    S, S, S, S, S, S, S, S, S, S, S, S, S, S, S, S,
    // 0x90 SETcc
    M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    // 0xA0
    0, 0, 0, M, M | I8, M, X, X, 0, 0, R, M, M | I8, M, M, M,
    // 0xB0
    M, M, M, M, M, M, M, M, M, M, M | I8, M, M, M, M, M,
    // 0xC0 (C8-CF: BSWAP)
    M, M, M | I8, M, M | I8, M | I8, M | I8, M, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0xD0
    M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    // 0xE0
    M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    // 0xF0
    M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
];

// Opcode validity bitmaps for the 0F38 / 0F3A / VEX / EVEX spaces, bit `op`
// of `[u64; 4]`. Generated by enumerating every opcode with every ModRM.reg
// value (register and memory forms), W, L and mask variants through LLVM's
// x86 decoder (`LLVMDisasmInstruction`, LLVM 23). An opcode that no variant
// decodes is undefined.
/// Legacy 0F 38 opcodes accepted by LLVM's decoder, per mandatory prefix (none, 66, F3, F2).
#[rustfmt::skip]
const LEGACY_0F38: [[u64; 4]; 4] = [
    [0x0000000070000FFF, 0x0000000000000000, 0x0000000000000C00, 0x1243000000003F00],
    [0xFFBF0F3F70B10FFF, 0x0000000000000003, 0x0000000000000C07, 0x13630000F800BF00],
    [0x0000000070000FFF, 0x0000000000000000, 0x0000000000000C00, 0x1F430000F1003F00],
    [0x0000000070000FFF, 0x0000000000000000, 0x0000000000000C00, 0x1343000000003F00],
];

/// Legacy 0F 3A opcodes accepted by LLVM's decoder, per mandatory prefix.
#[rustfmt::skip]
const LEGACY_0F3A: [[u64; 4]; 4] = [
    [0x0000000000008000, 0x0000000000000000, 0x0000000000000000, 0x0000000000001000],
    [0x0000000700F0FF00, 0x0000000F00000017, 0x0000000000000000, 0x000000008000D000],
    [0x0000000000008000, 0x0000000000000000, 0x0000000000000000, 0x0001000000001000],
    [0x0000000000008000, 0x0000000000000000, 0x0000000000000000, 0x0000000000001000],
];

/// VEX opcodes accepted by LLVM's decoder: maps 1, 2, 3 x pp (none, 66, F3, F2).
#[rustfmt::skip]
const VEX_OPS: [[u64; 4]; 12] = [
    [0x0000CB0000FF0000, 0x00800000FFFF0CF6, 0x00004000030F0000, 0x0000000000000044],
    [0x0000CB0000FF0000, 0xF07FFFFFFFF30CF6, 0x00000000030F0000, 0x7FFEFFFFFFFF0074],
    [0x0000340000470000, 0xC0018000FF0E0000, 0x0000000000000000, 0x0000004000000004],
    [0x0000340000070000, 0x30010000F7020000, 0x00000000000C0000, 0x0001004000010004],
    [0x0000000000000000, 0x0000100040030200, 0x0001000000000000, 0x00AC0000040C0000],
    [0xFFFFFF3F77C8FFFF, 0x03001000470F0EE3, 0xFFF3FFC0FFCF5000, 0x0080FFFFFC0C8000],
    [0x0000000000000000, 0x0004000050030800, 0x0003000000000000, 0x00A00000040C0000],
    [0x0000000000000000, 0x0000000050030E00, 0x0001000000000000, 0x00E0000004003800],
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x030F000723F0FF77, 0xFF00FF0FF0001F57, 0x0000000000000000, 0x00000000C000C000],
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0001000000000000],
];

/// EVEX opcodes accepted by LLVM's decoder: maps 1, 2, 3, 5, 6 x pp.
#[rustfmt::skip]
const EVEX_OPS: [[u64; 4]; 20] = [
    [0x0000CB0000FF0000, 0x03000000FFF20000, 0x00000000000F0000, 0x0000000000000044],
    [0x0000CB0000FF0000, 0xCF7FFFFFFFF20000, 0x00000000000F0000, 0x7F7EFFFFFF7E0074],
    [0x0000F40000470000, 0xCF018000FF020000, 0x0000000000000000, 0x0000004000000004],
    [0x0000F40000070000, 0x8F018000F7020000, 0x00000000000C0000, 0x0000004000000004],
    [0x0000000000000000, 0x0010200000070200, 0x0000000000000000, 0x00AC0000000C0000],
    [0xFFFF3FFFFF7F3811, 0xFFEF20FC0F3FFEFD, 0xFFF0FFCFFFCFAF08, 0x00ACFFFFF00CBDD0],
    [0x073F07FF003F0000, 0x0014200000070C00, 0x0000000000000000, 0x00A00000040C0000],
    [0x0000000000000000, 0x00142100000F0C00, 0x00000C000C000000, 0x00E0000004000000],
    [0x000000C000000580, 0x000000C000CC0000, 0x0000000000000000, 0x0000000000000004],
    [0xCF0000EFEFF08FBB, 0x000F00C000FF001C, 0x0000000000000000, 0x000000000000C000],
    [0x0000000000000080, 0x0080000000000004, 0x0000000000000000, 0x0000000000000004],
    [0x0000004000000180, 0x0080004000440000, 0x0000000000000000, 0x0001000000000004],
    [0x0000C00029000000, 0x33103F00FF020000, 0x0000000000000000, 0x0000000000000000],
    [0x0000800020000000, 0x7F007F00FF020000, 0x0000000000000000, 0x0000000000000000],
    [0x0000F40009030000, 0x6B10F000FF020000, 0x0000000000000000, 0x0000000000000000],
    [0x0000000049000000, 0x2410BF0004000000, 0x0000000000000000, 0x0000000000000000],
    [0x0000100000080000, 0x0000000000005004, 0x5500550055000003, 0x0000000000000000],
    [0x0000300000080000, 0x000000000000F00C, 0xFFC0FFC0FFC00000, 0x0000000000000000],
    [0x0000000000000000, 0x0000000000C00000, 0x0000000000000000, 0x0000000000C00000],
    [0x0000000000000000, 0x0000000000C00000, 0x0000000000000000, 0x0000000000C00000],
];

fn has(bits: &[u64; 4], op: u8) -> bool {
    bits[usize::from(op >> 6)] >> (op & 63) & 1 != 0
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct Prefixes {
    /// 0x66 seen.
    opsz: bool,
    /// 0x67 seen.
    adsz: bool,
    /// 0xF0 seen.
    lock: bool,
    /// Last of 0xF2 / 0xF3, or 0.
    rep: u8,
    /// REX byte immediately before the opcode, or 0.
    rex: u8,
}

impl Prefixes {
    /// Mandatory-prefix index for SSE tables: 0 none, 1 = 66, 2 = F3, 3 = F2.
    fn mandatory(&self) -> usize {
        match self.rep {
            0xF3 => 2,
            0xF2 => 3,
            _ => usize::from(self.opsz),
        }
    }
}

/// Byte at `i`, or bail out with `Truncated`.
macro_rules! at {
    ($b:expr, $i:expr) => {
        match $b.get($i) {
            Some(&v) => v,
            None => return Decoded::Truncated,
        }
    };
}

/// Length of ModRM + SIB + displacement at `b[pos]`.
fn modrm_len(b: &[u8], pos: usize, addr16: bool) -> Option<usize> {
    let m = *b.get(pos)?;
    let md = m >> 6;
    let rm = m & 7;
    if md == 3 {
        return Some(1);
    }
    if addr16 {
        let disp = match md {
            0 if rm == 6 => 2,
            0 => 0,
            1 => 1,
            _ => 2,
        };
        return Some(1 + disp);
    }
    let mut len = 1;
    let mut sib_base5 = false;
    if rm == 4 {
        sib_base5 = *b.get(pos + 1)? & 7 == 5;
        len += 1;
    }
    let disp = match md {
        0 if rm == 5 || (rm == 4 && sib_base5) => 4,
        0 => 0,
        1 => 1,
        _ => 4,
    };
    Some(len + disp)
}

/// Finish an instruction: ModRM (if any) at `pos`, then `imm` bytes.
fn finish(b: &[u8], pos: usize, has_modrm: bool, addr16: bool, imm: usize, ext: u64) -> Decoded {
    let mut len = pos;
    if has_modrm {
        match modrm_len(b, pos, addr16) {
            Some(n) => len += n,
            None => return Decoded::Truncated,
        }
    }
    len += imm;
    if len > MAX_LEN {
        return Decoded::Invalid;
    }
    if len > b.len() {
        return Decoded::Truncated;
    }
    Decoded::Insn { len, ext }
}

/// Decode the instruction at the start of `b`.
pub(crate) fn decode(b: &[u8], m64: bool) -> Decoded {
    let mut p = Prefixes::default();
    let mut i = 0usize;
    let mut odd = 0u64;
    loop {
        let c = at!(b, i);
        match c {
            0x26 | 0x36 => odd = ODD,
            0x2E | 0x3E | 0x64 | 0x65 => {}
            0x66 => p.opsz = true,
            0x67 => p.adsz = true,
            0xF0 => p.lock = true,
            0xF2 | 0xF3 => p.rep = c,
            0x40..=0x4F if m64 => {
                p.rex = c;
                i += 1;
                if i >= MAX_LEN {
                    return Decoded::Invalid;
                }
                continue;
            }
            _ => break,
        }
        // A legacy prefix after REX makes the REX ineffective.
        p.rex = 0;
        i += 1;
        if i >= MAX_LEN {
            return Decoded::Invalid;
        }
    }
    let addr16 = !m64 && p.adsz;
    let c = b[i];
    let r = match c {
        0xD5 if m64 => rex2(b, i, &p),
        0xC4 | 0xC5 => {
            let nx = at!(b, i + 1);
            if m64 || nx >> 6 == 3 {
                vex(b, i, m64, &p)
            } else {
                // LES/LDS (memory operand only, which nx >> 6 != 3 guarantees).
                if p.rep != 0 || p.lock {
                    return Decoded::Invalid;
                }
                finish(b, i + 1, true, addr16, 0, ODD)
            }
        }
        0x62 => {
            let nx = at!(b, i + 1);
            if m64 || nx >> 6 == 3 {
                evex(b, i, m64, &p)
            } else {
                // BOUND r, m.
                if p.rep != 0 || p.lock {
                    return Decoded::Invalid;
                }
                finish(b, i + 1, true, addr16, 0, ODD)
            }
        }
        0x8F if (at!(b, i + 1) >> 3) & 7 != 0 => xop(b, i, m64, &p),
        // ARPL (MOVSXD in 64-bit mode).
        0x63 if !m64 => match finish(b, i + 1, true, addr16, 0, ODD) {
            Decoded::Insn { len, ext } if !p.lock && p.rep == 0 => Decoded::Insn { len, ext },
            Decoded::Insn { .. } => Decoded::Invalid,
            other => other,
        },
        _ => {
            let rexw = p.rex & 0x08 != 0;
            legacy(b, i, m64, &p, rexw, false)
        }
    };
    match r {
        Decoded::Insn { len, ext } => Decoded::Insn { len, ext: ext | odd },
        other => other,
    }
}

/// Immediate size of a 16/32-bit ("z") operand.
fn iz(p: &Prefixes, rexw: bool) -> usize {
    if !rexw && p.opsz {
        2
    } else {
        4
    }
}

/// Size of a near relative branch displacement (E8, E9, 0F 8x).
fn rel(p: &Prefixes, m64: bool) -> usize {
    if !m64 && p.opsz {
        2
    } else {
        4
    }
}

/// Whether LOCK is allowed on this opcode (the memory operand is checked by the caller).
fn lockable(map1: bool, op: u8, reg: u8) -> bool {
    if map1 {
        match op {
            0xAB | 0xB3 | 0xBB | 0xB0 | 0xB1 | 0xC0 | 0xC1 => true,
            0xBA => reg >= 4,
            0xC7 => reg == 1,
            _ => false,
        }
    } else {
        match op {
            0x00 | 0x01 | 0x08 | 0x09 | 0x10 | 0x11 | 0x18 | 0x19 | 0x20 | 0x21 | 0x28 | 0x29
            | 0x30 | 0x31 | 0x86 | 0x87 => true,
            0x80 | 0x81 | 0x83 => reg != 7,
            0xF6 | 0xF7 => reg == 2 || reg == 3,
            0xFE | 0xFF => reg <= 1,
            _ => false,
        }
    }
}

/// Legacy (non-VEX) instruction with its opcode at `b[i]`. With `map1_direct`
/// (REX2.M0 = 1) `b[i]` is already a 0F-map opcode.
fn legacy(b: &[u8], i: usize, m64: bool, p: &Prefixes, rexw: bool, map1_direct: bool) -> Decoded {
    let addr16 = !m64 && p.adsz;
    let c = b[i];
    if !map1_direct && c != 0x0F {
        // One-byte map.
        let f = MAP0[c as usize];
        if f & X != 0 || (m64 && f & N64 != 0) {
            return Decoded::Invalid;
        }
        let mut ext = if f & R != 0 { ODD } else { 0 };
        let (has_modrm, imm) = if f & S != 0 {
            match c {
                0xA0..=0xA3 => (false, if m64 { if p.adsz { 4 } else { 8 } } else if p.adsz { 2 } else { 4 }),
                0xB8..=0xBF => (false, if m64 && rexw { 8 } else { iz(p, rexw) }),
                0xC8 => (false, 3),
                0x9A | 0xEA => (false, if p.opsz { 4 } else { 6 }),
                0xE8 | 0xE9 => {
                    if m64 && p.opsz {
                        ext |= ODD; // operand-size prefix on a near branch
                    }
                    (false, rel(p, m64))
                }
                0xF6 | 0xF7 => {
                    let reg = (at!(b, i + 1) >> 3) & 7;
                    let imm = match (c, reg) {
                        (0xF6, 0) => 1,
                        (0xF7, 0) => iz(p, rexw),
                        (_, 1) => return Decoded::Invalid, // undocumented TEST alias
                        _ => 0,
                    };
                    (true, imm)
                }
                // 62 / C4 / C5 in their legacy meaning are handled by the caller.
                _ => return Decoded::Invalid,
            }
        } else {
            (f & M != 0, if f & I8 != 0 { 1 } else if f & IZ != 0 { iz(p, rexw) } else if f & I16 != 0 { 2 } else { 0 })
        };
        if has_modrm {
            let m = at!(b, i + 1);
            let (md, reg) = (m >> 6, (m >> 3) & 7);
            let valid = match c {
                0x8D => md != 3,
                0x8C | 0x8E => reg < 6,
                0x8F => reg == 0,
                0xC6 | 0xC7 => reg == 0 || m == 0xF8,
                0xFE => reg <= 1,
                0xFF => reg != 7 && !((reg == 3 || reg == 5) && md == 3),
                _ => true,
            };
            if !valid {
                return Decoded::Invalid;
            }
            if p.lock && (md == 3 || !lockable(false, c, reg)) {
                return Decoded::Invalid;
            }
            if (c == 0xC6 || c == 0xC7) && m == 0xF8 {
                ext |= TSX; // XABORT / XBEGIN
            }
            if c == 0x00 && m == 0x00 {
                ext |= ODD; // add %al,(%rax): zero bytes
            }
        } else if p.lock {
            return Decoded::Invalid;
        }
        return finish(b, i + 1, has_modrm, addr16, imm, ext);
    }

    // 0F map (and the 0F38 / 0F3A escapes).
    let (op, opi) = if map1_direct { (c, i) } else { (at!(b, i + 1), i + 1) };
    let mp = p.mandatory();
    if op == 0x38 || op == 0x3A {
        let op3 = at!(b, opi + 1);
        let m = at!(b, opi + 2);
        if p.lock {
            return Decoded::Invalid;
        }
        let defined = if op == 0x38 { &LEGACY_0F38[mp] } else { &LEGACY_0F3A[mp] };
        if !has(defined, op3) {
            return Decoded::Invalid;
        }
        let ext = if op == 0x38 { class_0f38(op3, mp) } else { class_0f3a(op3, mp) };
        let Some(ext) = ext else {
            return Decoded::Invalid;
        };
        let _ = m;
        return finish(b, opi + 2, true, addr16, usize::from(op == 0x3A), ext);
    }
    let f = MAP1[op as usize];
    if f & X != 0 {
        return Decoded::Invalid;
    }
    let (has_modrm, imm) = if f & S != 0 {
        match op {
            0x0F => (true, 1),
            0x78 => (true, if mp == 1 || mp == 3 { 2 } else { 0 }),
            0x80..=0x8F => {
                if m64 && p.opsz {
                    return match finish(b, opi + 1, false, addr16, rel(p, m64), ODD) {
                        Decoded::Insn { len, ext } => Decoded::Insn { len, ext },
                        other => other,
                    };
                }
                (false, rel(p, m64))
            }
            _ => return Decoded::Invalid,
        }
    } else {
        (f & M != 0, usize::from(f & I8 != 0))
    };
    let mut ext = if f & R != 0 { ODD } else { 0 };
    if has_modrm {
        let m = at!(b, opi + 1);
        let (md, reg) = (m >> 6, (m >> 3) & 7);
        if p.lock && (md == 3 || !lockable(true, op, reg)) {
            return Decoded::Invalid;
        }
        match class_0f(op, mp, m) {
            Some(e) => ext |= e,
            None => return Decoded::Invalid,
        }
    } else {
        if p.lock {
            return Decoded::Invalid;
        }
        if op == 0x77 {
            if mp != 0 {
                return Decoded::Invalid;
            }
            ext = MMX; // EMMS
        }
    }
    finish(b, opi + 1, has_modrm, addr16, imm, ext)
}

/// APX REX2 prefix (64-bit mode only).
fn rex2(b: &[u8], i: usize, p: &Prefixes) -> Decoded {
    if p.rex != 0 {
        return Decoded::Invalid;
    }
    let payload = at!(b, i + 1);
    let op = at!(b, i + 2);
    let m0 = payload & 0x80 != 0;
    let w = payload & 0x08 != 0;
    // Payload: M0 R4 X4 B4 W R3 X3 B3. Assemblers emit REX2 only to reach
    // r16-r31 (R4/X4/B4), for PUSHP/POPP (W on 50-5F) and for JMPABS; any
    // other REX2 is pointless and does not occur in real code.
    let useful = payload & 0x70 != 0 || (!m0 && w && matches!(op, 0x50..=0x5F)) || (!m0 && !w && op == 0xA1);
    let r = if m0 {
        // Rows 3 (incl. the 0F38/0F3A escapes) and 8 (Jcc rel32) of map 1 are #UD with REX2.
        if matches!(op, 0x30..=0x3F | 0x80..=0x8F) {
            return Decoded::Invalid;
        }
        legacy(b, i + 2, true, p, w, true)
    } else {
        match op {
            // JMPABS: REX2 (W=0) A1 imm64.
            0xA1 if !w => finish(b, i + 3, false, false, 8, 0),
            0x0F | 0x40..=0x4F | 0x70..=0x7F | 0xA0..=0xAF | 0xE0..=0xEF => return Decoded::Invalid,
            0x62 | 0xC4 | 0xC5 | 0xD5 => return Decoded::Invalid,
            _ => legacy(b, i + 2, true, p, w, false),
        }
    };
    match r {
        Decoded::Insn { len, ext } if useful => Decoded::Insn { len, ext: ext | APX },
        Decoded::Insn { len, ext } => Decoded::Insn { len, ext: ext | ODD },
        other => other,
    }
}

/// VEX2 (C5) / VEX3 (C4).
fn vex(b: &[u8], i: usize, m64: bool, p: &Prefixes) -> Decoded {
    if p.opsz || p.rep != 0 || p.lock || p.rex != 0 {
        return Decoded::Invalid;
    }
    let addr16 = !m64 && p.adsz;
    let b1 = at!(b, i + 1);
    let (map, w, l, pp, opi) = if b[i] == 0xC5 {
        (1u8, false, (b1 >> 2) & 1, b1 & 3, i + 2)
    } else {
        let b2 = at!(b, i + 2);
        (b1 & 0x1F, b2 & 0x80 != 0, (b2 >> 2) & 1, b2 & 3, i + 3)
    };
    let op = at!(b, opi);
    if !(1..=3).contains(&map) || !has(&VEX_OPS[usize::from(map - 1) * 4 + usize::from(pp)], op) {
        return Decoded::Invalid;
    }
    let has_modrm = !(map == 1 && op == 0x77);
    let modrm = if has_modrm { at!(b, opi + 1) } else { 0 };
    let imm = match map {
        1 => usize::from(matches!(op, 0x70..=0x73 | 0xC2 | 0xC4..=0xC6)),
        2 => 0,
        3 => 1,
        _ => return Decoded::Invalid,
    };
    let Some(ext) = class_vex(map, pp, op, l, w, modrm) else {
        return Decoded::Invalid;
    };
    finish(b, opi + 1, has_modrm, addr16, imm, ext)
}

/// EVEX (62). AVX-512 needs P0 bit 3 = 0 and P1 bit 2 = 1; with APX these
/// bits carry B4 / ~X4 (extended GPRs), and map 4 holds APX-promoted legacy
/// instructions.
fn evex(b: &[u8], i: usize, m64: bool, p: &Prefixes) -> Decoded {
    if p.opsz || p.rep != 0 || p.lock || p.rex != 0 {
        return Decoded::Invalid;
    }
    let addr16 = !m64 && p.adsz;
    let p0 = at!(b, i + 1);
    let p1 = at!(b, i + 2);
    let p2 = at!(b, i + 3);
    let op = at!(b, i + 4);
    let modrm = at!(b, i + 5);
    let map = p0 & 7;
    let b4 = p0 & 0x08 != 0;
    let x4 = p1 & 0x04 == 0;
    let egpr = b4 || x4;
    if !m64 && (egpr || map == 4) {
        return Decoded::Invalid;
    }
    if map != 4 {
        let row = match map {
            1..=3 => usize::from(map - 1),
            5 | 6 => usize::from(map - 2),
            _ => return Decoded::Invalid,
        };
        if !has(&EVEX_OPS[row * 4 + usize::from(p1 & 3)], op) {
            return Decoded::Invalid;
        }
        // P2: z L'L b V' aaa. L'L = 11 only encodes rounding (b = 1, register
        // form); zeroing needs a mask register.
        let (z, ll, bc, aaa) = (p2 >> 7, (p2 >> 5) & 3, (p2 >> 4) & 1, p2 & 7);
        if (ll == 3 && !(bc == 1 && modrm >> 6 == 3)) || (z == 1 && aaa == 0) {
            return Decoded::Invalid;
        }
    } else if p2 & 0xE0 != 0 {
        // Promoted legacy instructions: no zeroing, no vector length.
        return Decoded::Invalid;
    }
    // Extended GPRs in a vector instruction exist only with APX.
    let vec = if egpr { APX } else { AVX512 };
    // EVEX map 2 F0-FF / map 3 F0 hold no AVX-512 instructions: they are the
    // APX promotions of the VEX GPR instructions (BMI1/BMI2 and friends).
    let pp = p1 & 3;
    let promoted = |m: u8| APX | class_vex(m, pp, op, 0, p1 & 0x80 != 0, modrm).unwrap_or(0);
    let (imm, ext) = match map {
        1 => (usize::from(matches!(op, 0x70..=0x73 | 0xC2 | 0xC4..=0xC6)), vec),
        2 if op >= 0xF0 => (0, promoted(2)),
        3 if op == 0xF0 => (1, promoted(3)),
        2 | 5 | 6 => (0, vec),
        3 => (1, vec),
        4 => {
            // APX promoted legacy map: immediates follow the legacy opcodes.
            let reg = (modrm >> 3) & 7;
            let w = p1 & 0x80 != 0;
            let pp = p1 & 3;
            let z = if pp == 1 && !w { 2 } else { 4 };
            let imm = match op {
                0x24 | 0x2C | 0x6B | 0x80 | 0x83 | 0xC0 | 0xC1 => 1,
                0x69 | 0x81 => z,
                0xF6 if reg <= 1 => 1,
                0xF7 if reg <= 1 => z,
                _ => 0,
            };
            (imm, APX)
        }
        _ => return Decoded::Invalid,
    };
    finish(b, i + 5, true, addr16, imm, ext)
}

/// AMD XOP (8F with ModRM.reg != 0): decoded for length, not reported.
fn xop(b: &[u8], i: usize, m64: bool, p: &Prefixes) -> Decoded {
    if p.opsz || p.rep != 0 || p.lock || p.rex != 0 {
        return Decoded::Invalid;
    }
    let addr16 = !m64 && p.adsz;
    let map = at!(b, i + 1) & 0x1F;
    let _ = at!(b, i + 2);
    let imm = match map {
        8 => 1,
        9 => 0,
        0xA => 4,
        _ => return Decoded::Invalid,
    };
    finish(b, i + 4, true, addr16, imm, 0)
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Marker for an undefined mandatory-prefix combination.
const U: u64 = u64::MAX;

/// Legacy 0F map. `mp`: 0 none, 1 = 66, 2 = F3, 3 = F2. `None` = invalid.
fn class_0f(op: u8, mp: usize, modrm: u8) -> Option<u64> {
    let md = modrm >> 6;
    let reg = (modrm >> 3) & 7;
    // [none, 66, F3, F2]
    let t: [u64; 4] = match op {
        0x01 => match modrm {
            0xD5 | 0xD6 => [TSX; 4], // XEND, XTEST
            // XGETBV, RDTSCP, RDPKRU/WRPKRU, SERIALIZE, ENCLU, UIRET/TESTUI/CLUI/STUI
            0xD0 | 0xF9 | 0xEE | 0xEF | 0xE8 | 0xD7 | 0xEC..=0xED | 0xC6 => [0; 4],
            _ => [ODD; 4], // LGDT/SGDT/.../VMCALL/SWAPGS/...
        },
        0x10 | 0x11 => [SSE, SSE2, SSE, SSE2],
        0x12 => [SSE, SSE2, SSE3, SSE3],
        0x13 | 0x14 | 0x15 | 0x17 | 0x28 | 0x29 | 0x2E | 0x2F | 0x50 | 0x54..=0x57 | 0xC6 => {
            [SSE, SSE2, U, U]
        }
        0x16 => [SSE, SSE2, SSE3, U],
        0x1E => match (mp, modrm) {
            (2, 0xFA | 0xFB) => [CET; 4],             // ENDBR64 / ENDBR32
            (2, _) if md == 3 && reg == 1 => [CET; 4], // RDSSPD/Q
            _ => [0; 4],
        },
        0x2A | 0x2C | 0x2D | 0x51 | 0x58 | 0x59 | 0x5C..=0x5F | 0xC2 => [SSE, SSE2, SSE, SSE2],
        0x2B => [SSE, SSE2, 0, 0], // F3/F2: AMD SSE4a MOVNTSS/SD
        0x52 | 0x53 => [SSE, U, SSE, U],
        0x5A => [SSE2; 4],
        0x5B => [SSE2, SSE2, SSE2, U],
        0x60..=0x6B | 0x74..=0x76 => [MMX, SSE2, U, U],
        0x6C | 0x6D => [U, SSE2, U, U],
        0x6E => [MMX, SSE2, U, U],
        0x6F | 0x7E | 0x7F => [MMX, SSE2, SSE2, U],
        0x70 => [SSE, SSE2, SSE2, SSE2],
        0x71..=0x73 => {
            // Shift-by-immediate groups: register operand, defined /reg only.
            let ok = md == 3
                && match (op, mp) {
                    (0x71 | 0x72, 0 | 1) => matches!(reg, 2 | 4 | 6),
                    (0x73, 0) => matches!(reg, 2 | 6),
                    (0x73, 1) => matches!(reg, 2 | 3 | 6 | 7),
                    _ => false,
                };
            if !ok {
                return None;
            }
            [MMX, SSE2, U, U]
        }
        0x78 | 0x79 => [0, 0, U, 0], // VMREAD/VMWRITE, AMD EXTRQ/INSERTQ
        0x7C | 0x7D | 0xD0 => [U, SSE3, U, SSE3],
        0xAE => match (mp, md, reg) {
            (0, 3, 5 | 6) => [SSE2; 4], // LFENCE, MFENCE
            (0, 3, 7) => [SSE; 4],      // SFENCE
            (0, 0..=2, 2 | 3) => [SSE; 4], // LDMXCSR, STMXCSR
            (2, 3, 5) => [CET; 4],      // INCSSP
            _ => [0; 4],
        },
        0xB8 => [U, U, POPCNT, U], // without F3: JMPE (IA-64 only)
        0xBA => {
            if reg < 4 {
                return None;
            }
            [0; 4]
        }
        0xBD => [0, 0, LZCNT, 0],
        0xC3 => [SSE2, U, U, U], // MOVNTI
        0xC4 | 0xC5 => [SSE, SSE2, U, U],
        0xC7 => match (md, reg) {
            (3, 6) => [RDRAND, RDRAND, 0, U], // F3: SENDUIPI
            (3, 7) => [RDSEED, RDSEED, 0, U], // F3: RDPID
            (3, _) => return None,
            (_, 0 | 2) => return None,
            _ => [0; 4],
        },
        0xD1..=0xD3 | 0xD5 | 0xD8 | 0xD9 | 0xDB..=0xDD | 0xDF | 0xE1 | 0xE2 | 0xE5 | 0xE8
        | 0xE9 | 0xEB..=0xED | 0xEF | 0xF1..=0xF3 | 0xF5 | 0xF8..=0xFA | 0xFC..=0xFE => {
            [MMX, SSE2, U, U]
        }
        0xD4 | 0xF4 | 0xFB => [SSE2, SSE2, U, U],
        0xD6 => [U, SSE2, SSE2, SSE2],
        0xD7 | 0xDA | 0xDE | 0xE0 | 0xE3 | 0xE4 | 0xE7 | 0xEA | 0xEE | 0xF6 | 0xF7 => {
            [SSE, SSE2, U, U]
        }
        0xE6 => [U, SSE2, SSE2, SSE2],
        0xF0 => [U, U, U, SSE3], // LDDQU
        _ => [0; 4],
    };
    let e = t[mp];
    if e == U {
        None
    } else {
        Some(e)
    }
}

/// Legacy 0F 38 map.
fn class_0f38(op: u8, mp: usize) -> Option<u64> {
    Some(match (op, mp) {
        (0x00..=0x0B | 0x1C..=0x1E, 0 | 1) => SSSE3,
        (0x10 | 0x14 | 0x15 | 0x17 | 0x20..=0x25 | 0x28..=0x2B | 0x30..=0x35, 1) => SSE41,
        (0x38..=0x41, 1) => SSE41,
        (0x37, 1) => SSE42,
        (0xC8..=0xCD, 0) => SHA,
        (0xCF, 1) => GFNI,
        (0xDB..=0xDF, 1) => AES,
        (0xF0 | 0xF1, 3) => SSE42, // CRC32
        (0xF0 | 0xF1, 0 | 1) => MOVBE,
        (0xF6, 1 | 2) => ADX,
        (0x00..=0x0B | 0x1C..=0x1E | 0x10..=0x41 | 0xC8..=0xCF | 0xDB..=0xDF, _) => return None,
        _ => 0,
    })
}

/// Legacy 0F 3A map.
fn class_0f3a(op: u8, mp: usize) -> Option<u64> {
    Some(match (op, mp) {
        (0x0F, 0 | 1) => SSSE3, // PALIGNR
        (0x08..=0x0E | 0x14..=0x17 | 0x20..=0x22 | 0x40..=0x42, 1) => SSE41,
        (0x44, 1) => PCLMUL,
        (0x60..=0x63, 1) => SSE42,
        (0xCC, 0) => SHA,
        (0xCE | 0xCF, 1) => GFNI,
        (0xDF, 1) => AES,
        (0x08..=0x0F | 0x14..=0x17 | 0x20..=0x22 | 0x40..=0x44 | 0x60..=0x63 | 0xDF, _) => {
            return None
        }
        _ => 0,
    })
}

/// VEX-encoded instructions. `None` = undefined (map 1 only; unknown 0F38 /
/// 0F3A VEX opcodes are accepted without evidence, as new ones keep appearing).
fn class_vex(map: u8, pp: u8, op: u8, l: u8, _w: bool, modrm: u8) -> Option<u64> {
    let md = modrm >> 6;
    let reg = (modrm >> 3) & 7;
    // Integer SIMD: AVX at 128 bits, AVX2 at 256 bits.
    let int = if l == 1 { AVX2 } else { AVX };
    let p66 = pp == 1;
    Some(match map {
        1 => match op {
            0x10..=0x17 | 0x28..=0x2F | 0x50..=0x5F | 0x7C | 0x7D | 0xC2 | 0xC6 | 0xD0 | 0xE6 => AVX,
            0x6E | 0x6F | 0x7E | 0x7F | 0xC4 | 0xC5 | 0xD6 | 0xE7 | 0xF0 | 0xF7 => AVX,
            0x77 if pp == 0 => AVX, // VZEROUPPER / VZEROALL
            0xAE if pp == 0 && md != 3 && (reg == 2 || reg == 3) => AVX, // VLDMXCSR / VSTMXCSR
            // AVX-512 opmask instructions are VEX-encoded.
            0x41 | 0x42 | 0x44..=0x47 | 0x4A | 0x4B | 0x90..=0x93 | 0x98 | 0x99 => AVX512,
            0x70 if pp != 0 => int,
            0x60..=0x6D | 0x71..=0x76 | 0xD1..=0xD5 | 0xD7..=0xDF | 0xE0..=0xE5 | 0xE8..=0xEF
            | 0xF1..=0xF6 | 0xF8..=0xFE
                if p66 =>
            {
                int
            }
            _ => return None,
        },
        2 => match op {
            _ if matches!(op, 0x00..=0x0B | 0x1C..=0x1E | 0x20..=0x25 | 0x28..=0x2B | 0x30..=0x35 | 0x37..=0x40)
                && p66 =>
            {
                int
            }
            0x0C..=0x0F | 0x17 | 0x1A | 0x2C..=0x2F | 0x41 if p66 => AVX,
            0x13 if p66 => F16C | AVX,
            0x18 | 0x19 if p66 => {
                if md == 3 {
                    AVX2
                } else {
                    AVX
                }
            }
            0x16 | 0x36 | 0x45..=0x47 | 0x58..=0x5A | 0x78 | 0x79 | 0x8C | 0x8E | 0x90..=0x93
                if p66 =>
            {
                AVX2
            }
            0x96..=0x9F | 0xA6..=0xAF | 0xB6..=0xBF if p66 => FMA,
            0x50..=0x53 => AVXVNNI,
            0x49 | 0x4B | 0x5C | 0x5E => AMX,
            0xCF if p66 => GFNI | AVX,
            0xDB if p66 => AES | AVX,
            0xDC..=0xDF if p66 => {
                if l == 1 {
                    VAES | AVX
                } else {
                    AES | AVX
                }
            }
            0xF2 if pp == 0 => BMI1,                     // ANDN
            0xF3 if pp == 0 && matches!(reg, 1..=3) => BMI1, // BLSR / BLSMSK / BLSI
            0xF3 => return None,
            0xF5 if pp != 1 => BMI2,                     // BZHI / PEXT / PDEP
            0xF6 if pp == 3 => BMI2,                     // MULX
            0xF7 if pp == 0 => BMI1,                     // BEXTR
            0xF7 => BMI2,                                // SHLX / SARX / SHRX
            _ => 0,
        },
        3 => match op {
            0x00..=0x02 | 0x38 | 0x39 | 0x46 if p66 => AVX2,
            0x04..=0x06 | 0x08..=0x0D | 0x14..=0x19 | 0x20..=0x22 | 0x40 | 0x41 | 0x4A | 0x4B
            | 0x60..=0x63
                if p66 =>
            {
                AVX
            }
            0x0E | 0x0F | 0x42 | 0x4C if p66 => int,
            0x1D if p66 => F16C | AVX,
            0x30..=0x33 if p66 => AVX512, // KSHIFT
            0x44 if p66 => {
                if l == 1 {
                    VPCLMUL | AVX
                } else {
                    PCLMUL | AVX
                }
            }
            0xCE | 0xCF if p66 => GFNI | AVX,
            0xDF if p66 => AES | AVX,
            0xF0 if pp == 3 => BMI2, // RORX
            _ => 0,
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::test_util::{detect, hits, repeat};

    /// Length and evidence bits (without the ODD marker) of one instruction.
    fn one(bytes: &[u8], m64: bool) -> (usize, u64) {
        match decode(bytes, m64) {
            Decoded::Insn { len, ext } => (len, ext & !ODD),
            other => panic!("{bytes:02X?}: {other:?}"),
        }
    }

    fn is_odd(bytes: &[u8], m64: bool) -> bool {
        matches!(decode(bytes, m64), Decoded::Insn { ext, .. } if ext & ODD != 0)
    }

    /// (bytes, expected evidence) pairs, encodings from `llvm-mc -triple=x86_64 -show-encoding`.
    #[rustfmt::skip]
    const X64: &[(&[u8], u64)] = &[
        (&[0xc5, 0xec, 0x58, 0xd9], AVX),                          // vaddps %ymm1,%ymm2,%ymm3
        (&[0xc5, 0xed, 0xfe, 0xd9], AVX2),                         // vpaddd %ymm1,%ymm2,%ymm3
        (&[0xc5, 0xe9, 0xfe, 0xd9], AVX),                          // vpaddd %xmm1,%xmm2,%xmm3
        (&[0xc4, 0xe2, 0x6d, 0xb8, 0xd9], FMA),                    // vfmadd231ps %ymm1,%ymm2,%ymm3
        (&[0x62, 0xf1, 0x6c, 0x48, 0x58, 0xd9], AVX512),           // vaddps %zmm1,%zmm2,%zmm3
        (&[0xc5, 0xf8, 0x92, 0xc8], AVX512),                       // kmovw %eax,%k1
        (&[0xc4, 0xe2, 0x60, 0xf2, 0xc8], BMI1),                   // andn %eax,%ebx,%ecx
        (&[0xc4, 0xe3, 0x7b, 0xf0, 0xd8, 0x03], BMI2),             // rorx $3,%eax,%ebx
        (&[0xf3, 0x0f, 0xbc, 0xd8], 0),                            // tzcnt = rep bsf: no evidence
        (&[0xf3, 0x0f, 0xbd, 0xd8], LZCNT),                        // lzcnt %eax,%ebx
        (&[0xf3, 0x0f, 0xb8, 0xd8], POPCNT),                       // popcnt %eax,%ebx
        (&[0xf2, 0x48, 0x0f, 0x38, 0xf1, 0xd8], SSE42),            // crc32q %rax,%rbx
        (&[0xf2, 0x0f, 0x38, 0xf0, 0xd8], SSE42),                  // crc32b %al,%ebx
        (&[0x66, 0xf2, 0x0f, 0x38, 0xf1, 0xd8], SSE42),            // crc32w %ax,%ebx
        (&[0x0f, 0x38, 0xf0, 0x18], MOVBE),                        // movbe (%rax),%ebx
        (&[0x66, 0x0f, 0x38, 0xf6, 0xd8], ADX),                    // adcx %eax,%ebx
        (&[0xf3, 0x0f, 0x38, 0xf6, 0xd8], ADX),                    // adox %eax,%ebx
        (&[0x0f, 0xc7, 0xf0], RDRAND),                             // rdrand %eax
        (&[0x0f, 0xc7, 0xf8], RDSEED),                             // rdseed %eax
        (&[0xf3, 0x0f, 0xc7, 0xf8], 0),                            // rdpid %rax
        (&[0xf3, 0x0f, 0x1e, 0xfa], CET),                          // endbr64
        (&[0xf3, 0x0f, 0x1e, 0xfb], CET),                          // endbr32
        (&[0x66, 0x0f, 0x38, 0xdc, 0xd1], AES),                    // aesenc %xmm1,%xmm2
        (&[0xc4, 0xe2, 0x6d, 0xdc, 0xd9], VAES | AVX),             // vaesenc %ymm1,%ymm2,%ymm3
        (&[0xc4, 0xe2, 0x69, 0xdc, 0xd9], AES | AVX),              // vaesenc %xmm1,%xmm2,%xmm3
        (&[0x66, 0x0f, 0x3a, 0x44, 0xd1, 0x00], PCLMUL),           // pclmulqdq $0,%xmm1,%xmm2
        (&[0x0f, 0x38, 0xcb, 0xd1], SHA),                          // sha256rnds2 %xmm0,%xmm1,%xmm2
        (&[0x0f, 0x3a, 0xcc, 0xd1, 0x01], SHA),                    // sha1rnds4 $1,%xmm1,%xmm2
        (&[0xc7, 0xf8, 0x00, 0x00, 0x00, 0x00], TSX),              // xbegin
        (&[0x0f, 0x01, 0xd5], TSX),                                // xend
        (&[0x0f, 0x01, 0xd6], TSX),                                // xtest
        (&[0xc4, 0xe2, 0x75, 0x90, 0x1c, 0x90], AVX2),             // vpgatherdd %ymm1,(%rax,%ymm2,4),%ymm3
        (&[0xc5, 0xf8, 0x77], AVX),                                // vzeroupper
        (&[0xc4, 0xe2, 0x7d, 0x13, 0xd1], F16C | AVX),             // vcvtph2ps %xmm1,%ymm2
        (&[0xc4, 0xe2, 0x7b, 0x4b, 0x0c, 0x18], AMX),              // tileloadd (%rax,%rbx),%tmm1
        (&[0xc4, 0xe2, 0x6d, 0x50, 0xd9], AVXVNNI),                // {vex} vpdpbusd %ymm1,%ymm2,%ymm3
        (&[0x62, 0xf2, 0x6d, 0x28, 0x50, 0xd9], AVX512),           // vpdpbusd (EVEX)
        (&[0xd5, 0x58, 0x01, 0xc1], APX),                          // addq %r16,%r17
        (&[0x62, 0xec, 0xec, 0x10, 0x01, 0xc1], APX),              // addq %r16,%r17,%r18
        (&[0x62, 0xf4, 0xfc, 0x0c, 0x01, 0xc3], APX),              // {nf} addq %rax,%rbx
        (&[0x62, 0xfc, 0x74, 0x10, 0xff, 0xf0], APX),              // push2 %r16,%r17
        (&[0x62, 0xe2, 0xa7, 0x08, 0xf7, 0xd6], APX | BMI2),       // shrx (EVEX, r16+)
        (&[0x62, 0x43, 0x7f, 0x08, 0xf0, 0xdf, 0x02], APX | BMI2), // rorx (EVEX, r16+)
        (&[0x62, 0xf9, 0x6c, 0x48, 0x58, 0x18], APX),              // vaddps (%r16),%zmm2,%zmm3
        (&[0x62, 0xf1, 0x68, 0x48, 0x58, 0x1c, 0x88], APX),        // vaddps (%rax,%r17,4),%zmm2,%zmm3
        (&[0xd5, 0x00, 0xa1, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12], APX), // jmpabs
        (&[0xd5, 0x18, 0x50], APX),                                // pushp %r16
        (&[0xd5, 0x90, 0x10, 0x0c, 0x24], SSE | APX),              // movups (%r20),%xmm1
        (&[0x0f, 0x28, 0xc1], SSE),                                // movaps %xmm1,%xmm0
        (&[0x66, 0x0f, 0xef, 0xc0], SSE2),                         // pxor %xmm0,%xmm0
        (&[0xf2, 0x0f, 0x58, 0xc1], SSE2),                         // addsd %xmm1,%xmm0
        (&[0xf3, 0x0f, 0x10, 0x05, 0, 0, 0, 0], SSE),              // movss 0(%rip),%xmm0
        (&[0x66, 0x0f, 0x38, 0x00, 0xc1], SSSE3),                  // pshufb %xmm1,%xmm0
        (&[0x66, 0x0f, 0x3a, 0x0f, 0xc1, 0x08], SSSE3),            // palignr $8,%xmm1,%xmm0
        (&[0x66, 0x0f, 0x38, 0x40, 0xc1], SSE41),                  // pmulld %xmm1,%xmm0
        (&[0x66, 0x0f, 0x3a, 0x0b, 0xc1, 0x04], SSE41),            // roundsd $4,%xmm1,%xmm0
        (&[0x66, 0x0f, 0x3a, 0x63, 0xc1, 0x0c], SSE42),            // pcmpistri $12,%xmm1,%xmm0
        (&[0xf2, 0x0f, 0x7c, 0xc1], SSE3),                         // haddps %xmm1,%xmm0
        (&[0x0f, 0xfe, 0xc1], MMX),                                // paddd %mm1,%mm0
        (&[0x0f, 0x77], MMX),                                      // emms
        (&[0x66, 0x0f, 0x73, 0xd8, 0x08], SSE2),                   // psrldq $8,%xmm0
        (&[0x0f, 0xae, 0xf8], SSE),                                // sfence
        (&[0x0f, 0xae, 0xf0], SSE2),                               // mfence
        (&[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00], 0),                // nopw 0(%rax,%rax)
        (&[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0], 0),       // cs nopw 0(%rax,%rax)
        (&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8], 0),                // movabs $imm64,%rax
        (&[0xf7, 0xc1, 1, 0, 0, 0], 0),                            // test $1,%ecx
        (&[0x66, 0xf7, 0xc1, 1, 0], 0),                            // test $1,%cx
        (&[0xf6, 0xc1, 1], 0),                                     // test $1,%cl
        (&[0xf7, 0xd9], 0),                                        // neg %ecx
        (&[0xa1, 1, 2, 3, 4, 5, 6, 7, 8], 0),                      // movabs 0x..,%eax
        (&[0x0f, 0x0f, 0xc1, 0x9e], 0),                            // pfadd %mm1,%mm0 (3DNow!)
        (&[0xc8, 0x10, 0x00, 0x01], 0),                            // enter $16,$1
        (&[0xf0, 0x48, 0x0f, 0xb1, 0x0a], 0),                      // lock cmpxchg %rcx,(%rdx)
        (&[0xdd, 0x44, 0x24, 0x08], 0),                            // fldl 8(%rsp)
        (&[0x8f, 0xe8, 0x78, 0xc2, 0xc1, 0x05], 0),                // vprotb $5,%xmm1,%xmm0 (XOP)
        (&[0xc4, 0xe3, 0x7d, 0x39, 0xc1, 0x01], AVX2),             // vextracti128 $1,%ymm0,%xmm1
        (&[0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b], AVX2),             // vpermq $27,%ymm1,%ymm0
        (&[0xc4, 0xe2, 0x7d, 0x58, 0xc1], AVX2),                   // vpbroadcastd %xmm1,%ymm0
        (&[0xc4, 0xe2, 0x7d, 0x18, 0x00], AVX),                    // vbroadcastss (%rax),%ymm0
        (&[0xc4, 0xe2, 0x7d, 0x18, 0xc1], AVX2),                   // vbroadcastss %xmm1,%ymm0
        (&[0xc4, 0xe2, 0x71, 0x47, 0xc2], AVX2),                   // vpsllvd %xmm2,%xmm1,%xmm0
        (&[0xc4, 0xe2, 0x6b, 0xf6, 0xc1], BMI2),                   // mulx %ecx,%edx,%eax
        (&[0xc4, 0xe2, 0x70, 0xf3, 0xc8], BMI1),                   // blsr %eax,%ecx
    ];

    #[test]
    fn x86_64_encodings() {
        for &(bytes, want) in X64 {
            let (len, ext) = one(bytes, true);
            assert_eq!(len, bytes.len(), "length of {bytes:02X?}");
            assert_eq!(ext, want, "evidence of {bytes:02X?}");
        }
    }

    #[test]
    fn i386_vex_les_lds_bound() {
        // 32-bit: C5 with mod=11 next is VEX.
        assert_eq!(one(&[0xc5, 0xec, 0x58, 0xd9], false), (4, AVX));
        // C5 / C4 with mod != 11 is LDS / LES.
        assert_eq!(one(&[0xc5, 0x06], false), (2, 0)); // lds (%esi),%eax
        assert_eq!(one(&[0xc4, 0x45, 0x08], false), (3, 0)); // les 8(%ebp),%eax
        assert_eq!(one(&[0xc4, 0x04, 0x24], false), (3, 0)); // les (%esp),%eax
        // 62 with mod != 11 is BOUND.
        assert_eq!(one(&[0x62, 0x06], false), (2, 0)); // bound %eax,(%esi)
        assert_eq!(one(&[0x62, 0x44, 0x24, 0x08], false), (4, 0)); // bound %eax,8(%esp)
        // 62 with mod = 11 in 32-bit mode is EVEX.
        assert_eq!(one(&[0x62, 0xf1, 0x6c, 0x48, 0x58, 0xd9], false), (6, AVX512));
        // EVEX with APX bits is invalid in 32-bit mode.
        assert_eq!(decode(&[0x62, 0xf9, 0x6c, 0x48, 0x58, 0x18], false), Decoded::Invalid);
        // D5 is AAD imm8 in 32-bit mode.
        assert_eq!(one(&[0xd5, 0x0a], false), (2, 0));
        // 16-bit operand / address size.
        assert_eq!(one(&[0x66, 0xe8, 0x00, 0x00], false), (4, 0)); // call rel16
        assert_eq!(one(&[0x67, 0x8b, 0x46, 0x08], false), (4, 0)); // mov 8(%bp),%eax
        assert_eq!(one(&[0x67, 0x8b, 0x06, 0x34, 0x12], false), (5, 0)); // mov 0x1234,%eax (addr16)
        assert_eq!(one(&[0x9a, 1, 2, 3, 4, 5, 6], false), (7, 0)); // lcall $0x605,$0x4030201
        assert_eq!(one(&[0x40], false), (1, 0)); // inc %eax
        // Decoded, but not something compiled code contains.
        for odd in [&[0xc5, 0x06][..], &[0xc4, 0x45, 0x08], &[0x62, 0x06], &[0x9a, 1, 2, 3, 4, 5, 6], &[0x27], &[0x1e], &[0xe4, 0x60], &[0x26, 0x8b, 0x00], &[0x63, 0xc8]] {
            assert!(is_odd(odd, false), "{odd:02X?}");
        }
        for ok in [&[0x0f, 0x31][..], &[0x0f, 0xa2], &[0xcd, 0x80], &[0x65, 0xa1, 0x14, 0, 0, 0], &[0x0f, 0x01, 0xd0], &[0x40], &[0xc5, 0xec, 0x58, 0xd9]] {
            assert!(!is_odd(ok, false), "{ok:02X?}");
        }
        assert!(is_odd(&[0x0f, 0x01, 0x15, 0, 0, 0, 0], true)); // lgdt
        assert!(is_odd(&[0x0f, 0x22, 0xd8], true)); // mov %rax,%cr3
        assert!(!is_odd(&[0x48, 0x63, 0xc8], true)); // movslq %eax,%rcx
        assert!(!is_odd(&[0x0f, 0x05], true)); // syscall
    }

    #[test]
    fn invalid_encodings() {
        for bytes in [
            &[0x06][..],                  // push %es in 64-bit mode
            &[0x0f, 0x0b][..],            // (valid: ud2) - checked below
            &[0x66, 0xc5, 0xf8, 0x77][..], // 66 before VEX
            &[0x48, 0xc5, 0xf8, 0x77][..], // REX before VEX
            &[0xf0, 0x01, 0xc8][..],      // lock add %ecx,%eax (register destination)
            &[0xf0, 0x90][..],            // lock nop
            &[0xfe, 0xd0][..],            // FE /2
            &[0xff, 0xf8][..],            // FF /7
            &[0x8d, 0xc0][..],            // lea with register operand
            &[0xf3, 0x0f, 0x28, 0xc1][..], // F3 before MOVAPS
            &[0x0f, 0x04][..],
            &[0xd6][..],
        ] {
            if bytes == [0x0f, 0x0b] {
                assert_eq!(decode(bytes, true), Decoded::Insn { len: 2, ext: 0 });
                continue;
            }
            assert_eq!(decode(bytes, true), Decoded::Invalid, "{bytes:02X?}");
        }
        assert_eq!(decode(&[0xc5, 0xf8], true), Decoded::Truncated);
    }

    #[test]
    fn pointless_rex2_and_zero_bytes_are_odd() {
        assert!(is_odd(&[0xd5, 0x02, 0x00, 0x00], true)); // REX2 without r16-r31
        assert!(is_odd(&[0xd5, 0x09, 0x03, 0x49, 0x08], true));
        assert!(!is_odd(&[0xd5, 0x58, 0x01, 0xc1], true)); // addq %r16,%r17
        assert!(is_odd(&[0x00, 0x00], true));
        assert!(!is_odd(&[0x00, 0xc0], true));
        // EVEX with reserved P2 combinations.
        assert_eq!(decode(&[0x62, 0xf1, 0x6c, 0xe8, 0x58, 0x18], true), Decoded::Invalid); // L'L=11 memory
        assert_eq!(decode(&[0x62, 0xf1, 0x6c, 0xc8, 0x58, 0xd9], true), Decoded::Invalid); // z without mask
        assert_eq!(decode(&[0x62, 0xf4, 0xfc, 0x2c, 0x01, 0xc3], true), Decoded::Invalid); // map 4 with L'L
    }

    #[test]
    fn lone_d5_in_an_immediate_is_not_apx() {
        // mov $0xd5d5d5d5,%eax ; add $0xd5,%al ; mov %edx,%ebp (89 d5) - repeated.
        let unit = [0xb8, 0xd5, 0xd5, 0xd5, 0xd5, 0x04, 0xd5, 0x89, 0xd5, 0xc3];
        let code = repeat(&unit, 64 * 1024);
        assert!(!hits(&code, Isa::X86_64, Endianness::Little).iter().any(|(n, _)| *n == "APX"));
        assert!(detect(&code, Isa::X86_64, Endianness::Little).is_empty());
    }

    #[test]
    fn modrm_bytes_c4_c5_62_are_not_vex_evex() {
        // mov %eax,%ebp (89 c5); mov %eax,%esp (89 c4); add $0x62,%al;
        // movsd %xmm0,-8(%rbp)
        let unit = [0x89, 0xc5, 0x89, 0xc4, 0x04, 0x62, 0xf2, 0x0f, 0x11, 0x45, 0xf8];
        let code = repeat(&unit, 64 * 1024);
        let found = detect(&code, Isa::X86_64, Endianness::Little);
        assert_eq!(found, vec!["SSE2".to_string()]);
    }

    #[test]
    fn avx2_fma_program() {
        // vmovups (%rdi),%ymm0; vfmadd231ps (%rsi),%ymm1,%ymm0; vpaddd %ymm1,%ymm2,%ymm3;
        // vmovups %ymm0,(%rdi); add $32,%rdi; dec %ecx; jne; vzeroupper; ret
        let unit: &[u8] = &[
            0xc5, 0xfc, 0x10, 0x07, 0xc4, 0xe2, 0x75, 0xb8, 0x06, 0xc5, 0xed, 0xfe, 0xd9, 0xc5,
            0xfc, 0x11, 0x07, 0x48, 0x83, 0xc7, 0x20, 0xff, 0xc9, 0x75, 0xe5, 0xc5, 0xf8, 0x77,
            0xc3,
        ];
        let code = repeat(unit, 16 * 1024);
        let found = detect(&code, Isa::X86_64, Endianness::Little);
        assert_eq!(found, vec!["AVX", "AVX2", "FMA"]);
    }

    #[test]
    fn i386_program_with_les_lds_is_not_avx() {
        // les 8(%ebp),%eax ; lds (%esi),%edx ; bound %eax,8(%esp) ; add %eax,%ebx ; ret
        let unit: &[u8] = &[0xc4, 0x45, 0x08, 0xc5, 0x16, 0x62, 0x44, 0x24, 0x08, 0x01, 0xc3, 0xc3];
        let code = repeat(unit, 32 * 1024);
        assert!(detect(&code, Isa::X86, Endianness::Little).is_empty());
    }

    #[test]
    fn random_bytes_produce_nothing() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let data: Vec<u8> = (0..1 << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        assert!(detect(&data, Isa::X86_64, Endianness::Little).is_empty());
        assert!(detect(&data, Isa::X86, Endianness::Little).is_empty());
    }

    /// Decode one sequence per line of `EXTDET_X86_SEQ` (hex) and write
    /// `<len or -1> <odd>` per line to `EXTDET_X86_OUT`.
    #[test]
    #[ignore]
    fn decode_sequences() {
        let (Ok(inp), Ok(out)) = (std::env::var("EXTDET_X86_SEQ"), std::env::var("EXTDET_X86_OUT")) else {
            return;
        };
        let m64 = std::env::var("EXTDET_X86_MODE").map(|m| m != "32").unwrap_or(true);
        let mut res = String::new();
        for line in std::fs::read_to_string(inp).unwrap().lines() {
            let bytes: Vec<u8> = (0..line.len() / 2).map(|i| u8::from_str_radix(&line[2 * i..2 * i + 2], 16).unwrap()).collect();
            match decode(&bytes, m64) {
                Decoded::Insn { len, ext } => res.push_str(&format!("{len} {}\n", u8::from(ext & ODD != 0))),
                Decoded::Invalid => res.push_str("-1 0\n"),
                Decoded::Truncated => res.push_str("-2 0\n"),
            }
        }
        std::fs::write(out, res).unwrap();
    }

    /// Cross-check instruction boundaries against a disassembler listing.
    ///
    /// `EXTDET_X86_TEXT` = raw code bytes, `EXTDET_X86_STARTS` = one decimal
    /// instruction start offset per line (e.g. from `llvm-objdump -d`),
    /// `EXTDET_X86_MODE` = 32 or 64.
    #[test]
    #[ignore]
    fn boundaries_match_reference() {
        let (Ok(text), Ok(starts)) =
            (std::env::var("EXTDET_X86_TEXT"), std::env::var("EXTDET_X86_STARTS"))
        else {
            return;
        };
        let m64 = std::env::var("EXTDET_X86_MODE").map(|m| m != "32").unwrap_or(true);
        let code = std::fs::read(text).unwrap();
        let starts: Vec<usize> = std::fs::read_to_string(starts)
            .unwrap()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        let mut mism = 0usize;
        let mut pos = starts[0];
        let mut k = 0usize;
        let mut total = 0usize;
        while k < starts.len() && pos < code.len() {
            while k < starts.len() && starts[k] < pos {
                k += 1;
            }
            if k >= starts.len() {
                break;
            }
            if starts[k] != pos {
                if mism < 20 {
                    eprintln!(
                        "desync at {pos:#x}: expected {:#x}, bytes {:02X?}",
                        starts[k],
                        &code[pos.saturating_sub(8)..(pos + 8).min(code.len())]
                    );
                }
                mism += 1;
                pos = starts[k];
                continue;
            }
            total += 1;
            match decode(&code[pos..], m64) {
                Decoded::Insn { len, .. } => pos += len,
                other => {
                    if mism < 20 {
                        eprintln!("{other:?} at {pos:#x}: {:02X?}", &code[pos..(pos + 12).min(code.len())]);
                    }
                    mism += 1;
                    k += 1;
                    if k < starts.len() {
                        pos = starts[k];
                    }
                }
            }
        }
        eprintln!("{total} instructions, {mism} mismatches");
        assert!(mism * 10_000 <= total.max(1), "too many mismatches");
    }
}
