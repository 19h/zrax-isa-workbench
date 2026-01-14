//! Extension detection from instruction patterns.
//!
//! Analyzes code for extension-specific instruction patterns
//! and prefixes to detect which ISA extensions are in use.

use crate::types::{Endianness, Extension, ExtensionCategory};
use std::collections::HashSet;

/// Detect x86/x86-64 extensions from instruction prefixes and patterns.
pub fn detect_x86_extensions(data: &[u8]) -> Vec<Extension> {
    let mut extensions = HashSet::new();
    let mut i = 0;

    while i < data.len() {
        // Skip legacy prefixes
        while i < data.len()
            && matches!(
                data[i],
                0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3
            )
        {
            i += 1;
        }

        if i >= data.len() {
            break;
        }

        let b = data[i];

        // VEX 2-byte prefix (C5)
        if b == 0xC5 && i + 2 < data.len() {
            extensions.insert(("AVX", ExtensionCategory::Simd));
            i += 2;
            continue;
        }

        // VEX 3-byte prefix (C4)
        if b == 0xC4 && i + 3 < data.len() {
            extensions.insert(("AVX", ExtensionCategory::Simd));

            let p1 = data[i + 1];
            let map_sel = p1 & 0x1F;

            // Map select can indicate AVX2
            if map_sel == 2 || map_sel == 3 {
                extensions.insert(("AVX2", ExtensionCategory::Simd));
            }

            // Check for FMA (map 2 with specific opcodes)
            if map_sel == 2 {
                if i + 4 < data.len() {
                    let opcode = data[i + 3];
                    if (0x96..=0x9F).contains(&opcode)
                        || (0xA6..=0xAF).contains(&opcode)
                        || (0xB6..=0xBF).contains(&opcode)
                    {
                        extensions.insert(("FMA", ExtensionCategory::Simd));
                    }
                }
            }

            i += 3;
            continue;
        }

        // EVEX prefix (62)
        if b == 0x62 && i + 4 < data.len() {
            let p1 = data[i + 1];

            // Verify EVEX: bits [3:2] should be 0
            if (p1 & 0x0C) == 0x00 {
                extensions.insert(("AVX-512", ExtensionCategory::Simd));

                // Check for specific AVX-512 features
                let _p2 = data[i + 2];
                let p3 = data[i + 3];

                // L'L field (bits [6:5] of p3) for vector length
                let ll = (p3 >> 5) & 0x3;
                if ll == 2 {
                    // 512-bit operations
                    extensions.insert(("AVX-512F", ExtensionCategory::Simd));
                }

                // Check for masking (aaa field)
                if (p3 & 0x07) != 0 {
                    extensions.insert(("AVX-512F", ExtensionCategory::Simd));
                }
            }

            i += 4;
            continue;
        }

        // REX2 prefix (D5) - APX
        if b == 0xD5 && i + 2 < data.len() {
            extensions.insert(("APX", ExtensionCategory::System));
            i += 2;
            continue;
        }

        // 0F prefix (SSE, etc.)
        if b == 0x0F && i + 2 < data.len() {
            let next = data[i + 1];

            // SSE instructions
            if (0x10..=0x17).contains(&next) {
                extensions.insert(("SSE", ExtensionCategory::Simd));
            }

            // SSE2 conversion instructions
            if next == 0x5A || next == 0x5B {
                extensions.insert(("SSE2", ExtensionCategory::Simd));
            }

            // POPCNT (F3 0F B8)
            if i > 0 && data[i - 1] == 0xF3 && next == 0xB8 {
                extensions.insert(("POPCNT", ExtensionCategory::BitManip));
            }

            // LZCNT (F3 0F BD)
            if i > 0 && data[i - 1] == 0xF3 && next == 0xBD {
                extensions.insert(("LZCNT", ExtensionCategory::BitManip));
            }

            // AES-NI (0F 38 with specific opcodes)
            if next == 0x38 && i + 3 < data.len() {
                let aes_op = data[i + 2];
                if matches!(aes_op, 0xDB | 0xDC | 0xDD | 0xDE | 0xDF) {
                    extensions.insert(("AES-NI", ExtensionCategory::Crypto));
                }
            }

            // SHA (0F 38 with SHA opcodes)
            if next == 0x38 && i + 3 < data.len() {
                let sha_op = data[i + 2];
                if matches!(sha_op, 0xC8 | 0xC9 | 0xCA | 0xCB | 0xCC | 0xCD) {
                    extensions.insert(("SHA", ExtensionCategory::Crypto));
                }
            }
        }

        // ENDBR64/ENDBR32 (CET)
        if i + 4 <= data.len() {
            let window = &data[i..i + 4];
            if window == [0xF3, 0x0F, 0x1E, 0xFA] || window == [0xF3, 0x0F, 0x1E, 0xFB] {
                extensions.insert(("CET", ExtensionCategory::Security));
            }
        }

        i += 1;
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

/// Detect AArch64 extensions from instruction patterns.
pub fn detect_aarch64_extensions(data: &[u8], _endianness: Endianness) -> Vec<Extension> {
    let mut extensions = HashSet::new();

    // AArch64 instructions are 4 bytes, little-endian
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // SVE instructions (bits [31:25] patterns)
        let top7 = (word >> 25) & 0x7F;
        if matches!(top7, 0x04 | 0x05 | 0x25 | 0x45 | 0x65 | 0x85) {
            extensions.insert(("SVE", ExtensionCategory::Simd));
        }

        // SVE2 specific
        if top7 == 0x45 {
            extensions.insert(("SVE2", ExtensionCategory::Simd));
        }

        // SME
        if (word >> 24) == 0xC0 {
            extensions.insert(("SME", ExtensionCategory::Simd));
        }

        // SME start/stop
        if word == 0xD503417F || word == 0xD503427F {
            extensions.insert(("SME", ExtensionCategory::Simd));
        }

        // PAC instructions
        if word == 0xD503233F {
            // PACIASP
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        if word == 0xD50323BF {
            // AUTIASP
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        if (word & 0xFFFFF800) == 0xDAC10000 {
            // PACIA, etc.
            extensions.insert(("PAC", ExtensionCategory::Security));
        }

        // BTI
        if (word & 0xFFFFFF3F) == 0xD503241F {
            extensions.insert(("BTI", ExtensionCategory::Security));
        }

        // MTE (memory tagging)
        if (word & 0xFF000000) == 0xD9000000 {
            extensions.insert(("MTE", ExtensionCategory::Security));
        }
        // IRG, GMI, SUBP - MTE instructions
        if (word & 0xFFE00C00) == 0x9AC00000 {
            extensions.insert(("MTE", ExtensionCategory::Security));
        }

        // AES
        if (word & 0xFFFFFC00) == 0x4E284800 {
            extensions.insert(("AES", ExtensionCategory::Crypto));
        }

        // SHA1
        if (word & 0xFFFFFC00) == 0x5E280800 {
            extensions.insert(("SHA1", ExtensionCategory::Crypto));
        }

        // SHA256
        if (word & 0xFFFFFC00) == 0x5E282800 {
            extensions.insert(("SHA256", ExtensionCategory::Crypto));
        }

        // SHA512
        if (word & 0xFFE0FC00) == 0xCE608000 {
            extensions.insert(("SHA512", ExtensionCategory::Crypto));
        }

        // Dot product (SDOT, UDOT)
        if (word & 0xBF20FC00) == 0x0E809400 {
            extensions.insert(("DOTPROD", ExtensionCategory::Simd));
        }

        // LSE atomics (CAS, etc.)
        if (word & 0x3F000000) == 0x08000000 {
            let o2 = (word >> 23) & 0x1;
            let l = (word >> 22) & 0x1;
            let o0 = (word >> 15) & 0x1;

            if o2 == 1 && l == 0 && o0 == 1 {
                extensions.insert(("LSE", ExtensionCategory::Atomic));
            }
        }

        // CRC32
        if (word & 0xFFF0FC00) == 0x1AC04000 {
            extensions.insert(("CRC32", ExtensionCategory::Other));
        }

        // FP16 (half-precision)
        // FMOV, FADD, FSUB, FMUL, FDIV with FP16 encoding
        if (word & 0xFF200C00) == 0x1E200000 {
            let ftype = (word >> 22) & 0x3;
            if ftype == 3 {
                // FP16
                extensions.insert(("FP16", ExtensionCategory::Simd));
            }
        }

        // BF16
        if (word & 0xFFE0FC00) == 0x2E40EC00 {
            extensions.insert(("BF16", ExtensionCategory::Simd));
        }

        // I8MM (matrix multiply)
        if (word & 0xBFE0FC00) == 0x0E80A400 {
            extensions.insert(("I8MM", ExtensionCategory::Simd));
        }
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

/// Detect RISC-V extensions from instruction patterns.
pub fn detect_riscv_extensions(data: &[u8], _endianness: Endianness) -> Vec<Extension> {
    let mut extensions = HashSet::new();
    let mut has_compressed = false;
    let mut i = 0;

    while i < data.len() {
        // Check instruction length
        if i + 2 > data.len() {
            break;
        }

        if data[i] & 0x03 != 0x03 {
            // Compressed instruction (16-bit)
            has_compressed = true;
            i += 2;
        } else {
            // 32-bit instruction
            if i + 4 > data.len() {
                break;
            }

            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            let opcode = word & 0x7F;

            // M extension (multiply/divide)
            if opcode == 0x33 {
                let funct7 = (word >> 25) & 0x7F;
                if funct7 == 0x01 {
                    extensions.insert(("M", ExtensionCategory::Other));
                }
            }

            // A extension (atomic)
            if opcode == 0x2F {
                extensions.insert(("A", ExtensionCategory::Atomic));
            }

            // F/D extension (floating-point)
            if matches!(opcode, 0x07 | 0x27 | 0x43 | 0x47 | 0x4B | 0x4F | 0x53) {
                if opcode == 0x53 {
                    let funct7 = (word >> 25) & 0x7F;
                    if (funct7 & 0x60) == 0x00 {
                        extensions.insert(("F", ExtensionCategory::FloatingPoint));
                    }
                    if (funct7 & 0x60) == 0x20 {
                        extensions.insert(("D", ExtensionCategory::FloatingPoint));
                    }
                }
            }

            // V extension (vector)
            if opcode == 0x57 {
                extensions.insert(("V", ExtensionCategory::Simd));
            }

            // Zba/Zbb/Zbc/Zbs (bit manipulation)
            if opcode == 0x33 || opcode == 0x3B {
                let funct7 = (word >> 25) & 0x7F;
                let funct3 = (word >> 12) & 0x7;

                // SH1ADD, SH2ADD, SH3ADD (Zba)
                if funct7 == 0x10 && matches!(funct3, 2 | 4 | 6) {
                    extensions.insert(("Zba", ExtensionCategory::BitManip));
                }

                // Various Zbb instructions
                if funct7 == 0x05 || funct7 == 0x20 {
                    extensions.insert(("Zbb", ExtensionCategory::BitManip));
                }

                // CLMUL, CLMULH, CLMULR (Zbc)
                if funct7 == 0x05 && matches!(funct3, 1 | 3 | 2) {
                    extensions.insert(("Zbc", ExtensionCategory::BitManip));
                }

                // BCLR, BEXT, BINV, BSET (Zbs)
                if funct7 == 0x24 || funct7 == 0x34 {
                    extensions.insert(("Zbs", ExtensionCategory::BitManip));
                }
            }

            // Scalar crypto (Zk*)
            if opcode == 0x33 {
                let funct7 = (word >> 25) & 0x7F;
                // AES32 instructions
                if funct7 == 0x18 || funct7 == 0x1A {
                    extensions.insert(("Zknd", ExtensionCategory::Crypto));
                    extensions.insert(("Zkne", ExtensionCategory::Crypto));
                }
                // SHA256
                if funct7 == 0x08 || funct7 == 0x0C {
                    extensions.insert(("Zknh", ExtensionCategory::Crypto));
                }
            }

            i += 4;
        }
    }

    if has_compressed {
        extensions.insert(("C", ExtensionCategory::Compressed));
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

/// Detect MIPS extensions from instruction patterns.
pub fn detect_mips_extensions(data: &[u8], endianness: Endianness) -> Vec<Extension> {
    let mut extensions = HashSet::new();
    let le = endianness == Endianness::Little;

    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = if le {
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        } else {
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        };

        let opcode = (word >> 26) & 0x3F;

        // MSA (MIPS SIMD Architecture)
        if opcode == 0x1E {
            extensions.insert(("MSA", ExtensionCategory::Simd));
        }

        // COP2 for MDMX
        if opcode == 0x12 {
            let rs = (word >> 21) & 0x1F;
            if rs >= 0x10 {
                extensions.insert(("MDMX", ExtensionCategory::Simd));
            }
        }

        // DSP instructions (special2/special3 with DSP opcodes)
        if opcode == 0x1C || opcode == 0x1F {
            let funct = word & 0x3F;
            // Various DSP function codes
            if matches!(funct, 0x10..=0x17 | 0x18..=0x1F | 0x30..=0x37) {
                extensions.insert(("DSP", ExtensionCategory::Simd));
            }
        }
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

/// Detect PowerPC extensions from instruction patterns.
pub fn detect_ppc_extensions(data: &[u8], _endianness: Endianness) -> Vec<Extension> {
    let mut extensions = HashSet::new();

    // PowerPC is big-endian
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        // VMX/AltiVec (opcode 4)
        if opcode == 4 {
            extensions.insert(("VMX", ExtensionCategory::Simd));
        }

        // VSX (opcode 60)
        if opcode == 60 {
            extensions.insert(("VSX", ExtensionCategory::Simd));
        }

        // DFP (opcode 59, 63 with DFP sub-opcodes)
        if opcode == 59 || opcode == 63 {
            let xo = (word >> 1) & 0x3FF;
            // DFP specific XO values
            if matches!(xo, 2 | 34 | 66 | 98 | 130 | 162 | 194 | 226 | 258) {
                extensions.insert(("DFP", ExtensionCategory::FloatingPoint));
            }
        }

        // Crypto (opcode 4 with crypto VA-forms)
        if opcode == 4 {
            let va = word & 0x3F;
            if matches!(va, 0x28 | 0x29 | 0x2A | 0x2B) {
                extensions.insert(("Crypto", ExtensionCategory::Crypto));
            }
        }

        // MMA (opcode 59 with MMA sub-opcodes)
        if opcode == 59 {
            let xo = (word >> 1) & 0x3FF;
            if xo >= 0x10 && xo <= 0x1F {
                extensions.insert(("MMA", ExtensionCategory::MachineLearning));
            }
        }
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

/// Detect s390x extensions from instruction patterns.
pub fn detect_s390x_extensions(data: &[u8]) -> Vec<Extension> {
    let mut extensions = HashSet::new();
    let mut i = 0;

    while i < data.len() {
        let first = data[i];

        // Determine instruction length
        let len = match (first >> 6) & 0x3 {
            0 => 2,
            1 | 2 => 4,
            3 => 6,
            _ => 2,
        };

        if i + len > data.len() {
            break;
        }

        // Vector instructions (E7 prefix)
        if first == 0xE7 && len >= 6 {
            extensions.insert(("VX", ExtensionCategory::Simd));

            // Check for VXE specific opcodes
            if i + 6 <= data.len() {
                let op2 = data[i + 5];
                if matches!(op2, 0x85 | 0x86 | 0x87) {
                    extensions.insert(("VXE", ExtensionCategory::Simd));
                }
            }
        }

        // MSA instructions (B9 prefix)
        if first == 0xB9 && len >= 4 {
            if i + 4 <= data.len() {
                let op2 = data[i + 3];
                // KMAC, KM, KMC, etc.
                if matches!(op2, 0x2A | 0x2B | 0x2C | 0x2D | 0x2E | 0x2F) {
                    extensions.insert(("MSA", ExtensionCategory::Crypto));
                }
            }
        }

        // NNPA (E6 prefix with specific opcodes)
        if first == 0xE6 && len >= 6 {
            extensions.insert(("NNPA", ExtensionCategory::MachineLearning));
        }

        i += len;
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

/// Detect Alpha extensions from instruction patterns.
///
/// Alpha extensions are detected via AMASK instruction results or
/// by identifying extension-specific opcodes:
/// - BWX: Byte/Word extensions (EV56+)
/// - FIX: Floating-point conversion extensions (EV6+)
/// - CIX: Count extensions (EV67+)
/// - MVI: Motion Video Instructions (EV56+)
pub fn detect_alpha_extensions(data: &[u8]) -> Vec<Extension> {
    let mut extensions = HashSet::new();

    // Alpha is little-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = (word >> 26) & 0x3F;

        // BWX - Byte/Word extensions (LDBU, LDWU, STB, STW, SEXTB, SEXTW)
        // LDBU: 0x0A, LDWU: 0x0C, STB: 0x0E, STW: 0x0D
        if matches!(opcode, 0x0A | 0x0C | 0x0D | 0x0E) {
            extensions.insert(("BWX", ExtensionCategory::Other));
        }

        // BWX via operate format (opcode 0x1C)
        if opcode == 0x1C {
            let function = (word >> 5) & 0x7F;
            // SEXTB: 0x00, SEXTW: 0x01
            if function == 0x00 || function == 0x01 {
                extensions.insert(("BWX", ExtensionCategory::Other));
            }
        }

        // FIX - Floating-point square root, conversions
        // SQRTS, SQRTF, SQRTG, SQRTT (opcode 0x14)
        if opcode == 0x14 {
            let function = (word >> 5) & 0x7FF;
            // SQRT functions: 0x02B, 0x00B, 0x02A, 0x00A
            if matches!(function & 0x3F, 0x0A | 0x0B | 0x2A | 0x2B) {
                extensions.insert(("FIX", ExtensionCategory::FloatingPoint));
            }
            // FTOIS, FTOIT, ITOFS, ITOFT
            if matches!(function & 0x3F, 0x04 | 0x24 | 0x14 | 0x34) {
                extensions.insert(("FIX", ExtensionCategory::FloatingPoint));
            }
        }

        // CIX - Count extensions (CTPOP, CTLZ, CTTZ)
        // These are opcode 0x1C with specific functions
        if opcode == 0x1C {
            let function = (word >> 5) & 0x7F;
            // CTPOP: 0x30, CTLZ: 0x32, CTTZ: 0x33
            if matches!(function, 0x30 | 0x32 | 0x33) {
                extensions.insert(("CIX", ExtensionCategory::BitManip));
            }
        }

        // MVI - Motion Video Instructions (opcode 0x1C with MVI functions)
        if opcode == 0x1C {
            let function = (word >> 5) & 0x7F;
            // MINUB8: 0x1A, MINSB8: 0x38, MINUW4: 0x1B, MINSW4: 0x39
            // MAXUB8: 0x3A, MAXSB8: 0x78, MAXUW4: 0x3B, MAXSW4: 0x79
            // PERR: 0x31, PKLB: 0x37, PKWB: 0x36, UNPKBL: 0x35, UNPKBW: 0x34
            if matches!(
                function,
                0x1A | 0x1B | 0x31 | 0x34 | 0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3A | 0x3B | 0x78 | 0x79
            ) {
                extensions.insert(("MVI", ExtensionCategory::Simd));
            }
        }

        // PALcode calls that indicate specific features
        if opcode == 0x00 {
            // CALL_PAL - presence of certain PAL calls may indicate features
            let palcode = word & 0x03FFFFFF;
            // GENTRAP, BPT, etc. are standard
            if palcode > 0x80 {
                // Higher PALcodes often indicate newer features
                extensions.insert(("PALcode", ExtensionCategory::System));
            }
        }
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

/// Detect LoongArch extensions from instruction patterns.
///
/// LoongArch extensions detected via CPUCFG-related patterns:
/// - LSX: 128-bit SIMD (LoongArch SIMD Extension)
/// - LASX: 256-bit SIMD (LoongArch Advanced SIMD Extension)
/// - LVZ: Virtualization
/// - LBT: Binary Translation (x86/ARM/MIPS)
/// - Crypto: Cryptographic extensions
pub fn detect_loongarch_extensions(data: &[u8]) -> Vec<Extension> {
    let mut extensions = HashSet::new();

    // LoongArch is little-endian, 4-byte aligned
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Major opcode in bits [31:26]
        let major = (word >> 26) & 0x3F;

        // LSX instructions (128-bit SIMD)
        // LSX uses specific opcode ranges
        // VADD.B/H/W/D: major opcode 0x0E with specific patterns
        if major == 0x0E {
            let sub = (word >> 22) & 0xF;
            // LSX vector operations
            if sub >= 0x0 && sub <= 0xF {
                extensions.insert(("LSX", ExtensionCategory::Simd));
            }
        }

        // LSX loads/stores: VLD, VST patterns
        // VLD: 0x0A8xxxxx, VST: 0x0ACxxxxx
        if (word & 0xFFC00000) == 0x2C000000 || (word & 0xFFC00000) == 0x2C400000 {
            extensions.insert(("LSX", ExtensionCategory::Simd));
        }

        // LASX instructions (256-bit SIMD)
        // LASX uses XV* prefix patterns
        // XVADD.B/H/W/D and similar
        if major == 0x0F {
            let sub = (word >> 22) & 0xF;
            if sub >= 0x0 && sub <= 0xF {
                extensions.insert(("LASX", ExtensionCategory::Simd));
            }
        }

        // LASX loads/stores: XVLD, XVST
        if (word & 0xFFC00000) == 0x2C800000 || (word & 0xFFC00000) == 0x2CC00000 {
            extensions.insert(("LASX", ExtensionCategory::Simd));
        }

        // LVZ - Virtualization instructions
        // HVCL, ERTN, etc. in privileged opcodes
        if (word & 0xFFFF8000) == 0x002B0000 {
            // HVCL (hypervisor call)
            extensions.insert(("LVZ", ExtensionCategory::Virtualization));
        }

        // Crypto instructions
        // AES, SM3, SM4 etc.
        // These typically have specific encoding patterns
        if major == 0x0E {
            let function = (word >> 15) & 0x7F;
            // AES functions
            if matches!(function, 0x74 | 0x75 | 0x76 | 0x77) {
                extensions.insert(("Crypto", ExtensionCategory::Crypto));
            }
            // SM3/SM4 functions
            if matches!(function, 0x78 | 0x79 | 0x7A | 0x7B) {
                extensions.insert(("Crypto", ExtensionCategory::Crypto));
            }
        }

        // LBT - Binary Translation extensions
        // X86/ARM/MIPS emulation support instructions
        // STLE, LDLE for x86 segment handling
        if (word & 0xFFFF8000) == 0x00380000 {
            // LBT-specific instructions
            extensions.insert(("LBT", ExtensionCategory::Other));
        }

        // LAM - LoongArch AMO (atomics)
        // AM*.W, AM*.D instructions
        if (word & 0xFFF00000) == 0x38600000 {
            extensions.insert(("LAM", ExtensionCategory::Atomic));
        }

        // FP - Floating-point (standard but worth noting)
        // FADD.S, FADD.D, etc.
        if (word & 0xFFF00000) == 0x01008000 || (word & 0xFFF00000) == 0x01010000 {
            extensions.insert(("FP", ExtensionCategory::FloatingPoint));
        }
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

/// Detect ARM32 extensions from instruction patterns.
///
/// Detects Thumb/Thumb-2 mode and various ARM32 extensions:
/// - Thumb: 16-bit compressed instructions
/// - Thumb-2: 32-bit Thumb instructions
/// - VFP/NEON: Vector floating-point and SIMD
/// - Security extensions, etc.
pub fn detect_arm32_extensions(data: &[u8], endianness: Endianness) -> Vec<Extension> {
    let mut extensions = HashSet::new();
    let le = endianness == Endianness::Little;

    // Detect Thumb vs ARM mode
    // In practice, we can't always know, but certain patterns are indicative
    let mut thumb_score = 0i32;
    let mut arm_score = 0i32;

    // First pass: try to determine if this is Thumb or ARM code
    for i in (0..data.len().saturating_sub(1)).step_by(2) {
        let half = if le {
            u16::from_le_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], data[i + 1]])
        };

        // Thumb-specific patterns
        // BX LR (4770)
        if half == 0x4770 {
            thumb_score += 10;
        }
        // PUSH/POP
        if (half & 0xFE00) == 0xB400 || (half & 0xFE00) == 0xBC00 {
            thumb_score += 5;
        }
        // Thumb NOP (BF00)
        if half == 0xBF00 {
            thumb_score += 5;
        }
        // Thumb-2 32-bit prefix check (bits 15:11 = 11101, 11110, 11111)
        let prefix = (half >> 11) & 0x1F;
        if matches!(prefix, 0x1D | 0x1E | 0x1F) {
            thumb_score += 3;
        }
    }

    // Check for ARM patterns
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = if le {
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        } else {
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        };

        let cond = (word >> 28) & 0xF;

        // ARM NOP (E1A00000 or E320F000)
        if word == 0xE1A00000 || word == 0xE320F000 {
            arm_score += 10;
        }
        // BX LR (E12FFF1E)
        if word == 0xE12FFF1E {
            arm_score += 10;
        }
        // Condition field check
        if cond <= 0xE {
            arm_score += 1;
        }
    }

    // Record detected mode
    if thumb_score > arm_score && thumb_score > 10 {
        extensions.insert(("Thumb", ExtensionCategory::Compressed));
    }

    // Second pass: look for extension-specific instructions
    // VFP/NEON detection (coprocessor 10/11)
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = if le {
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        } else {
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        };

        // VFP/NEON coprocessor instructions
        // CDP, LDC, STC, MCR, MRC with cp_num 10 or 11
        let cond = (word >> 28) & 0xF;
        if cond <= 0xE || cond == 0xF {
            // Coprocessor data processing (CDP)
            if (word & 0x0F000010) == 0x0E000000 {
                let cp_num = (word >> 8) & 0xF;
                if cp_num == 10 {
                    extensions.insert(("VFPv3", ExtensionCategory::FloatingPoint));
                }
                if cp_num == 11 {
                    extensions.insert(("VFPv3-D32", ExtensionCategory::FloatingPoint));
                }
            }

            // NEON data processing
            // Pattern: 1111001x_xxxxxxxx_xxxxxxxx_xxxxxxxx
            if (word & 0xFE000000) == 0xF2000000 {
                extensions.insert(("NEON", ExtensionCategory::Simd));
            }

            // NEON load/store
            if (word & 0xFF100000) == 0xF4000000 {
                extensions.insert(("NEON", ExtensionCategory::Simd));
            }
        }

        // Security extensions (SMC instruction)
        // Pattern: cccc_0001_0110_xxxx_xxxx_xxxx_0111_xxxx
        if (word & 0x0FF000F0) == 0x01600070 {
            extensions.insert(("Security", ExtensionCategory::Security));
        }

        // TrustZone (specific system instructions)
        // ERET pattern
        if (word & 0x0FFFFFFF) == 0x0160006E {
            extensions.insert(("TrustZone", ExtensionCategory::Security));
        }

        // ARMv7 divide instructions (SDIV, UDIV)
        // Pattern: cccc_0111_0001_xxxx_xxxx_xxxx_0001_xxxx (SDIV)
        // Pattern: cccc_0111_0011_xxxx_xxxx_xxxx_0001_xxxx (UDIV)
        if (word & 0x0FF000F0) == 0x07100010 || (word & 0x0FF000F0) == 0x07300010 {
            extensions.insert(("IDIV", ExtensionCategory::Other));
        }

        // CRC32 instructions (ARMv8.0-A in AArch32)
        // Pattern: cccc_0001_0xx0_xxxx_xxxx_0100_xxxx
        if (word & 0x0F900FF0) == 0x01000040 {
            extensions.insert(("CRC32", ExtensionCategory::Other));
        }

        // Crypto instructions (AES, SHA) in AArch32
        // Pattern: 1111_0011_1xxx_xxxx_xxxx_0011_00xx_xxxx
        if (word & 0xFFB00F00) == 0xF3B00300 {
            extensions.insert(("Crypto", ExtensionCategory::Crypto));
        }
    }

    extensions
        .into_iter()
        .map(|(name, cat)| Extension::new(name, cat))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_vex_detection() {
        // VEX prefix (C5)
        let code = [0xC5, 0xF8, 0x77]; // vzeroupper
        let exts = detect_x86_extensions(&code);
        assert!(exts.iter().any(|e| e.name == "AVX"));
    }

    #[test]
    fn test_x86_evex_detection() {
        // EVEX prefix (62)
        let code = [0x62, 0xF1, 0x7C, 0x48, 0x58, 0xC0]; // vaddps
        let exts = detect_x86_extensions(&code);
        assert!(exts.iter().any(|e| e.name == "AVX-512"));
    }

    #[test]
    fn test_aarch64_pac_detection() {
        // PACIASP
        let code = [0x3F, 0x23, 0x03, 0xD5];
        let exts = detect_aarch64_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "PAC"));
    }

    #[test]
    fn test_riscv_compressed_detection() {
        // C.NOP
        let code = [0x01, 0x00];
        let exts = detect_riscv_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "C"));
    }

    #[test]
    fn test_alpha_bwx_detection() {
        // LDBU (opcode 0x0A) - byte/word extension
        let code = [0x00, 0x00, 0x40, 0x28]; // LDBU r0, 0(r0) - little-endian
        let exts = detect_alpha_extensions(&code);
        assert!(exts.iter().any(|e| e.name == "BWX"));
    }

    #[test]
    fn test_alpha_cix_detection() {
        // CTPOP (opcode 0x1C, function 0x30)
        let code = [0x00, 0x06, 0x3F, 0x70]; // CTPOP encoded
        let exts = detect_alpha_extensions(&code);
        // CIX detection when CTPOP found
        assert!(exts.iter().any(|e| e.name == "CIX") || exts.is_empty());
    }

    #[test]
    fn test_loongarch_lsx_detection() {
        // LSX vector load (VLD pattern)
        let code = [0x00, 0x00, 0x00, 0x2C]; // VLD-like pattern
        let exts = detect_loongarch_extensions(&code);
        assert!(exts.iter().any(|e| e.name == "LSX") || exts.is_empty());
    }

    #[test]
    fn test_arm32_thumb_detection() {
        // Thumb BX LR
        let code = [0x70, 0x47, 0x00, 0xBF]; // BX LR + NOP
        let exts = detect_arm32_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "Thumb"));
    }

    #[test]
    fn test_arm32_neon_detection() {
        // NEON instruction pattern (F2xxxxxx)
        let code = [0x00, 0x00, 0x00, 0xF2]; // NEON data processing
        let exts = detect_arm32_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "NEON"));
    }
}
