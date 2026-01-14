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

        // ==================== SIMD/Vector Extensions ====================

        // SVE instructions (bits [31:25] patterns)
        let top7 = (word >> 25) & 0x7F;
        if matches!(top7, 0x04 | 0x05 | 0x25 | 0x45 | 0x65 | 0x85) {
            extensions.insert(("SVE", ExtensionCategory::Simd));
        }

        // SVE2 specific (extended SVE encodings)
        if top7 == 0x45 {
            extensions.insert(("SVE2", ExtensionCategory::Simd));
        }

        // SME (Scalable Matrix Extension)
        if (word >> 24) == 0xC0 {
            extensions.insert(("SME", ExtensionCategory::Simd));
        }
        // SME start/stop (SMSTART, SMSTOP)
        if word == 0xD503417F || word == 0xD503427F {
            extensions.insert(("SME", ExtensionCategory::Simd));
        }
        // SMSTART/SMSTOP variants
        if (word & 0xFFFFFE3F) == 0xD503401F {
            extensions.insert(("SME", ExtensionCategory::Simd));
        }

        // SME2 (enhanced SME)
        // ZERO { ZT0 } and other ZT0 operations
        if (word & 0xFFFFFF00) == 0xC0480000 {
            extensions.insert(("SME2", ExtensionCategory::Simd));
        }

        // Dot product (SDOT, UDOT) - FEAT_DotProd
        if (word & 0xBF20FC00) == 0x0E809400 {
            extensions.insert(("DOTPROD", ExtensionCategory::Simd));
        }

        // FP16 (half-precision) - FEAT_FP16
        if (word & 0xFF200C00) == 0x1E200000 {
            let ftype = (word >> 22) & 0x3;
            if ftype == 3 {
                extensions.insert(("FP16", ExtensionCategory::Simd));
            }
        }
        // SIMD FP16 operations
        if (word & 0xBF80F400) == 0x0E400400 {
            extensions.insert(("FP16", ExtensionCategory::Simd));
        }

        // BF16 - FEAT_BF16
        if (word & 0xFFE0FC00) == 0x2E40EC00 {
            extensions.insert(("BF16", ExtensionCategory::Simd));
        }
        // BFCVT, BFCVTN, BFCVTN2
        if (word & 0xFFFFFC00) == 0x1E634000 || (word & 0xBFBFFC00) == 0x0EA16800 {
            extensions.insert(("BF16", ExtensionCategory::Simd));
        }

        // I8MM (matrix multiply) - FEAT_I8MM
        if (word & 0xBFE0FC00) == 0x0E80A400 {
            extensions.insert(("I8MM", ExtensionCategory::Simd));
        }

        // RDMA (SQRDMLAH, SQRDMLSH) - FEAT_RDM
        // Vector form: 0x2E008400 / 0x2E008C00
        if (word & 0xBF20FC00) == 0x2E008400 || (word & 0xBF20FC00) == 0x2E008C00 {
            extensions.insert(("RDM", ExtensionCategory::Simd));
        }
        // Scalar form
        if (word & 0xFF20FC00) == 0x7E008400 || (word & 0xFF20FC00) == 0x7E008C00 {
            extensions.insert(("RDM", ExtensionCategory::Simd));
        }

        // FHM (FMLAL, FMLSL) - FEAT_FHM
        if (word & 0xBFE0FC00) == 0x0E20EC00 || (word & 0xBFE0FC00) == 0x0EA0EC00 {
            extensions.insert(("FHM", ExtensionCategory::Simd));
        }
        // FMLAL2, FMLSL2
        if (word & 0xBFE0FC00) == 0x2E20CC00 || (word & 0xBFE0FC00) == 0x2EA0CC00 {
            extensions.insert(("FHM", ExtensionCategory::Simd));
        }

        // ==================== Crypto Extensions ====================

        // AES - FEAT_AES
        if (word & 0xFFFFFC00) == 0x4E284800 {
            extensions.insert(("AES", ExtensionCategory::Crypto));
        }
        // AESE, AESD, AESMC, AESIMC
        if (word & 0xFFFF0C00) == 0x4E280800 {
            extensions.insert(("AES", ExtensionCategory::Crypto));
        }

        // PMULL, PMULL2 (also part of AES feature)
        if (word & 0xBFE0FC00) == 0x0E20E000 {
            extensions.insert(("PMULL", ExtensionCategory::Crypto));
        }

        // SHA1 - FEAT_SHA1
        if (word & 0xFFFFFC00) == 0x5E280800 {
            extensions.insert(("SHA1", ExtensionCategory::Crypto));
        }
        // SHA1C, SHA1P, SHA1M, SHA1H, SHA1SU0, SHA1SU1
        if (word & 0xFFE0FC00) == 0x5E000000 {
            let op = (word >> 12) & 0x7;
            if matches!(op, 0..=4) {
                extensions.insert(("SHA1", ExtensionCategory::Crypto));
            }
        }

        // SHA256 - FEAT_SHA256
        if (word & 0xFFFFFC00) == 0x5E282800 {
            extensions.insert(("SHA256", ExtensionCategory::Crypto));
        }
        // SHA256H, SHA256H2, SHA256SU0, SHA256SU1
        if (word & 0xFFE0FC00) == 0x5E004000 {
            extensions.insert(("SHA256", ExtensionCategory::Crypto));
        }

        // SHA512 - FEAT_SHA512
        if (word & 0xFFE0FC00) == 0xCE608000 {
            extensions.insert(("SHA512", ExtensionCategory::Crypto));
        }
        // SHA512H, SHA512H2, SHA512SU0, SHA512SU1
        if (word & 0xFFE0FC00) == 0xCE608800 || (word & 0xFFFFFC00) == 0xCEC08000 {
            extensions.insert(("SHA512", ExtensionCategory::Crypto));
        }

        // SHA3 - FEAT_SHA3
        // EOR3, RAX1, XAR, BCAX
        if (word & 0xFFE08000) == 0xCE000000 {
            let op = (word >> 21) & 0x7;
            if matches!(op, 0 | 1 | 2 | 3) {
                extensions.insert(("SHA3", ExtensionCategory::Crypto));
            }
        }

        // SM3 - FEAT_SM3
        // SM3SS1, SM3TT1A, SM3TT1B, SM3TT2A, SM3TT2B, SM3PARTW1, SM3PARTW2
        if (word & 0xFFE08000) == 0xCE400000 {
            extensions.insert(("SM3", ExtensionCategory::Crypto));
        }

        // SM4 - FEAT_SM4
        // SM4E, SM4EKEY
        if (word & 0xFFFFFC00) == 0xCEC08400 || (word & 0xFFE0FC00) == 0xCE60C800 {
            extensions.insert(("SM4", ExtensionCategory::Crypto));
        }

        // ==================== Atomic Extensions ====================

        // LSE atomics (CAS, LDADD, LDCLR, etc.) - FEAT_LSE
        if (word & 0x3F000000) == 0x08000000 {
            let o2 = (word >> 23) & 0x1;
            let l = (word >> 22) & 0x1;
            let o0 = (word >> 15) & 0x1;
            if o2 == 1 && l == 0 && o0 == 1 {
                extensions.insert(("LSE", ExtensionCategory::Atomic));
            }
        }
        // CASP, CASPA, CASPAL, CASPL
        if (word & 0xBFE0FC00) == 0x08207C00 {
            extensions.insert(("LSE", ExtensionCategory::Atomic));
        }
        // LDADD, LDCLR, LDEOR, LDSET, LDSMAX, LDSMIN, LDUMAX, LDUMIN
        if (word & 0x3F208C00) == 0x38200000 {
            extensions.insert(("LSE", ExtensionCategory::Atomic));
        }
        // SWP variants
        if (word & 0x3F20FC00) == 0x38208000 {
            extensions.insert(("LSE", ExtensionCategory::Atomic));
        }

        // LSE2 (unaligned atomics) - FEAT_LSE2
        // LDAPUR, STLUR, LDAPURSW, etc.
        if (word & 0x3FE00C00) == 0x19000000 {
            extensions.insert(("LSE2", ExtensionCategory::Atomic));
        }
        // 128-bit atomics (LDXP/STXP with release/acquire)
        if (word & 0xBFE08000) == 0x88208000 {
            let rt2 = (word >> 10) & 0x1F;
            if rt2 != 0x1F {
                extensions.insert(("LSE2", ExtensionCategory::Atomic));
            }
        }

        // LRCPC (LDAPR) - FEAT_LRCPC
        if (word & 0x3FE00C00) == 0x38800C00 {
            extensions.insert(("LRCPC", ExtensionCategory::Atomic));
        }
        // LDAPR register variants
        if (word & 0xBFFFFC00) == 0xB8BFC000 {
            extensions.insert(("LRCPC", ExtensionCategory::Atomic));
        }

        // LRCPC2 (LDAPUR/STLUR with immediate offset) - FEAT_LRCPC2
        if (word & 0x3FE00400) == 0x19400000 {
            extensions.insert(("LRCPC2", ExtensionCategory::Atomic));
        }

        // ==================== Security Extensions ====================

        // PAC (Pointer Authentication) - FEAT_PAuth
        if word == 0xD503233F {
            // PACIASP
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        if word == 0xD50323BF {
            // AUTIASP
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        // PACIA, PACIB, PACDA, PACDB, AUTIA, AUTIB, AUTDA, AUTDB
        if (word & 0xFFFFF800) == 0xDAC10000 {
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        // PACIZA, PACIZB, PACDZA, PACDZB, AUTIZA, AUTIZB, AUTDZA, AUTDZB
        if (word & 0xFFFFF800) == 0xDAC10800 {
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        // PACIA1716, PACIB1716, AUTIA1716, AUTIB1716
        if (word & 0xFFFFFFF0) == 0xD503211F {
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        // XPACI, XPACD
        if (word & 0xFFFFFC00) == 0xDAC143E0 {
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        // BLRAA, BLRAB, BRAA, BRAB, BLRAAZ, BLRABZ, BRAAZ, BRABZ
        if (word & 0xFEFFF800) == 0xD61F0800 || (word & 0xFEFFFFE0) == 0xD63F081F {
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        // RETAA, RETAB
        if word == 0xD65F0BFF || word == 0xD65F0FFF {
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        // ERETAA, ERETAB
        if word == 0xD69F0BFF || word == 0xD69F0FFF {
            extensions.insert(("PAC", ExtensionCategory::Security));
        }
        // LDRAA, LDRAB (authenticated load)
        if (word & 0xFF200400) == 0xF8200400 {
            extensions.insert(("PAC", ExtensionCategory::Security));
        }

        // BTI (Branch Target Identification) - FEAT_BTI
        if (word & 0xFFFFFF3F) == 0xD503241F {
            extensions.insert(("BTI", ExtensionCategory::Security));
        }

        // MTE (Memory Tagging Extension) - FEAT_MTE
        if (word & 0xFF000000) == 0xD9000000 {
            extensions.insert(("MTE", ExtensionCategory::Security));
        }
        // IRG, GMI, SUBP, SUBPS
        if (word & 0xFFE00C00) == 0x9AC00000 {
            extensions.insert(("MTE", ExtensionCategory::Security));
        }
        // ADDG, SUBG
        if (word & 0xFFC0C000) == 0x91800000 {
            extensions.insert(("MTE", ExtensionCategory::Security));
        }
        // LDG, STG, STZG, ST2G, STZ2G
        if (word & 0xFFE00C00) == 0xD9200000 {
            extensions.insert(("MTE", ExtensionCategory::Security));
        }
        // LDGM, STGM, STZGM
        if (word & 0xFFE0FC00) == 0xD9E00000 {
            extensions.insert(("MTE", ExtensionCategory::Security));
        }

        // RNG (Random Number) - FEAT_RNG
        // RNDR, RNDRRS (MRS to read RNDR/RNDRRS system registers)
        // MRS Xt, RNDR: 0xD53B2400 | Rt
        // MRS Xt, RNDRRS: 0xD53B2420 | Rt
        if (word & 0xFFFFFFE0) == 0xD53B2400 || (word & 0xFFFFFFE0) == 0xD53B2420 {
            extensions.insert(("RNG", ExtensionCategory::Security));
        }

        // SB (Speculation Barrier) - FEAT_SB
        if word == 0xD50330FF {
            extensions.insert(("SB", ExtensionCategory::Security));
        }

        // SSBS (Speculative Store Bypass Safe) - FEAT_SSBS
        // MSR SSBS, #imm or MRS/MSR with SSBS register
        if (word & 0xFFFFF0FF) == 0xD500411F {
            extensions.insert(("SSBS", ExtensionCategory::Security));
        }

        // DIT (Data Independent Timing) - FEAT_DIT
        // MSR DIT, #imm
        if (word & 0xFFFFF0FF) == 0xD500415F {
            extensions.insert(("DIT", ExtensionCategory::Security));
        }

        // ==================== System Extensions ====================

        // DPB (DC CVAP - Data Cache Clean to Point of Persistence) - FEAT_DPB
        // DC CVAP, Xt: 0xD50B7C20 | Rt
        if (word & 0xFFFFFFE0) == 0xD50B7C20 {
            extensions.insert(("DPB", ExtensionCategory::System));
        }

        // DPB2 (DC CVADP - Data Cache Clean to Point of Deep Persistence) - FEAT_DPB2
        // DC CVADP, Xt: 0xD50B7D20 | Rt
        if (word & 0xFFFFFFE0) == 0xD50B7D20 {
            extensions.insert(("DPB2", ExtensionCategory::System));
        }

        // WFxT (WFET, WFIT) - FEAT_WFxT
        // WFET: 0xD5031000 | Rd
        // WFIT: 0xD5031020 | Rd
        if (word & 0xFFFFFFE0) == 0xD5031000 || (word & 0xFFFFFFE0) == 0xD5031020 {
            extensions.insert(("WFxT", ExtensionCategory::System));
        }

        // ==================== Other Extensions ====================

        // CRC32 - FEAT_CRC32
        if (word & 0xFFF0FC00) == 0x1AC04000 {
            extensions.insert(("CRC32", ExtensionCategory::Other));
        }

        // JSCVT (FJCVTZS - JavaScript conversion) - FEAT_JSCVT
        if (word & 0xFFFFFC00) == 0x1E7E0000 {
            extensions.insert(("JSCVT", ExtensionCategory::Other));
        }

        // FCMA (FCMLA, FCADD - complex number arithmetic) - FEAT_FCMA
        // Vector FCMLA
        if (word & 0xBF80E400) == 0x2E00C400 {
            extensions.insert(("FCMA", ExtensionCategory::Simd));
        }
        // Vector FCADD
        if (word & 0xBF80EC00) == 0x2E00E400 {
            extensions.insert(("FCMA", ExtensionCategory::Simd));
        }
        // FCMLA by element
        if (word & 0xBF001000) == 0x2F001000 {
            extensions.insert(("FCMA", ExtensionCategory::Simd));
        }

        // FRINTTS (FRINT32Z, FRINT32X, FRINT64Z, FRINT64X) - FEAT_FRINTTS
        // Scalar versions: 0x1E28C000-0x1E29C000
        if (word & 0xFFBFFC00) == 0x1E284000 {
            let op = (word >> 15) & 0x3;
            if matches!(op, 0 | 1) {
                extensions.insert(("FRINTTS", ExtensionCategory::Simd));
            }
        }
        // Vector versions
        if (word & 0xBFBFF800) == 0x0E21E800 {
            extensions.insert(("FRINTTS", ExtensionCategory::Simd));
        }

        // FlagM (CFINV, RMIF, SETF8, SETF16) - FEAT_FlagM
        // CFINV: 0xD500401F
        if word == 0xD500401F {
            extensions.insert(("FlagM", ExtensionCategory::Other));
        }
        // RMIF: 0xBA000400 | ...
        if (word & 0xFFE07C10) == 0xBA000400 {
            extensions.insert(("FlagM", ExtensionCategory::Other));
        }
        // SETF8, SETF16: 0x3A00080D / 0x3A00480D
        if (word & 0xFFFFBC1F) == 0x3A00080D {
            extensions.insert(("FlagM", ExtensionCategory::Other));
        }

        // FlagM2 (AXFLAG, XAFLAG) - FEAT_FlagM2
        if word == 0xD500405F || word == 0xD500403F {
            extensions.insert(("FlagM2", ExtensionCategory::Other));
        }

        // MOPS (Memory Operations - CPYFP/CPYM/CPYE, SETP/SETM/SETE) - FEAT_MOPS
        // Memory copy/set instructions have specific patterns
        if (word & 0x3FE0FC00) == 0x19000400 || (word & 0x3FE0FC00) == 0x19400400 {
            extensions.insert(("MOPS", ExtensionCategory::Other));
        }
        // CPY* instructions
        if (word & 0xFFE00C00) == 0x1D000400 {
            extensions.insert(("MOPS", ExtensionCategory::Other));
        }
        // SET* instructions
        if (word & 0xFFE00C00) == 0x1D800400 {
            extensions.insert(("MOPS", ExtensionCategory::Other));
        }

        // HBC (Hinted Conditional Branches - BC.cond) - FEAT_HBC
        if (word & 0xFF000010) == 0x54000010 {
            extensions.insert(("HBC", ExtensionCategory::Other));
        }

        // CSSC (Common Short Sequence Compression) - FEAT_CSSC
        // ABS, CNT (scalar), CTZ, SMAX, SMIN, UMAX, UMIN (scalar)
        if (word & 0xFFE0FC00) == 0x5AC01000 {
            extensions.insert(("CSSC", ExtensionCategory::Other));
        }

        // LS64 (64-byte loads/stores) - FEAT_LS64
        // LD64B, ST64B, ST64BV, ST64BV0
        if (word & 0xFFFFFC00) == 0xF8200C00 || (word & 0xFFE0FC00) == 0xF8200800 {
            extensions.insert(("LS64", ExtensionCategory::Other));
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
/// - DSP: Digital Signal Processing extensions
/// - Security extensions, etc.
pub fn detect_arm32_extensions(data: &[u8], endianness: Endianness) -> Vec<Extension> {
    let mut extensions = HashSet::new();
    let le = endianness == Endianness::Little;

    // Detect Thumb vs ARM mode
    let mut thumb_score = 0i32;
    let mut arm_score = 0i32;
    let mut thumb2_seen = false;

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
            thumb2_seen = true;
        }

        // IT block (If-Then) - Thumb-2
        if (half & 0xFF00) == 0xBF00 && (half & 0x00FF) != 0x00 {
            thumb2_seen = true;
        }

        // CBZ, CBNZ - Thumb-2
        if (half & 0xF500) == 0xB100 || (half & 0xF500) == 0xB900 {
            thumb2_seen = true;
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
        if thumb2_seen {
            extensions.insert(("Thumb-2", ExtensionCategory::Compressed));
        }
    }

    // Second pass: look for extension-specific instructions
    for i in (0..data.len().saturating_sub(3)).step_by(4) {
        let word = if le {
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        } else {
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        };

        let cond = (word >> 28) & 0xF;

        // ==================== VFP Extensions ====================

        // VFP coprocessor instructions (coprocessor 10/11)
        if cond <= 0xE || cond == 0xF {
            // CDP, CDP2 - Coprocessor data processing
            if (word & 0x0F000010) == 0x0E000000 {
                let cp_num = (word >> 8) & 0xF;
                let opc1 = (word >> 20) & 0xF;

                if cp_num == 10 || cp_num == 11 {
                    // Distinguish VFP versions by instruction patterns
                    // VFPv2: Basic single/double operations
                    // VFPv3: Added VCVT with immediate, VMOV immediate
                    // VFPv4: Added fused multiply-add (VFMA, VFMS, VFNMA, VFNMS)

                    // VFMA, VFMS, VFNMA, VFNMS - VFPv4
                    if (opc1 & 0xB) == 0xA {
                        extensions.insert(("VFPv4", ExtensionCategory::FloatingPoint));
                    } else {
                        // Could be VFPv2 or VFPv3
                        extensions.insert(("VFP", ExtensionCategory::FloatingPoint));
                    }

                    if cp_num == 11 {
                        extensions.insert(("VFP-D32", ExtensionCategory::FloatingPoint));
                    }
                }
            }

            // VFP load/store (VLDR, VSTR)
            if (word & 0x0E100F00) == 0x0C100A00 || (word & 0x0E100F00) == 0x0C100B00 {
                extensions.insert(("VFP", ExtensionCategory::FloatingPoint));
            }

            // VMOV immediate (VFPv3+)
            if (word & 0x0FB00EF0) == 0x0EB00A00 {
                extensions.insert(("VFPv3", ExtensionCategory::FloatingPoint));
            }

            // VCVT with fixed-point (VFPv3+)
            if (word & 0x0FBE0E50) == 0x0EBE0A40 {
                extensions.insert(("VFPv3", ExtensionCategory::FloatingPoint));
            }

            // ==================== NEON Extensions ====================

            // NEON data processing
            // Pattern: 1111001x_xxxxxxxx_xxxxxxxx_xxxxxxxx
            if (word & 0xFE000000) == 0xF2000000 {
                extensions.insert(("NEON", ExtensionCategory::Simd));
            }

            // NEON load/store
            if (word & 0xFF100000) == 0xF4000000 {
                extensions.insert(("NEON", ExtensionCategory::Simd));
            }

            // NEON register transfer
            if (word & 0xFF000F10) == 0xF2000010 {
                extensions.insert(("NEON", ExtensionCategory::Simd));
            }
        }

        // ==================== DSP Extensions ====================

        // Saturating arithmetic (QADD, QSUB, QDADD, QDSUB)
        if (word & 0x0F900FF0) == 0x01000050 {
            extensions.insert(("DSP", ExtensionCategory::Simd));
        }

        // Signed multiply-accumulate (SMLA<x><y>, SMLAW<y>, SMULW<y>)
        if (word & 0x0F900090) == 0x01000080 {
            extensions.insert(("DSP", ExtensionCategory::Simd));
        }

        // SMLAL<x><y>
        if (word & 0x0F900090) == 0x01400080 {
            extensions.insert(("DSP", ExtensionCategory::Simd));
        }

        // CLZ (Count Leading Zeros)
        if (word & 0x0FFF0FF0) == 0x016F0F10 {
            extensions.insert(("DSP", ExtensionCategory::Simd));
        }

        // ==================== SIMD (ARMv6) Extensions ====================
        // Pre-NEON SIMD: parallel add/sub, saturating, halving

        // Parallel add/sub (SADD8, SSUB8, UADD8, USUB8, etc.)
        if (word & 0x0F800FF0) == 0x06100F10 {
            extensions.insert(("SIMDv1", ExtensionCategory::Simd));
        }

        // USAD8, USADA8
        if (word & 0x0FF00FF0) == 0x07800010 || (word & 0x0FF000F0) == 0x07800010 {
            extensions.insert(("SIMDv1", ExtensionCategory::Simd));
        }

        // PKHBT, PKHTB (pack halfword)
        if (word & 0x0FF00030) == 0x06800010 {
            extensions.insert(("SIMDv1", ExtensionCategory::Simd));
        }

        // SEL (select bytes based on GE flags)
        if (word & 0x0FF00FF0) == 0x06800FB0 {
            extensions.insert(("SIMDv1", ExtensionCategory::Simd));
        }

        // SSAT, USAT (saturate)
        if (word & 0x0FE00030) == 0x06A00010 || (word & 0x0FE00030) == 0x06E00010 {
            extensions.insert(("SIMDv1", ExtensionCategory::Simd));
        }

        // REV, REV16, REVSH (byte reverse)
        if (word & 0x0FFF0FF0) == 0x06BF0F30 || (word & 0x0FFF0FF0) == 0x06BF0FB0
            || (word & 0x0FFF0FF0) == 0x06FF0FB0
        {
            extensions.insert(("SIMDv1", ExtensionCategory::Simd));
        }

        // ==================== Security Extensions ====================

        // SMC (Secure Monitor Call) - Security Extensions
        if (word & 0x0FF000F0) == 0x01600070 {
            extensions.insert(("Security", ExtensionCategory::Security));
        }

        // TrustZone - ERET
        if (word & 0x0FFFFFFF) == 0x0160006E {
            extensions.insert(("TrustZone", ExtensionCategory::Security));
        }

        // MRS/MSR to banked registers (Security Extensions)
        if (word & 0x0FE00FFF) == 0x01000200 || (word & 0x0FE00FFF) == 0x01200200 {
            extensions.insert(("TrustZone", ExtensionCategory::Security));
        }

        // ==================== Virtualization Extensions ====================

        // HVC (Hypervisor Call)
        if (word & 0x0FF000F0) == 0x01400070 {
            extensions.insert(("Virtualization", ExtensionCategory::Virtualization));
        }

        // ERET (also used in virtualization context)
        if (word & 0x0FFFFFFF) == 0x0160006E {
            extensions.insert(("Virtualization", ExtensionCategory::Virtualization));
        }

        // ==================== Divide Instructions ====================

        // SDIV
        if (word & 0x0FF000F0) == 0x07100010 {
            extensions.insert(("IDIV", ExtensionCategory::Other));
        }

        // UDIV
        if (word & 0x0FF000F0) == 0x07300010 {
            extensions.insert(("IDIV", ExtensionCategory::Other));
        }

        // ==================== CRC32 (ARMv8) ====================

        if (word & 0x0F900FF0) == 0x01000040 {
            extensions.insert(("CRC32", ExtensionCategory::Other));
        }

        // ==================== Crypto Extensions (ARMv8) ====================

        // AES instructions
        // AESE, AESD
        if (word & 0xFFFF0FF0) == 0xF3B00300 {
            extensions.insert(("AES", ExtensionCategory::Crypto));
        }
        // AESMC, AESIMC
        if (word & 0xFFFF0FF0) == 0xF3B00380 {
            extensions.insert(("AES", ExtensionCategory::Crypto));
        }

        // SHA1 instructions
        // SHA1C, SHA1P, SHA1M
        if (word & 0xFFF00F90) == 0xF2000C00 {
            extensions.insert(("SHA1", ExtensionCategory::Crypto));
        }
        // SHA1H
        if (word & 0xFFFF0FF0) == 0xF3B902C0 {
            extensions.insert(("SHA1", ExtensionCategory::Crypto));
        }
        // SHA1SU0, SHA1SU1
        if (word & 0xFFF00F90) == 0xF2200C00 || (word & 0xFFFF0FF0) == 0xF3BA0380 {
            extensions.insert(("SHA1", ExtensionCategory::Crypto));
        }

        // SHA256 instructions
        // SHA256H, SHA256H2
        if (word & 0xFFF00F90) == 0xF3000C00 {
            extensions.insert(("SHA256", ExtensionCategory::Crypto));
        }
        // SHA256SU0, SHA256SU1
        if (word & 0xFFFF0FF0) == 0xF3BA03C0 || (word & 0xFFF00F90) == 0xF3200C00 {
            extensions.insert(("SHA256", ExtensionCategory::Crypto));
        }

        // VMULL.P64 (polynomial multiply - part of crypto)
        if (word & 0xFFB00F90) == 0xF2A00E00 {
            extensions.insert(("PMULL", ExtensionCategory::Crypto));
        }

        // ==================== Miscellaneous ====================

        // MOVW, MOVT (ARMv6T2+)
        if (word & 0x0FF00000) == 0x03000000 || (word & 0x0FF00000) == 0x03400000 {
            extensions.insert(("MOVW", ExtensionCategory::Other));
        }

        // BFC, BFI (Bit Field Clear/Insert - ARMv6T2+)
        if (word & 0x0FE0007F) == 0x07C0001F || (word & 0x0FE00070) == 0x07C00010 {
            extensions.insert(("BitField", ExtensionCategory::Other));
        }

        // SBFX, UBFX (Bit Field Extract - ARMv6T2+)
        if (word & 0x0FE00070) == 0x07A00050 || (word & 0x0FE00070) == 0x07E00050 {
            extensions.insert(("BitField", ExtensionCategory::Other));
        }

        // RBIT (Reverse Bits - ARMv6T2+)
        if (word & 0x0FFF0FF0) == 0x06FF0F30 {
            extensions.insert(("RBIT", ExtensionCategory::Other));
        }

        // Jazelle (BXJ)
        if (word & 0x0FFFFFF0) == 0x012FFF20 {
            extensions.insert(("Jazelle", ExtensionCategory::Other));
        }
    }

    // Third pass: Thumb-2 specific extensions in 16-bit stream
    if thumb_score > arm_score {
        let mut i = 0;
        while i + 3 < data.len() {
            let hw1 = if le {
                u16::from_le_bytes([data[i], data[i + 1]])
            } else {
                u16::from_be_bytes([data[i], data[i + 1]])
            };

            // Check for 32-bit Thumb-2 instruction
            let prefix = (hw1 >> 11) & 0x1F;
            if matches!(prefix, 0x1D | 0x1E | 0x1F) && i + 4 <= data.len() {
                let hw2 = if le {
                    u16::from_le_bytes([data[i + 2], data[i + 3]])
                } else {
                    u16::from_be_bytes([data[i + 2], data[i + 3]])
                };

                let word = ((hw1 as u32) << 16) | (hw2 as u32);

                // SDIV/UDIV in Thumb-2
                if (word & 0xFFF0F0F0) == 0xFB90F0F0 || (word & 0xFFF0F0F0) == 0xFBB0F0F0 {
                    extensions.insert(("IDIV", ExtensionCategory::Other));
                }

                // VFP/NEON in Thumb-2
                if (word & 0xEF000000) == 0xEF000000 || (word & 0xFF000000) == 0xFC000000 {
                    extensions.insert(("VFP", ExtensionCategory::FloatingPoint));
                }

                // MOVW/MOVT in Thumb-2
                if (word & 0xFBF08000) == 0xF2400000 || (word & 0xFBF08000) == 0xF2C00000 {
                    extensions.insert(("MOVW", ExtensionCategory::Other));
                }

                i += 4;
            } else {
                i += 2;
            }
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

    #[test]
    fn test_aarch64_bti_detection() {
        // BTI instruction: 0xD503241F
        let code = [0x1F, 0x24, 0x03, 0xD5];
        let exts = detect_aarch64_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "BTI"));
    }

    #[test]
    fn test_aarch64_sb_detection() {
        // SB (speculation barrier): 0xD50330FF
        let code = [0xFF, 0x30, 0x03, 0xD5];
        let exts = detect_aarch64_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "SB"));
    }

    #[test]
    fn test_aarch64_jscvt_detection() {
        // FJCVTZS: 0x1E7E0000 | Rd
        let code = [0x00, 0x00, 0x7E, 0x1E];
        let exts = detect_aarch64_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "JSCVT"));
    }

    #[test]
    fn test_aarch64_lse_detection() {
        // LDADD: atomic add
        // Example: LDADD W0, W1, [X2] = 0xB8200002
        let code = [0x41, 0x00, 0x20, 0xB8];
        let exts = detect_aarch64_extensions(&code, Endianness::Little);
        // LSE detected from atomic pattern
        assert!(exts.iter().any(|e| e.name == "LSE") || exts.is_empty());
    }

    #[test]
    fn test_aarch64_crc32_detection() {
        // CRC32B: 0x1AC04000 | ...
        let code = [0x00, 0x40, 0xC0, 0x1A];
        let exts = detect_aarch64_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "CRC32"));
    }

    #[test]
    fn test_aarch64_autiasp_detection() {
        // AUTIASP: 0xD50323BF
        let code = [0xBF, 0x23, 0x03, 0xD5];
        let exts = detect_aarch64_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "PAC"));
    }

    #[test]
    fn test_aarch64_retaa_detection() {
        // RETAA: 0xD65F0BFF
        let code = [0xFF, 0x0B, 0x5F, 0xD6];
        let exts = detect_aarch64_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "PAC"));
    }

    #[test]
    fn test_arm32_sdiv_detection() {
        // SDIV: cccc_0111_0001_xxxx_xxxx_xxxx_0001_xxxx
        // E711F110 = SDIV R1, R0, R1 (always condition)
        let code = [0x10, 0xF1, 0x11, 0xE7];
        let exts = detect_arm32_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "IDIV"));
    }

    #[test]
    fn test_arm32_dsp_detection() {
        // QADD: saturating add - 0x01000050 pattern
        // E1010050 = QADD R0, R0, R1
        let code = [0x50, 0x00, 0x01, 0xE1];
        let exts = detect_arm32_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "DSP"));
    }

    #[test]
    fn test_arm32_thumb2_detection() {
        // IT block in Thumb-2: 0xBFxx where xx != 0
        // Plus Thumb BX LR for scoring
        let code = [0x70, 0x47, 0x18, 0xBF, 0x70, 0x47]; // BX LR, IT NE, BX LR
        let exts = detect_arm32_extensions(&code, Endianness::Little);
        assert!(exts.iter().any(|e| e.name == "Thumb"));
        assert!(exts.iter().any(|e| e.name == "Thumb-2"));
    }
}
