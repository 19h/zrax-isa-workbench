//! Extension detection module.
//!
//! This module detects ISA extensions and features from:
//! - Instruction prefixes (x86 VEX/EVEX)
//! - Specific instruction patterns
//! - ELF attributes and flags

pub mod detector;

use crate::types::{Endianness, Extension, ExtensionCategory, Isa};

pub use detector::*;

/// Detect extensions from code analysis.
pub fn detect_from_code(data: &[u8], isa: Isa, endianness: Endianness) -> Vec<Extension> {
    match isa {
        Isa::X86 | Isa::X86_64 => detector::detect_x86_extensions(data),
        Isa::Arm => detector::detect_arm32_extensions(data, endianness),
        Isa::AArch64 => detector::detect_aarch64_extensions(data, endianness),
        Isa::RiscV32 | Isa::RiscV64 | Isa::RiscV128 => {
            detector::detect_riscv_extensions(data, endianness)
        }
        Isa::Mips | Isa::Mips64 => detector::detect_mips_extensions(data, endianness),
        Isa::Ppc | Isa::Ppc64 => detector::detect_ppc_extensions(data, endianness),
        Isa::S390 | Isa::S390x => detector::detect_s390x_extensions(data),
        Isa::Alpha => detector::detect_alpha_extensions(data),
        Isa::LoongArch32 | Isa::LoongArch64 => detector::detect_loongarch_extensions(data),
        _ => Vec::new(),
    }
}

/// Get all known extensions for an ISA.
pub fn known_extensions(isa: Isa) -> Vec<(&'static str, ExtensionCategory)> {
    match isa {
        Isa::X86 | Isa::X86_64 => vec![
            // SIMD
            ("MMX", ExtensionCategory::Simd),
            ("SSE", ExtensionCategory::Simd),
            ("SSE2", ExtensionCategory::Simd),
            ("SSE3", ExtensionCategory::Simd),
            ("SSSE3", ExtensionCategory::Simd),
            ("SSE4.1", ExtensionCategory::Simd),
            ("SSE4.2", ExtensionCategory::Simd),
            ("AVX", ExtensionCategory::Simd),
            ("AVX2", ExtensionCategory::Simd),
            ("AVX-512F", ExtensionCategory::Simd),
            ("AVX-512BW", ExtensionCategory::Simd),
            ("AVX-512VL", ExtensionCategory::Simd),
            ("AVX-512DQ", ExtensionCategory::Simd),
            ("AVX-512CD", ExtensionCategory::Simd),
            ("AVX-512_VNNI", ExtensionCategory::Simd),
            ("AVX-512_VBMI", ExtensionCategory::Simd),
            ("AVX-512_VBMI2", ExtensionCategory::Simd),
            ("AVX-512_FP16", ExtensionCategory::Simd),
            ("AVX10", ExtensionCategory::Simd),
            // Crypto
            ("AES-NI", ExtensionCategory::Crypto),
            ("SHA", ExtensionCategory::Crypto),
            ("PCLMULQDQ", ExtensionCategory::Crypto),
            ("VAES", ExtensionCategory::Crypto),
            ("VPCLMULQDQ", ExtensionCategory::Crypto),
            ("GFNI", ExtensionCategory::Crypto),
            // Bit manipulation
            ("BMI1", ExtensionCategory::BitManip),
            ("BMI2", ExtensionCategory::BitManip),
            ("POPCNT", ExtensionCategory::BitManip),
            ("LZCNT", ExtensionCategory::BitManip),
            // ML
            ("AMX-TILE", ExtensionCategory::MachineLearning),
            ("AMX-INT8", ExtensionCategory::MachineLearning),
            ("AMX-BF16", ExtensionCategory::MachineLearning),
            ("AMX-FP16", ExtensionCategory::MachineLearning),
            ("AVX-VNNI", ExtensionCategory::MachineLearning),
            // Security
            ("CET", ExtensionCategory::Security),
            ("SGX", ExtensionCategory::Security),
            // System
            ("APX", ExtensionCategory::System),
            ("TSX", ExtensionCategory::Transactional),
        ],
        Isa::AArch64 => vec![
            // SIMD / Vector
            ("NEON", ExtensionCategory::Simd),
            ("SVE", ExtensionCategory::Simd),
            ("SVE2", ExtensionCategory::Simd),
            ("SME", ExtensionCategory::Simd),
            ("SME2", ExtensionCategory::Simd),
            ("DOTPROD", ExtensionCategory::Simd),
            ("FP16", ExtensionCategory::Simd),
            ("BF16", ExtensionCategory::Simd),
            ("I8MM", ExtensionCategory::Simd),
            ("RDM", ExtensionCategory::Simd),
            ("FHM", ExtensionCategory::Simd),
            ("FCMA", ExtensionCategory::Simd),
            ("FRINTTS", ExtensionCategory::Simd),
            // Crypto
            ("AES", ExtensionCategory::Crypto),
            ("PMULL", ExtensionCategory::Crypto),
            ("SHA1", ExtensionCategory::Crypto),
            ("SHA256", ExtensionCategory::Crypto),
            ("SHA512", ExtensionCategory::Crypto),
            ("SHA3", ExtensionCategory::Crypto),
            ("SM3", ExtensionCategory::Crypto),
            ("SM4", ExtensionCategory::Crypto),
            // Atomics
            ("LSE", ExtensionCategory::Atomic),
            ("LSE2", ExtensionCategory::Atomic),
            ("LRCPC", ExtensionCategory::Atomic),
            ("LRCPC2", ExtensionCategory::Atomic),
            // Security
            ("PAC", ExtensionCategory::Security),
            ("BTI", ExtensionCategory::Security),
            ("MTE", ExtensionCategory::Security),
            ("RNG", ExtensionCategory::Security),
            ("SB", ExtensionCategory::Security),
            ("SSBS", ExtensionCategory::Security),
            ("DIT", ExtensionCategory::Security),
            // System
            ("DPB", ExtensionCategory::System),
            ("DPB2", ExtensionCategory::System),
            ("WFxT", ExtensionCategory::System),
            // Other
            ("CRC32", ExtensionCategory::Other),
            ("JSCVT", ExtensionCategory::Other),
            ("FlagM", ExtensionCategory::Other),
            ("FlagM2", ExtensionCategory::Other),
            ("MOPS", ExtensionCategory::Other),
            ("HBC", ExtensionCategory::Other),
            ("CSSC", ExtensionCategory::Other),
            ("LS64", ExtensionCategory::Other),
        ],
        Isa::RiscV32 | Isa::RiscV64 | Isa::RiscV128 => vec![
            // Standard
            ("M", ExtensionCategory::Other),  // Multiply/Divide
            ("A", ExtensionCategory::Atomic), // Atomic
            ("F", ExtensionCategory::FloatingPoint), // Single-precision FP
            ("D", ExtensionCategory::FloatingPoint), // Double-precision FP
            ("Q", ExtensionCategory::FloatingPoint), // Quad-precision FP
            ("C", ExtensionCategory::Compressed), // Compressed
            ("V", ExtensionCategory::Simd),   // Vector
            ("H", ExtensionCategory::Virtualization), // Hypervisor
            // Zicsr, Zifencei
            ("Zicsr", ExtensionCategory::System),
            ("Zifencei", ExtensionCategory::System),
            // Bit manipulation
            ("Zba", ExtensionCategory::BitManip),
            ("Zbb", ExtensionCategory::BitManip),
            ("Zbc", ExtensionCategory::BitManip),
            ("Zbs", ExtensionCategory::BitManip),
            // Crypto
            ("Zbkb", ExtensionCategory::Crypto),
            ("Zbkc", ExtensionCategory::Crypto),
            ("Zbkx", ExtensionCategory::Crypto),
            ("Zknd", ExtensionCategory::Crypto),
            ("Zkne", ExtensionCategory::Crypto),
            ("Zknh", ExtensionCategory::Crypto),
            ("Zksed", ExtensionCategory::Crypto),
            ("Zksh", ExtensionCategory::Crypto),
            // Other
            ("Ztso", ExtensionCategory::Other),
        ],
        Isa::Ppc | Isa::Ppc64 => vec![
            ("VMX", ExtensionCategory::Simd), // AltiVec
            ("VSX", ExtensionCategory::Simd),
            ("DFP", ExtensionCategory::FloatingPoint),
            ("MMA", ExtensionCategory::MachineLearning),
            ("HTM", ExtensionCategory::Transactional),
            ("Crypto", ExtensionCategory::Crypto),
        ],
        Isa::Mips | Isa::Mips64 => vec![
            ("MSA", ExtensionCategory::Simd),
            ("DSP", ExtensionCategory::Simd),
            ("DSP2", ExtensionCategory::Simd),
            ("MDMX", ExtensionCategory::Simd),
            ("microMIPS", ExtensionCategory::Compressed),
            ("MIPS16e", ExtensionCategory::Compressed),
        ],
        Isa::S390 | Isa::S390x => vec![
            ("VX", ExtensionCategory::Simd),
            ("VXE", ExtensionCategory::Simd),
            ("VXE2", ExtensionCategory::Simd),
            ("MSA", ExtensionCategory::Crypto),
            ("NNPA", ExtensionCategory::MachineLearning),
            ("TX", ExtensionCategory::Transactional),
        ],
        Isa::Alpha => vec![
            ("BWX", ExtensionCategory::Other),
            ("FIX", ExtensionCategory::FloatingPoint),
            ("CIX", ExtensionCategory::BitManip),
            ("MVI", ExtensionCategory::Simd),
            ("PALcode", ExtensionCategory::System),
        ],
        Isa::LoongArch32 | Isa::LoongArch64 => vec![
            ("LSX", ExtensionCategory::Simd),
            ("LASX", ExtensionCategory::Simd),
            ("LVZ", ExtensionCategory::Virtualization),
            ("LBT", ExtensionCategory::Other),
            ("LAM", ExtensionCategory::Atomic),
            ("FP", ExtensionCategory::FloatingPoint),
            ("Crypto", ExtensionCategory::Crypto),
        ],
        Isa::Arm => vec![
            // Compressed instruction sets
            ("Thumb", ExtensionCategory::Compressed),
            ("Thumb-2", ExtensionCategory::Compressed),
            // Floating-point
            ("VFP", ExtensionCategory::FloatingPoint),
            ("VFPv2", ExtensionCategory::FloatingPoint),
            ("VFPv3", ExtensionCategory::FloatingPoint),
            ("VFPv3-D32", ExtensionCategory::FloatingPoint),
            ("VFP-D32", ExtensionCategory::FloatingPoint),
            ("VFPv4", ExtensionCategory::FloatingPoint),
            ("FPv4-SP", ExtensionCategory::FloatingPoint),
            // SIMD
            ("NEON", ExtensionCategory::Simd),
            ("DSP", ExtensionCategory::Simd),
            ("SIMDv1", ExtensionCategory::Simd),
            // Security
            ("Security", ExtensionCategory::Security),
            ("TrustZone", ExtensionCategory::Security),
            // Virtualization
            ("Virtualization", ExtensionCategory::Virtualization),
            // Crypto
            ("AES", ExtensionCategory::Crypto),
            ("SHA1", ExtensionCategory::Crypto),
            ("SHA256", ExtensionCategory::Crypto),
            ("PMULL", ExtensionCategory::Crypto),
            // Other
            ("IDIV", ExtensionCategory::Other),
            ("CRC32", ExtensionCategory::Other),
            ("MOVW", ExtensionCategory::Other),
            ("BitField", ExtensionCategory::Other),
            ("RBIT", ExtensionCategory::Other),
            ("Jazelle", ExtensionCategory::Other),
            ("XScale", ExtensionCategory::Other),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_extensions_x86() {
        let exts = known_extensions(Isa::X86_64);
        assert!(exts.iter().any(|(name, _)| *name == "AVX"));
        assert!(exts.iter().any(|(name, _)| *name == "AES-NI"));
    }

    #[test]
    fn test_known_extensions_aarch64() {
        let exts = known_extensions(Isa::AArch64);
        assert!(exts.iter().any(|(name, _)| *name == "SVE"));
        assert!(exts.iter().any(|(name, _)| *name == "PAC"));
    }

    #[test]
    fn test_known_extensions_riscv() {
        let exts = known_extensions(Isa::RiscV64);
        assert!(exts.iter().any(|(name, _)| *name == "M"));
        assert!(exts.iter().any(|(name, _)| *name == "V"));
    }
}
