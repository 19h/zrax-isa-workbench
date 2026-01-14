//! Mach-O (Mach Object) parser.
//!
//! Comprehensive Mach-O parser supporting all CPU types and subtypes,
//! including fat/universal binaries.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, Extension, ExtensionCategory,
    FileFormat, Isa, Variant,
};

/// Mach-O CPU type constants.
pub mod cpu_type {
    pub const VAX: u32 = 1;
    pub const MC680X0: u32 = 6;
    pub const X86: u32 = 7;
    pub const X86_64: u32 = 0x01000007;
    pub const MC98000: u32 = 10;
    pub const HPPA: u32 = 11;
    pub const ARM: u32 = 12;
    pub const ARM64: u32 = 0x0100000C;
    pub const ARM64_32: u32 = 0x0200000C;
    pub const MC88000: u32 = 13;
    pub const SPARC: u32 = 14;
    pub const I860: u32 = 15;
    pub const POWERPC: u32 = 18;
    pub const POWERPC64: u32 = 0x01000012;

    /// CPU_TYPE_64 flag
    pub const ABI64: u32 = 0x01000000;
    /// CPU_TYPE_ARM64_32 ILP32 flag
    pub const ARM64_32_FLAG: u32 = 0x02000000;
}

/// Mach-O ARM subtypes.
pub mod arm_subtype {
    pub const ALL: u32 = 0;
    pub const V4T: u32 = 5;
    pub const V6: u32 = 6;
    pub const V5TEJ: u32 = 7;
    pub const XSCALE: u32 = 8;
    pub const V7: u32 = 9;
    pub const V7F: u32 = 10;
    pub const V7S: u32 = 11;
    pub const V7K: u32 = 12;
    pub const V8: u32 = 13;
    pub const V6M: u32 = 14;
    pub const V7M: u32 = 15;
    pub const V7EM: u32 = 16;
}

/// Mach-O ARM64 subtypes.
pub mod arm64_subtype {
    pub const ALL: u32 = 0;
    pub const V8: u32 = 1;
    /// ARM64E - ARMv8.3+ with PAC (Pointer Authentication)
    pub const E: u32 = 2;
}

/// Extract extensions from CPU type and subtype.
fn extensions_from_cpu(cpu_type: u32, cpu_subtype: u32) -> Vec<Extension> {
    let subtype = cpu_subtype & 0xFF;

    match cpu_type {
        cpu_type::ARM64 | cpu_type::ARM64_32 => {
            let mut extensions = Vec::new();

            // ==================== Baseline Apple ARM64 (A7+) ====================
            // All Apple ARM64 chips have these features

            // SIMD/FP - mandatory in AArch64
            extensions.push(Extension::new("NEON", ExtensionCategory::Simd));
            extensions.push(Extension::new("FP16", ExtensionCategory::Simd));

            // Crypto - all Apple ARM64 has hardware crypto
            extensions.push(Extension::new("AES", ExtensionCategory::Crypto));
            extensions.push(Extension::new("PMULL", ExtensionCategory::Crypto));
            extensions.push(Extension::new("SHA1", ExtensionCategory::Crypto));
            extensions.push(Extension::new("SHA256", ExtensionCategory::Crypto));

            // Atomics - all Apple ARM64 has LSE (A10+ has full LSE)
            extensions.push(Extension::new("LSE", ExtensionCategory::Atomic));

            // Other baseline
            extensions.push(Extension::new("CRC32", ExtensionCategory::Other));

            // ==================== ARMv8.1+ features (A10 Fusion and later) ====================
            // A10 Fusion (2016) introduced ARMv8.1 features
            // All modern Apple chips have these

            // RDM (SQRDMLAH, SQRDMLSH) - ARMv8.1
            extensions.push(Extension::new("RDM", ExtensionCategory::Simd));

            // LRCPC (LDAPR) - ARMv8.3 but Apple has had this for a while
            extensions.push(Extension::new("LRCPC", ExtensionCategory::Atomic));

            // ==================== ARMv8.2+ features (A11 Bionic and later) ====================
            // A11 Bionic (2017) and later have these
            // We assume modern binaries target at least A11

            // FHM (FP16 multiply-accumulate) - ARMv8.2
            extensions.push(Extension::new("FHM", ExtensionCategory::Simd));

            // DotProd - ARMv8.2 (common in ML workloads)
            extensions.push(Extension::new("DOTPROD", ExtensionCategory::Simd));

            // SHA-512 and SHA-3 - available on A12+
            extensions.push(Extension::new("SHA512", ExtensionCategory::Crypto));
            extensions.push(Extension::new("SHA3", ExtensionCategory::Crypto));

            // ==================== ARMv8.3+ features (A12 Bionic and later) ====================
            // A12 Bionic (2018) introduced ARMv8.3 features

            // JSCVT - JavaScript type conversion
            extensions.push(Extension::new("JSCVT", ExtensionCategory::Other));

            // FCMA - Complex number arithmetic
            extensions.push(Extension::new("FCMA", ExtensionCategory::Simd));

            // LRCPC2 - Enhanced RCpc
            extensions.push(Extension::new("LRCPC2", ExtensionCategory::Atomic));

            // ==================== ARM64E specific (A12+ with PAC) ====================
            if subtype == arm64_subtype::E {
                // PAC (Pointer Authentication) - ARMv8.3
                extensions.push(Extension::new("PAC", ExtensionCategory::Security));

                // BTI (Branch Target Identification) - often paired with PAC
                extensions.push(Extension::new("BTI", ExtensionCategory::Security));

                // DIT (Data Independent Timing) - security feature
                extensions.push(Extension::new("DIT", ExtensionCategory::Security));

                // SSBS (Speculative Store Bypass Safe)
                extensions.push(Extension::new("SSBS", ExtensionCategory::Security));

                // SB (Speculation Barrier)
                extensions.push(Extension::new("SB", ExtensionCategory::Security));

                // FlagM - Flag manipulation
                extensions.push(Extension::new("FlagM", ExtensionCategory::Other));

                // FRINTTS - Float to int rounding
                extensions.push(Extension::new("FRINTTS", ExtensionCategory::Simd));

                // BF16 - available on M1 and later (A14+)
                extensions.push(Extension::new("BF16", ExtensionCategory::Simd));

                // I8MM - Int8 matrix multiply (A14+/M1+)
                extensions.push(Extension::new("I8MM", ExtensionCategory::Simd));

                // DPB/DPB2 - Data cache operations
                extensions.push(Extension::new("DPB", ExtensionCategory::System));
                extensions.push(Extension::new("DPB2", ExtensionCategory::System));
            }

            extensions
        }

        cpu_type::ARM => {
            let mut extensions = Vec::new();

            match subtype {
                arm_subtype::V4T => {
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                }
                arm_subtype::V5TEJ => {
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("Jazelle", ExtensionCategory::Other));
                }
                arm_subtype::V6 => {
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("VFPv2", ExtensionCategory::FloatingPoint));
                }
                arm_subtype::V6M => {
                    // Cortex-M0/M0+/M1 - Thumb only, no VFP
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                }
                arm_subtype::V7 | arm_subtype::V7F | arm_subtype::V7K => {
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("Thumb-2", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("VFPv3", ExtensionCategory::FloatingPoint));
                    extensions.push(Extension::new("NEON", ExtensionCategory::Simd));
                }
                arm_subtype::V7S => {
                    // Apple A6 chip - VFPv4
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("Thumb-2", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("VFPv4", ExtensionCategory::FloatingPoint));
                    extensions.push(Extension::new("NEON", ExtensionCategory::Simd));
                }
                arm_subtype::V7M => {
                    // Cortex-M3 - Thumb-2, no NEON/VFP
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("Thumb-2", ExtensionCategory::Compressed));
                }
                arm_subtype::V7EM => {
                    // Cortex-M4/M7 - Thumb-2 + optional FPv4-SP
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("Thumb-2", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("FPv4-SP", ExtensionCategory::FloatingPoint));
                    extensions.push(Extension::new("DSP", ExtensionCategory::Simd));
                }
                arm_subtype::V8 => {
                    // ARMv8 in AArch32 mode
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("Thumb-2", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("VFPv4", ExtensionCategory::FloatingPoint));
                    extensions.push(Extension::new("NEON", ExtensionCategory::Simd));
                    extensions.push(Extension::new("CRC32", ExtensionCategory::Other));
                    extensions.push(Extension::new("Crypto", ExtensionCategory::Crypto));
                }
                arm_subtype::XSCALE => {
                    extensions.push(Extension::new("Thumb", ExtensionCategory::Compressed));
                    extensions.push(Extension::new("XScale", ExtensionCategory::Other));
                }
                _ => {}
            }

            extensions
        }

        cpu_type::X86 => {
            let mut extensions = Vec::new();

            match subtype {
                x86_subtype::PENT => {
                    extensions.push(Extension::new("MMX", ExtensionCategory::Simd));
                }
                x86_subtype::PENTPRO | x86_subtype::PENTII_M3 | x86_subtype::PENTII_M5 => {
                    extensions.push(Extension::new("MMX", ExtensionCategory::Simd));
                }
                x86_subtype::PENTIUM_3 | x86_subtype::PENTIUM_3_M | x86_subtype::PENTIUM_3_XEON => {
                    extensions.push(Extension::new("MMX", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE", ExtensionCategory::Simd));
                }
                x86_subtype::PENTIUM_4 | x86_subtype::PENTIUM_4_M => {
                    extensions.push(Extension::new("MMX", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE2", ExtensionCategory::Simd));
                }
                x86_subtype::PENTIUM_M => {
                    extensions.push(Extension::new("MMX", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE2", ExtensionCategory::Simd));
                }
                x86_subtype::XEON | x86_subtype::XEON_MP => {
                    extensions.push(Extension::new("MMX", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE2", ExtensionCategory::Simd));
                }
                _ => {}
            }

            extensions
        }

        cpu_type::X86_64 => {
            let mut extensions = Vec::new();

            // x86-64 baseline includes SSE, SSE2, SSE3
            extensions.push(Extension::new("SSE", ExtensionCategory::Simd));
            extensions.push(Extension::new("SSE2", ExtensionCategory::Simd));
            extensions.push(Extension::new("SSE3", ExtensionCategory::Simd));

            match subtype {
                x86_64_subtype::H => {
                    // Haswell and later
                    extensions.push(Extension::new("SSSE3", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE4.1", ExtensionCategory::Simd));
                    extensions.push(Extension::new("SSE4.2", ExtensionCategory::Simd));
                    extensions.push(Extension::new("AVX", ExtensionCategory::Simd));
                    extensions.push(Extension::new("AVX2", ExtensionCategory::Simd));
                    extensions.push(Extension::new("FMA", ExtensionCategory::Simd));
                    extensions.push(Extension::new("BMI1", ExtensionCategory::BitManip));
                    extensions.push(Extension::new("BMI2", ExtensionCategory::BitManip));
                    extensions.push(Extension::new("POPCNT", ExtensionCategory::BitManip));
                    extensions.push(Extension::new("LZCNT", ExtensionCategory::BitManip));
                    extensions.push(Extension::new("AES-NI", ExtensionCategory::Crypto));
                }
                _ => {
                    // Generic x86-64 on macOS typically has at least SSSE3
                    extensions.push(Extension::new("SSSE3", ExtensionCategory::Simd));
                }
            }

            extensions
        }

        cpu_type::POWERPC | cpu_type::POWERPC64 => {
            // Most PowerPC Macs had AltiVec (G4, G5)
            // Can't reliably detect from subtype, but it's a reasonable assumption
            let mut extensions = Vec::new();
            extensions.push(Extension::new("AltiVec", ExtensionCategory::Simd));
            extensions
        }

        // No meaningful extensions can be inferred from subtypes for these
        cpu_type::VAX
        | cpu_type::MC680X0
        | cpu_type::SPARC
        | cpu_type::I860
        | cpu_type::HPPA
        | cpu_type::MC88000
        | cpu_type::MC98000 => Vec::new(),

        _ => Vec::new(),
    }
}

/// Mach-O x86 subtypes.
pub mod x86_subtype {
    pub const ALL: u32 = 3;
    pub const I386: u32 = 3;
    pub const I486: u32 = 4;
    pub const I486SX: u32 = 0x84;
    pub const PENT: u32 = 5;
    pub const PENTPRO: u32 = 0x16;
    pub const PENTII_M3: u32 = 0x36;
    pub const PENTII_M5: u32 = 0x56;
    pub const CELERON: u32 = 0x67;
    pub const CELERON_MOBILE: u32 = 0x77;
    pub const PENTIUM_3: u32 = 8;
    pub const PENTIUM_3_M: u32 = 0x18;
    pub const PENTIUM_3_XEON: u32 = 0x28;
    pub const PENTIUM_M: u32 = 9;
    pub const PENTIUM_4: u32 = 0x0A;
    pub const PENTIUM_4_M: u32 = 0x1A;
    pub const ITANIUM: u32 = 0x0B;
    pub const ITANIUM_2: u32 = 0x1B;
    pub const XEON: u32 = 0x0C;
    pub const XEON_MP: u32 = 0x1C;
}

/// Mach-O x86_64 subtypes.
pub mod x86_64_subtype {
    pub const ALL: u32 = 3;
    pub const H: u32 = 8;
}

/// Map Mach-O CPU type to ISA.
pub fn cpu_type_to_isa(cpu_type: u32, cpu_subtype: u32) -> (Isa, u8, Option<String>) {
    let variant = match cpu_type {
        cpu_type::VAX => {
            return (Isa::Vax, 32, None);
        }

        cpu_type::MC680X0 => {
            return (Isa::M68k, 32, None);
        }

        cpu_type::X86 => {
            let subtype_name = match cpu_subtype & 0xFF {
                x86_subtype::I386 => Some("i386".to_string()),
                x86_subtype::I486 => Some("i486".to_string()),
                x86_subtype::PENT => Some("Pentium".to_string()),
                x86_subtype::PENTPRO => Some("Pentium Pro".to_string()),
                x86_subtype::PENTIUM_M => Some("Pentium M".to_string()),
                x86_subtype::PENTIUM_4 => Some("Pentium 4".to_string()),
                _ => None,
            };
            return (Isa::X86, 32, subtype_name);
        }

        cpu_type::X86_64 => {
            let subtype_name = match cpu_subtype & 0xFF {
                x86_64_subtype::H => Some("Haswell".to_string()),
                _ => None,
            };
            return (Isa::X86_64, 64, subtype_name);
        }

        cpu_type::MC98000 => {
            return (Isa::Unknown(10), 32, Some("MC98000".to_string()));
        }

        cpu_type::HPPA => {
            return (Isa::Parisc, 32, None);
        }

        cpu_type::ARM => {
            let subtype_name = match cpu_subtype & 0xFF {
                arm_subtype::V4T => Some("ARMv4T".to_string()),
                arm_subtype::V6 => Some("ARMv6".to_string()),
                arm_subtype::V5TEJ => Some("ARMv5TEJ".to_string()),
                arm_subtype::XSCALE => Some("XScale".to_string()),
                arm_subtype::V7 => Some("ARMv7".to_string()),
                arm_subtype::V7F => Some("ARMv7 Cortex-A9".to_string()),
                arm_subtype::V7S => Some("ARMv7S (A6)".to_string()),
                arm_subtype::V7K => Some("ARMv7K (Watch)".to_string()),
                arm_subtype::V8 => Some("ARMv8".to_string()),
                arm_subtype::V6M => Some("ARMv6-M".to_string()),
                arm_subtype::V7M => Some("ARMv7-M".to_string()),
                arm_subtype::V7EM => Some("ARMv7E-M".to_string()),
                _ => None,
            };
            return (Isa::Arm, 32, subtype_name);
        }

        cpu_type::ARM64 => {
            let subtype_name = match cpu_subtype & 0xFF {
                arm64_subtype::V8 => Some("ARMv8".to_string()),
                arm64_subtype::E => Some("ARMv8.3+ (PAC)".to_string()),
                _ => None,
            };
            return (Isa::AArch64, 64, subtype_name);
        }

        cpu_type::ARM64_32 => {
            return (Isa::AArch64, 32, Some("ARM64_32 (ILP32)".to_string()));
        }

        cpu_type::MC88000 => {
            return (Isa::Unknown(13), 32, Some("MC88000".to_string()));
        }

        cpu_type::SPARC => {
            return (Isa::Sparc, 32, None);
        }

        cpu_type::I860 => {
            return (Isa::I860, 32, None);
        }

        cpu_type::POWERPC => {
            return (Isa::Ppc, 32, None);
        }

        cpu_type::POWERPC64 => {
            return (Isa::Ppc64, 64, None);
        }

        _ => None,
    };

    (Isa::Unknown(cpu_type), 32, variant)
}

/// Parse a single Mach-O binary.
pub fn parse(data: &[u8], bits: u8, big_endian: bool) -> Result<ClassificationResult> {
    let little_endian = !big_endian;

    // Determine header size
    let header_size = if bits == 64 { 32 } else { 28 };

    if data.len() < header_size {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: header_size,
            actual: data.len(),
        });
    }

    // Read CPU type and subtype
    let cpu_type = read_u32(data, 4, little_endian)?;
    let cpu_subtype = read_u32(data, 8, little_endian)?;
    let _file_type = read_u32(data, 12, little_endian)?;
    let _ncmds = read_u32(data, 16, little_endian)?;

    // Map to ISA
    let (isa, isa_bits, variant_note) = cpu_type_to_isa(cpu_type, cpu_subtype);

    // Use the larger of header bits or ISA-detected bits
    let actual_bits = bits.max(isa_bits);

    let endianness = if big_endian {
        Endianness::Big
    } else {
        Endianness::Little
    };

    // Build variant
    let variant = match variant_note {
        Some(note) => Variant::new(note),
        None => Variant::default(),
    };

    // Extract extensions from CPU type/subtype
    let extensions = extensions_from_cpu(cpu_type, cpu_subtype);

    // Build metadata
    let metadata = ClassificationMetadata {
        raw_machine: Some(cpu_type),
        notes: vec![format!(
            "CPU subtype: 0x{:08X}",
            cpu_subtype
        )],
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, actual_bits, endianness, FileFormat::MachO);
    result.variant = variant;
    result.extensions = extensions;
    result.metadata = metadata;

    Ok(result)
}

/// Parse a fat/universal Mach-O binary.
///
/// Returns the result for the first architecture in the fat binary.
/// For comprehensive analysis of all architectures, use `parse_fat_all`.
pub fn parse_fat(data: &[u8], big_endian: bool) -> Result<ClassificationResult> {
    if data.len() < 8 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 8,
            actual: data.len(),
        });
    }

    // Fat header is always big-endian
    let nfat_arch = read_u32(data, 4, false)?;

    if nfat_arch == 0 {
        return Err(ClassifierError::MachOParseError {
            message: "Fat binary has no architectures".to_string(),
        });
    }

    // Parse first fat_arch entry (offset 8)
    if data.len() < 28 {
        return Err(ClassifierError::TruncatedData {
            offset: 8,
            expected: 20,
            actual: data.len().saturating_sub(8),
        });
    }

    let cpu_type = read_u32(data, 8, false)?;
    let cpu_subtype = read_u32(data, 12, false)?;
    let offset = read_u32(data, 16, false)? as usize;
    let size = read_u32(data, 20, false)? as usize;

    // Validate slice offset
    if offset + 4 > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset,
            expected: 4,
            actual: data.len().saturating_sub(offset),
        });
    }

    // Determine if the slice is 64-bit from magic
    let slice_magic = read_u32(data, offset, false)?;
    let (slice_bits, slice_big_endian) = match slice_magic {
        0xFEEDFACE => (32, true),
        0xCEFAEDFE => (32, false),
        0xFEEDFACF => (64, true),
        0xCFFAEDFE => (64, false),
        _ => {
            // Guess from CPU type
            let is_64 = cpu_type & cpu_type::ABI64 != 0;
            (if is_64 { 64 } else { 32 }, big_endian)
        }
    };

    // Map to ISA
    let (isa, _, variant_note) = cpu_type_to_isa(cpu_type, cpu_subtype);

    let endianness = if slice_big_endian {
        Endianness::Big
    } else {
        Endianness::Little
    };

    // Build variant
    let variant = match variant_note {
        Some(note) => Variant::new(note),
        None => Variant::default(),
    };

    // Extract extensions from CPU type/subtype
    let extensions = extensions_from_cpu(cpu_type, cpu_subtype);

    // Build metadata
    let metadata = ClassificationMetadata {
        raw_machine: Some(cpu_type),
        notes: vec![
            format!("Fat binary with {} architectures", nfat_arch),
            format!("First slice: offset={}, size={}", offset, size),
        ],
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, slice_bits, endianness, FileFormat::MachOFat);
    result.variant = variant;
    result.extensions = extensions;
    result.metadata = metadata;

    Ok(result)
}

/// Architecture entry from a fat binary.
#[derive(Debug, Clone)]
pub struct FatArchEntry {
    /// CPU type
    pub cpu_type: u32,
    /// CPU subtype
    pub cpu_subtype: u32,
    /// Offset in file
    pub offset: u32,
    /// Size in bytes
    pub size: u32,
    /// Alignment
    pub align: u32,
    /// Classification result for this architecture
    pub classification: ClassificationResult,
}

/// Parse all architectures in a fat binary.
pub fn parse_fat_all(data: &[u8]) -> Result<Vec<FatArchEntry>> {
    if data.len() < 8 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 8,
            actual: data.len(),
        });
    }

    let nfat_arch = read_u32(data, 4, false)? as usize;

    // Validate header size
    let header_size = 8 + nfat_arch * 20;
    if data.len() < header_size {
        return Err(ClassifierError::TruncatedData {
            offset: 8,
            expected: nfat_arch * 20,
            actual: data.len().saturating_sub(8),
        });
    }

    let mut entries = Vec::with_capacity(nfat_arch);

    for i in 0..nfat_arch {
        let entry_off = 8 + i * 20;

        let cpu_type = read_u32(data, entry_off, false)?;
        let cpu_subtype = read_u32(data, entry_off + 4, false)?;
        let offset = read_u32(data, entry_off + 8, false)?;
        let size = read_u32(data, entry_off + 12, false)?;
        let align = read_u32(data, entry_off + 16, false)?;

        // Map to ISA
        let (isa, bits, variant_note) = cpu_type_to_isa(cpu_type, cpu_subtype);

        // Determine endianness from slice if possible
        let off = offset as usize;
        let endianness = if off + 4 <= data.len() {
            let magic = read_u32(data, off, false)?;
            match magic {
                0xFEEDFACE | 0xFEEDFACF => Endianness::Big,
                _ => Endianness::Little,
            }
        } else {
            Endianness::Little
        };

        let variant = match variant_note {
            Some(note) => Variant::new(note),
            None => Variant::default(),
        };

    // Extract extensions from CPU type/subtype
    let extensions = extensions_from_cpu(cpu_type, cpu_subtype);

        let mut classification =
            ClassificationResult::from_format(isa, bits, endianness, FileFormat::MachO);
        classification.variant = variant;
        classification.extensions = extensions;

        entries.push(FatArchEntry {
            cpu_type,
            cpu_subtype,
            offset,
            size,
            align,
            classification,
        });
    }

    Ok(entries)
}

/// Get a human-readable description of a Mach-O CPU type.
pub fn cpu_type_description(cpu_type: u32) -> &'static str {
    match cpu_type {
        cpu_type::VAX => "DEC VAX",
        cpu_type::MC680X0 => "Motorola 68000",
        cpu_type::X86 => "Intel x86",
        cpu_type::X86_64 => "Intel x86-64",
        cpu_type::MC98000 => "Motorola MC98000",
        cpu_type::HPPA => "HP PA-RISC",
        cpu_type::ARM => "ARM",
        cpu_type::ARM64 => "ARM64 / AArch64",
        cpu_type::ARM64_32 => "ARM64_32 (ILP32)",
        cpu_type::MC88000 => "Motorola MC88000",
        cpu_type::SPARC => "SPARC",
        cpu_type::I860 => "Intel i860",
        cpu_type::POWERPC => "PowerPC",
        cpu_type::POWERPC64 => "PowerPC 64-bit",
        _ => "Unknown CPU type",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_macho_header(cpu_type: u32, cpu_subtype: u32, bits: u8) -> Vec<u8> {
        let mut data = vec![0u8; 64];

        // Magic
        if bits == 64 {
            data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // 64-bit LE
        } else {
            data[0..4].copy_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]); // 32-bit LE
        }

        // CPU type (little-endian)
        data[4] = (cpu_type & 0xFF) as u8;
        data[5] = ((cpu_type >> 8) & 0xFF) as u8;
        data[6] = ((cpu_type >> 16) & 0xFF) as u8;
        data[7] = ((cpu_type >> 24) & 0xFF) as u8;

        // CPU subtype
        data[8] = (cpu_subtype & 0xFF) as u8;
        data[9] = ((cpu_subtype >> 8) & 0xFF) as u8;
        data[10] = ((cpu_subtype >> 16) & 0xFF) as u8;
        data[11] = ((cpu_subtype >> 24) & 0xFF) as u8;

        data
    }

    #[test]
    fn test_parse_x86_64_macho() {
        let data = make_macho_header(cpu_type::X86_64, x86_64_subtype::ALL, 64);
        let result = parse(&data, 64, false).unwrap();
        assert_eq!(result.isa, Isa::X86_64);
        assert_eq!(result.bitwidth, 64);
    }

    #[test]
    fn test_parse_arm64_macho() {
        let data = make_macho_header(cpu_type::ARM64, arm64_subtype::ALL, 64);
        let result = parse(&data, 64, false).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.bitwidth, 64);
    }

    #[test]
    fn test_parse_arm64e_macho() {
        let data = make_macho_header(cpu_type::ARM64, arm64_subtype::E, 64);
        let result = parse(&data, 64, false).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert!(result.variant.name.contains("PAC"));
        // ARM64E should have PAC extension detected from subtype
        assert!(
            result.extensions.iter().any(|e| e.name == "PAC"),
            "ARM64E should have PAC extension"
        );
    }

    #[test]
    fn test_arm64_baseline_extensions() {
        // Regular ARM64 should have baseline extensions but not PAC/BTI
        let data = make_macho_header(cpu_type::ARM64, arm64_subtype::V8, 64);
        let result = parse(&data, 64, false).unwrap();
        assert_eq!(result.isa, Isa::AArch64);

        // Should have baseline Apple ARM64 extensions
        assert!(result.extensions.iter().any(|e| e.name == "NEON"));
        assert!(result.extensions.iter().any(|e| e.name == "AES"));
        assert!(result.extensions.iter().any(|e| e.name == "SHA256"));
        assert!(result.extensions.iter().any(|e| e.name == "CRC32"));
        assert!(result.extensions.iter().any(|e| e.name == "LSE"));
        assert!(result.extensions.iter().any(|e| e.name == "FP16"));
        assert!(result.extensions.iter().any(|e| e.name == "DOTPROD"));

        // Should NOT have PAC/BTI (those are ARM64E only)
        assert!(!result.extensions.iter().any(|e| e.name == "PAC"));
        assert!(!result.extensions.iter().any(|e| e.name == "BTI"));
    }

    #[test]
    fn test_arm64e_security_extensions() {
        // ARM64E should have all security extensions
        let data = make_macho_header(cpu_type::ARM64, arm64_subtype::E, 64);
        let result = parse(&data, 64, false).unwrap();
        assert_eq!(result.isa, Isa::AArch64);

        // Security extensions
        assert!(result.extensions.iter().any(|e| e.name == "PAC"));
        assert!(result.extensions.iter().any(|e| e.name == "BTI"));
        assert!(result.extensions.iter().any(|e| e.name == "DIT"));
        assert!(result.extensions.iter().any(|e| e.name == "SSBS"));
        assert!(result.extensions.iter().any(|e| e.name == "SB"));

        // Additional ARM64E features
        assert!(result.extensions.iter().any(|e| e.name == "BF16"));
        assert!(result.extensions.iter().any(|e| e.name == "I8MM"));
        assert!(result.extensions.iter().any(|e| e.name == "DPB"));
    }

    #[test]
    fn test_parse_arm_macho() {
        let data = make_macho_header(cpu_type::ARM, arm_subtype::V7, 32);
        let result = parse(&data, 32, false).unwrap();
        assert_eq!(result.isa, Isa::Arm);
        assert!(result.variant.name.contains("ARMv7"));

        // ARMv7 should have Thumb, NEON, VFP
        assert!(result.extensions.iter().any(|e| e.name == "Thumb"));
        assert!(result.extensions.iter().any(|e| e.name == "NEON"));
        assert!(result.extensions.iter().any(|e| e.name == "VFPv3"));
    }

    #[test]
    fn test_x86_64_extensions() {
        // Generic x86-64
        let data = make_macho_header(cpu_type::X86_64, x86_64_subtype::ALL, 64);
        let result = parse(&data, 64, false).unwrap();
        assert_eq!(result.isa, Isa::X86_64);

        // x86-64 baseline
        assert!(result.extensions.iter().any(|e| e.name == "SSE"));
        assert!(result.extensions.iter().any(|e| e.name == "SSE2"));
        assert!(result.extensions.iter().any(|e| e.name == "SSE3"));
    }

    #[test]
    fn test_x86_64_haswell_extensions() {
        let data = make_macho_header(cpu_type::X86_64, x86_64_subtype::H, 64);
        let result = parse(&data, 64, false).unwrap();
        assert_eq!(result.isa, Isa::X86_64);

        // Haswell has AVX2, BMI, FMA, etc.
        assert!(result.extensions.iter().any(|e| e.name == "AVX"));
        assert!(result.extensions.iter().any(|e| e.name == "AVX2"));
        assert!(result.extensions.iter().any(|e| e.name == "FMA"));
        assert!(result.extensions.iter().any(|e| e.name == "BMI1"));
        assert!(result.extensions.iter().any(|e| e.name == "BMI2"));
        assert!(result.extensions.iter().any(|e| e.name == "AES-NI"));
    }

    #[test]
    fn test_powerpc_extensions() {
        let data = make_macho_header(cpu_type::POWERPC, 0, 32);
        let result = parse(&data, 32, false).unwrap();
        assert_eq!(result.isa, Isa::Ppc);

        // PowerPC Macs had AltiVec
        assert!(result.extensions.iter().any(|e| e.name == "AltiVec"));
    }

    #[test]
    fn test_arm_v7s_extensions() {
        // V7S (Apple A6) has VFPv4
        let data = make_macho_header(cpu_type::ARM, arm_subtype::V7S, 32);
        let result = parse(&data, 32, false).unwrap();
        assert_eq!(result.isa, Isa::Arm);

        assert!(result.extensions.iter().any(|e| e.name == "VFPv4"));
        assert!(result.extensions.iter().any(|e| e.name == "NEON"));
    }

    #[test]
    fn test_arm_v6m_extensions() {
        // Cortex-M0 - Thumb only, no VFP/NEON
        let data = make_macho_header(cpu_type::ARM, arm_subtype::V6M, 32);
        let result = parse(&data, 32, false).unwrap();
        assert_eq!(result.isa, Isa::Arm);

        assert!(result.extensions.iter().any(|e| e.name == "Thumb"));
        assert!(!result.extensions.iter().any(|e| e.name == "NEON"));
        assert!(!result.extensions.iter().any(|e| e.name.contains("VFP")));
    }

    #[test]
    fn test_cpu_type_coverage() {
        assert_eq!(cpu_type_to_isa(cpu_type::X86, 0).0, Isa::X86);
        assert_eq!(cpu_type_to_isa(cpu_type::X86_64, 0).0, Isa::X86_64);
        assert_eq!(cpu_type_to_isa(cpu_type::ARM, 0).0, Isa::Arm);
        assert_eq!(cpu_type_to_isa(cpu_type::ARM64, 0).0, Isa::AArch64);
        assert_eq!(cpu_type_to_isa(cpu_type::ARM64_32, 0).0, Isa::AArch64);
        assert_eq!(cpu_type_to_isa(cpu_type::POWERPC, 0).0, Isa::Ppc);
        assert_eq!(cpu_type_to_isa(cpu_type::POWERPC64, 0).0, Isa::Ppc64);
    }
}
