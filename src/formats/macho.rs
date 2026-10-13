//! Mach-O (Mach Object) parser: the header (`cputype`, `cpusubtype`), fat
//! headers and load commands.
//!
//! Sources, pinned (SHA-256 of each file in `docs/macho.md`):
//! - apple-oss-distributions/xnu tag `xnu-12377.121.6`
//!   (`ac9718fb1af618d5ce8678d0dc6e8a58f252216f`):
//!   `EXTERNAL_HEADERS/mach-o/loader.h` for the header, the load commands,
//!   segments, sections, `LC_BUILD_VERSION` platforms and
//!   `LC_FILESET_ENTRY`; `EXTERNAL_HEADERS/mach-o/fixup-chains.h`;
//!   `osfmk/mach/vm_prot.h`; `bsd/kern/mach_loader.c` (`load_threadstate`)
//!   for the walk over `LC_UNIXTHREAD` thread states.
//! - apple-oss-distributions/cctools tag `cctools-1035.1.102`:
//!   `include/mach-o/loader.h` (the platforms after `PLATFORM_XROSSIMULATOR`
//!   and the `MH_GPU_*` file types), `include/mach-o/fat.h`, and
//!   `include/mach/{i386,arm,ppc}/{thread_status.h,_structs.h}` for where a
//!   thread state keeps the program counter.
//! - apple-oss-distributions/dyld tag `dyld-1378`: `common/MachOFile.cpp`
//!   (`forEachLoadCommand`, `validSegments`) for the load-command rules
//!   dyld enforces.
//!
//! The ISA comes from `cputype` alone; load commands never change it. They
//! add the image's segments and sections, platform, entry point, UUID and
//! code-signature, encryption and chained-fixup records, and locate the
//! instruction sections that extension detection scans. An `MH_FILESET`
//! (an Apple silicon kernelcache) lists its entries, each a Mach-O image in
//! the fileset's own file coordinates.

use crate::error::{ClassifierError, Result};
use crate::formats::magic::{MACHO_32_BE, MACHO_32_LE, MACHO_64_BE, MACHO_64_LE};
use crate::formats::{read_u32, read_u64, MAX_PAYLOAD};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, Extension, ExtensionCategory,
    FileFormat, Isa, MetadataEntry, MetadataKey, MetadataValue, Variant,
};
use std::borrow::Cow;

mod commands;
mod platform;
mod report;
mod segments;
mod thread;

pub use segments::Code;

/// Prefix of the family's metadata keys (`macho_platform`,
/// `macho_segment_0`).
const KEY_PREFIX: &str = "macho";

/// `mach_header` and `mach_header_64` sizes.
const MACH_HEADER_SIZE: usize = 28;
const MACH_HEADER_64_SIZE: usize = 32;

/// `filetype` values (xnu `loader.h`; `MH_GPU_*` from cctools).
const MH_OBJECT: u32 = 0x1;
const MH_EXECUTE: u32 = 0x2;
const MH_FVMLIB: u32 = 0x3;
const MH_CORE: u32 = 0x4;
const MH_PRELOAD: u32 = 0x5;
const MH_DYLIB: u32 = 0x6;
const MH_DYLINKER: u32 = 0x7;
const MH_BUNDLE: u32 = 0x8;
const MH_DYLIB_STUB: u32 = 0x9;
const MH_DSYM: u32 = 0xA;
const MH_KEXT_BUNDLE: u32 = 0xB;
const MH_FILESET: u32 = 0xC;
const MH_GPU_EXECUTE: u32 = 0xD;
const MH_GPU_DYLIB: u32 = 0xE;

/// `flags`: the image is part of a dyld shared cache (and, as observed,
/// of a kernel collection), so its file offsets refer to the containing
/// file.
const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

/// Most segments and sections listed in metadata; the notes count the
/// rest.
const MAX_LISTED_SEGMENTS: usize = 64;
const MAX_LISTED_SECTIONS: usize = 128;

/// The family's parse error.
fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::MachOParseError {
        message: message.into(),
    }
}

/// A Mach-O header (`mach_header` or `mach_header_64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// File offset of the header in the input.
    pub offset: usize,
    /// A 64-bit header (`MH_MAGIC_64`, 32 B) rather than a 32-bit one
    /// (`MH_MAGIC`, 28 B).
    pub is_64: bool,
    /// The header and load commands are little-endian.
    pub little_endian: bool,
    /// `cputype`.
    pub cpu_type: u32,
    /// `cpusubtype`.
    pub cpu_subtype: u32,
    /// `filetype` (`MH_EXECUTE`, `MH_FILESET`, ...).
    pub file_type: u32,
    /// `ncmds`: number of load commands.
    pub command_count: u32,
    /// `sizeofcmds`: bytes of all load commands.
    pub commands_size: u32,
    /// `flags`.
    pub flags: u32,
}

impl Header {
    /// Read the header at file offset `offset` of `data`.
    ///
    /// Layout: `magic` (4), `cputype` (4), `cpusubtype` (4), `filetype`
    /// (4), `ncmds` (4), `sizeofcmds` (4), `flags` (4), and in 64-bit
    /// headers `reserved` (4).
    ///
    /// # Errors
    ///
    /// [`ClassifierError::MachOParseError`] when there is no Mach-O magic
    /// at `offset` or the header does not fit.
    pub fn read(data: &[u8], offset: usize) -> Result<Self> {
        let header = data.get(offset..).unwrap_or_default();
        let magic: [u8; 4] = header
            .get(..4)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| error(format!("Truncated Mach-O header at 0x{offset:X}")))?;
        let (is_64, little_endian) = match magic {
            MACHO_32_LE => (false, true),
            MACHO_64_LE => (true, true),
            MACHO_32_BE => (false, false),
            MACHO_64_BE => (true, false),
            _ => {
                return Err(error(format!(
                    "Missing Mach-O magic at 0x{offset:X}: found {}",
                    hex::encode_upper(magic)
                )))
            }
        };
        let size = if is_64 {
            MACH_HEADER_64_SIZE
        } else {
            MACH_HEADER_SIZE
        };
        if header.len() < size {
            return Err(error(format!(
                "Truncated Mach-O header at 0x{offset:X}: {size} B needed, {} B present",
                header.len()
            )));
        }
        let le = little_endian;
        Ok(Self {
            offset,
            is_64,
            little_endian,
            cpu_type: read_u32(header, 4, le)?,
            cpu_subtype: read_u32(header, 8, le)?,
            file_type: read_u32(header, 12, le)?,
            command_count: read_u32(header, 16, le)?,
            commands_size: read_u32(header, 20, le)?,
            flags: read_u32(header, 24, le)?,
        })
    }

    /// Header size in bytes: 32 for `mach_header_64`, 28 otherwise.
    pub fn size(&self) -> usize {
        if self.is_64 {
            MACH_HEADER_64_SIZE
        } else {
            MACH_HEADER_SIZE
        }
    }

    /// Header and load commands in bytes.
    pub fn size_with_commands(&self) -> u64 {
        self.size() as u64 + u64::from(self.commands_size)
    }

    /// The `loader.h` name of the file type, if it has one.
    pub fn file_type_name(&self) -> Option<&'static str> {
        let name = match self.file_type {
            MH_OBJECT => "MH_OBJECT",
            MH_EXECUTE => "MH_EXECUTE",
            MH_FVMLIB => "MH_FVMLIB",
            MH_CORE => "MH_CORE",
            MH_PRELOAD => "MH_PRELOAD",
            MH_DYLIB => "MH_DYLIB",
            MH_DYLINKER => "MH_DYLINKER",
            MH_BUNDLE => "MH_BUNDLE",
            MH_DYLIB_STUB => "MH_DYLIB_STUB",
            MH_DSYM => "MH_DSYM",
            MH_KEXT_BUNDLE => "MH_KEXT_BUNDLE",
            MH_FILESET => "MH_FILESET",
            MH_GPU_EXECUTE => "MH_GPU_EXECUTE",
            MH_GPU_DYLIB => "MH_GPU_DYLIB",
            _ => return None,
        };
        Some(name)
    }

    /// A set of Mach-O images (`MH_FILESET`), such as a kernel collection.
    pub fn is_fileset(&self) -> bool {
        self.file_type == MH_FILESET
    }
}

/// A segment (`LC_SEGMENT` or `LC_SEGMENT_64`) and its sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// `segname`.
    pub name: String,
    /// `vmaddr`: target address.
    pub vm_address: u64,
    /// `vmsize` in bytes.
    pub vm_size: u64,
    /// `fileoff`: file offset of the mapped bytes.
    pub file_offset: u64,
    /// `filesize`: bytes mapped from the file.
    pub file_size: u64,
    /// `maxprot` (`VM_PROT_*` bits).
    pub max_protection: u32,
    /// `initprot` (`VM_PROT_*` bits).
    pub initial_protection: u32,
    /// The segment's sections in command order.
    pub sections: Vec<Section>,
}

/// A section (`section` or `section_64`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// `sectname`.
    pub name: String,
    /// `segname`: the segment the section names (normally its own).
    pub segment_name: String,
    /// `addr`: target address.
    pub address: u64,
    /// `size` in bytes.
    pub size: u64,
    /// `offset`: file offset of the section's bytes.
    pub offset: u32,
    /// `flags`: section type (low byte) and attributes.
    pub flags: u32,
}

/// The platform and OS versions of `LC_BUILD_VERSION` or an
/// `LC_VERSION_MIN_*` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildVersion {
    /// The load command that holds the record.
    pub command: u32,
    /// `PLATFORM_*` value; for `LC_VERSION_MIN_*` the platform the command
    /// names.
    pub platform: u32,
    /// Minimum OS version, `xxxx.yy.zz` nibbles.
    pub min_os: u32,
    /// SDK version, `xxxx.yy.zz` nibbles; 0 when not recorded.
    pub sdk: u32,
}

/// How the image names its entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// `LC_MAIN`: file offset of `main()` from the start of the image.
    Main {
        /// `entryoff` in bytes.
        file_offset: u64,
    },
    /// `LC_UNIXTHREAD`: the initial thread state.
    Thread {
        /// First thread-state flavor in the command.
        flavor: u32,
        /// Program counter, when the flavor is decoded for the CPU type.
        address: Option<u64>,
        /// Name of the decoded flavor (`x86_THREAD_STATE64`).
        flavor_name: Option<&'static str>,
    },
}

/// A blob in `__LINKEDIT` (`linkedit_data_command`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataRange {
    /// `dataoff`: file offset.
    pub offset: u32,
    /// `datasize` in bytes.
    pub size: u32,
}

/// An `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encryption {
    /// The load command.
    pub command: u32,
    /// `cryptoff`: file offset of the encrypted range.
    pub offset: u32,
    /// `cryptsize` in bytes.
    pub size: u32,
    /// `cryptid`: encryption system; 0 means not encrypted.
    pub id: u32,
}

impl Encryption {
    /// The range is encrypted (`cryptid` is not 0).
    pub fn is_encrypted(&self) -> bool {
        self.id != 0
    }
}

/// An `LC_FILESET_ENTRY`: one image of an `MH_FILESET`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesetEntry {
    /// `entry_id` (a bundle identifier such as `com.apple.kernel`).
    pub id: String,
    /// `vmaddr`: target address of the entry's header.
    pub vm_address: u64,
    /// `fileoff`: file offset of the entry's Mach-O header in the fileset.
    pub file_offset: u64,
}

/// A Mach-O image: its header and what its load commands describe.
#[derive(Debug, Clone)]
pub struct Image {
    /// The header.
    pub header: Header,
    /// Segments in command order.
    pub segments: Vec<Segment>,
    /// `LC_BUILD_VERSION` and `LC_VERSION_MIN_*` records in command order.
    pub build_versions: Vec<BuildVersion>,
    /// The entry point command (`LC_MAIN` before `LC_UNIXTHREAD`).
    pub entry: Option<Entry>,
    /// `LC_UUID`.
    pub uuid: Option<[u8; 16]>,
    /// `LC_CODE_SIGNATURE`.
    pub code_signature: Option<DataRange>,
    /// `LC_DYLD_CHAINED_FIXUPS`.
    pub chained_fixups: Option<DataRange>,
    /// `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64`.
    pub encryption: Option<Encryption>,
    /// `LC_FILESET_ENTRY` records in command order.
    pub fileset: Vec<FilesetEntry>,
    /// Load commands that repeat or contradict earlier ones, as notes.
    pub remarks: Vec<String>,
    /// The file offsets in the load commands locate bytes of the input.
    /// False for an `MH_DYLIB_IN_CACHE` image read on its own (a dyld cache
    /// member), whose offsets refer to the containing file.
    pub offsets_in_input: bool,
}

/// Parse the Mach-O image that starts at the beginning of `data`: a thin
/// file, a fat slice or a container member. Its file offsets are offsets
/// in `data`, unless it is part of a dyld cache or kernel collection.
///
/// # Errors
///
/// [`ClassifierError::MachOParseError`] for a missing or truncated header,
/// load commands that do not fit `sizeofcmds` or the input, or a load
/// command that is smaller than its structure.
pub fn parse_image(data: &[u8]) -> Result<Image> {
    let header = Header::read(data, 0)?;
    let offsets_in_input = header.flags & MH_DYLIB_IN_CACHE == 0;
    commands::read_image(data, header, offsets_in_input)
}

/// Parse the image of a fileset entry. Its header is at the entry's file
/// offset and its load commands give file offsets in the fileset `data`.
///
/// # Errors
///
/// As [`parse_image`], and for an entry that points at the fileset's own
/// header.
pub fn parse_fileset_entry(data: &[u8], entry: &FilesetEntry) -> Result<Image> {
    let offset = usize::try_from(entry.file_offset)
        .ok()
        .filter(|&offset| offset > 0)
        .ok_or_else(|| {
            error(format!(
                "Invalid fileset entry {}: file offset 0x{:X}",
                entry.id, entry.file_offset
            ))
        })?;
    let header = Header::read(data, offset)?;
    commands::read_image(data, header, true)
}

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
        notes: vec![format!("CPU subtype: 0x{:08X}", cpu_subtype)],
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
    pub offset: u64,
    /// Size in bytes
    pub size: u64,
    /// Alignment
    pub align: u32,
    /// Classification result for this architecture
    pub classification: ClassificationResult,
}

/// Parse all architectures in a fat binary.
///
/// When `fat64` is true, each entry is a 32-byte `fat_arch_64` struct
/// (with 64-bit offset, size, and an extra reserved field).
/// When false, each entry is the standard 20-byte `fat_arch`.
pub fn parse_fat_all(data: &[u8], fat64: bool) -> Result<Vec<FatArchEntry>> {
    if data.len() < 8 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 8,
            actual: data.len(),
        });
    }

    let nfat_arch = read_u32(data, 4, false)? as usize;
    let entry_size: usize = if fat64 { 32 } else { 20 };

    // Validate header size
    let header_size = 8 + nfat_arch * entry_size;
    if data.len() < header_size {
        return Err(ClassifierError::TruncatedData {
            offset: 8,
            expected: nfat_arch * entry_size,
            actual: data.len().saturating_sub(8),
        });
    }

    let mut entries = Vec::with_capacity(nfat_arch);

    for i in 0..nfat_arch {
        let entry_off = 8 + i * entry_size;

        let cpu_type = read_u32(data, entry_off, false)?;
        let cpu_subtype = read_u32(data, entry_off + 4, false)?;

        let (offset, size, align) = if fat64 {
            // fat_arch_64: cpu_type(4) cpu_subtype(4) offset(8) size(8) align(4) reserved(4)
            let off_hi = read_u32(data, entry_off + 8, false)? as u64;
            let off_lo = read_u32(data, entry_off + 12, false)? as u64;
            let offset = (off_hi << 32) | off_lo;
            let sz_hi = read_u32(data, entry_off + 16, false)? as u64;
            let sz_lo = read_u32(data, entry_off + 20, false)? as u64;
            let size = (sz_hi << 32) | sz_lo;
            let align = read_u32(data, entry_off + 24, false)?;
            (offset, size, align)
        } else {
            let offset = read_u32(data, entry_off + 8, false)? as u64;
            let size = read_u32(data, entry_off + 12, false)? as u64;
            let align = read_u32(data, entry_off + 16, false)?;
            (offset, size, align)
        };

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
