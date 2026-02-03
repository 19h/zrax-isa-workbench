//! Kernel and boot image format parsers.
//!
//! This module handles:
//! - Linux zImage/bzImage (x86, ARM, etc.)
//! - U-Boot uImage
//! - Flattened Image Tree (FIT)
//! - Device Tree Blob (DTB)

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

// === Linux x86 Boot ===

/// x86 boot sector signature.
pub const BOOT_SIGNATURE: u16 = 0xAA55;

/// Linux boot header magic "HdrS"
pub const HDRS_MAGIC: [u8; 4] = [b'H', b'd', b'r', b'S'];

// === ARM64 Image ===

/// ARM64 Image magic at offset 0x38
pub const ARM64_MAGIC: u32 = 0x644D5241; // "ARM\x64"

// === RISC-V Image ===

/// RISC-V Image magic at offset 0x30
pub const RISCV_MAGIC: [u8; 8] = [b'R', b'I', b'S', b'C', b'V', 0, 0, 0];

// === U-Boot ===

/// uImage magic (big-endian)
pub const UIMAGE_MAGIC: u32 = 0x27051956;

/// FIT/DTB magic (big-endian)
pub const FDT_MAGIC: u32 = 0xD00DFEED;

/// uImage header size.
pub const UIMAGE_HEADER_SIZE: usize = 64;

/// uImage OS types.
pub mod uimage_os {
    pub const INVALID: u8 = 0;
    pub const OPENBSD: u8 = 1;
    pub const NETBSD: u8 = 2;
    pub const FREEBSD: u8 = 3;
    pub const BSD4_4: u8 = 4;
    pub const LINUX: u8 = 5;
    pub const SVR4: u8 = 6;
    pub const ESIX: u8 = 7;
    pub const SOLARIS: u8 = 8;
    pub const IRIX: u8 = 9;
    pub const SCO: u8 = 10;
    pub const DELL: u8 = 11;
    pub const NCR: u8 = 12;
    pub const LYNXOS: u8 = 13;
    pub const VXWORKS: u8 = 14;
    pub const PSOS: u8 = 15;
    pub const QNX: u8 = 16;
    pub const UBOOT: u8 = 17;
    pub const RTEMS: u8 = 18;
    pub const ARTOS: u8 = 19;
    pub const UNITY: u8 = 20;
    pub const INTEGRITY: u8 = 21;
    pub const OSE: u8 = 22;
    pub const PLAN9: u8 = 23;
    pub const OPENRTOS: u8 = 24;
    pub const ARM_TRUSTED: u8 = 25;
    pub const TEE: u8 = 26;
    pub const OPENSBI: u8 = 27;
    pub const EFI: u8 = 28;
}

/// uImage architecture types.
pub mod uimage_arch {
    pub const INVALID: u8 = 0;
    pub const ALPHA: u8 = 1;
    pub const ARM: u8 = 2;
    pub const X86: u8 = 3;
    pub const IA64: u8 = 4;
    pub const MIPS: u8 = 5;
    pub const MIPS64: u8 = 6;
    pub const PPC: u8 = 7;
    pub const S390: u8 = 8;
    pub const SH: u8 = 9;
    pub const SPARC: u8 = 10;
    pub const SPARC64: u8 = 11;
    pub const M68K: u8 = 12;
    pub const NIOS: u8 = 13;
    pub const MICROBLAZE: u8 = 14;
    pub const NIOS2: u8 = 15;
    pub const BLACKFIN: u8 = 16;
    pub const AVR32: u8 = 17;
    pub const ST200: u8 = 18;
    pub const SANDBOX: u8 = 19;
    pub const NDS32: u8 = 20;
    pub const OPENRISC: u8 = 21;
    pub const ARM64: u8 = 22;
    pub const ARC: u8 = 23;
    pub const X86_64: u8 = 24;
    pub const XTENSA: u8 = 25;
    pub const RISCV: u8 = 26;
}

/// uImage compression types.
pub mod uimage_comp {
    pub const NONE: u8 = 0;
    pub const GZIP: u8 = 1;
    pub const BZIP2: u8 = 2;
    pub const LZMA: u8 = 3;
    pub const LZO: u8 = 4;
    pub const LZ4: u8 = 5;
    pub const ZSTD: u8 = 6;
}

/// uImage image types.
pub mod uimage_type {
    pub const INVALID: u8 = 0;
    pub const STANDALONE: u8 = 1;
    pub const KERNEL: u8 = 2;
    pub const RAMDISK: u8 = 3;
    pub const MULTI: u8 = 4;
    pub const FIRMWARE: u8 = 5;
    pub const SCRIPT: u8 = 6;
    pub const FILESYSTEM: u8 = 7;
    pub const FLATDT: u8 = 8;
    pub const KWBIMAGE: u8 = 9;
    pub const IMXIMAGE: u8 = 10;
    pub const GPIMAGE: u8 = 16;
    pub const ATMELIMAGE: u8 = 17;
    pub const FIT: u8 = 18;
}

/// Detected kernel/boot format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFormat {
    /// Linux x86 bzImage/zImage
    LinuxX86 { protocol_version: u16 },
    /// Linux ARM64 Image
    LinuxArm64,
    /// Linux RISC-V Image
    LinuxRiscv,
    /// U-Boot uImage
    UImage { arch: u8, os: u8, image_type: u8 },
    /// Flattened Image Tree or DTB
    Fit,
    /// Device Tree Blob
    Dtb,
}

/// Detect kernel/boot format.
pub fn detect(data: &[u8]) -> Option<KernelFormat> {
    if data.len() < 4 {
        return None;
    }

    // Check for uImage magic (big-endian)
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic_be == UIMAGE_MAGIC && data.len() >= UIMAGE_HEADER_SIZE {
        let os = data[0x1C];
        let arch = data[0x1D];
        let image_type = data[0x1E];
        return Some(KernelFormat::UImage {
            arch,
            os,
            image_type,
        });
    }

    // Check for FIT/DTB magic
    if magic_be == FDT_MAGIC {
        // Could be FIT or plain DTB - check for FIT structure
        // For now, assume DTB
        return Some(KernelFormat::Dtb);
    }

    // Check for ARM64 Image (magic at offset 0x38)
    if data.len() >= 0x40 {
        let arm64_magic = u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]);
        if arm64_magic == ARM64_MAGIC {
            return Some(KernelFormat::LinuxArm64);
        }
    }

    // Check for RISC-V Image (magic at offset 0x30)
    if data.len() >= 0x38 {
        if data[0x30..0x35] == RISCV_MAGIC[0..5] {
            return Some(KernelFormat::LinuxRiscv);
        }
    }

    // Check for x86 bzImage (boot signature at 0x1FE, HdrS at 0x202)
    if data.len() >= 0x210 {
        let boot_sig = u16::from_le_bytes([data[0x1FE], data[0x1FF]]);
        if boot_sig == BOOT_SIGNATURE {
            if data[0x202..0x206] == HDRS_MAGIC {
                let protocol = u16::from_le_bytes([data[0x206], data[0x207]]);
                return Some(KernelFormat::LinuxX86 {
                    protocol_version: protocol,
                });
            }
        }
    }

    None
}

/// Map uImage arch to ISA.
fn uimage_arch_to_isa(arch: u8) -> (Isa, u8) {
    match arch {
        uimage_arch::ARM => (Isa::Arm, 32),
        uimage_arch::ARM64 => (Isa::AArch64, 64),
        uimage_arch::X86 => (Isa::X86, 32),
        uimage_arch::X86_64 => (Isa::X86_64, 64),
        uimage_arch::MIPS => (Isa::Mips, 32),
        uimage_arch::MIPS64 => (Isa::Mips64, 64),
        uimage_arch::PPC => (Isa::Ppc, 32),
        uimage_arch::SPARC => (Isa::Sparc, 32),
        uimage_arch::SPARC64 => (Isa::Sparc64, 64),
        uimage_arch::M68K => (Isa::M68k, 32),
        uimage_arch::SH => (Isa::Sh, 32),
        uimage_arch::ALPHA => (Isa::Alpha, 64),
        uimage_arch::S390 => (Isa::S390, 32),
        uimage_arch::IA64 => (Isa::Ia64, 64),
        uimage_arch::RISCV => (Isa::RiscV64, 64),
        uimage_arch::MICROBLAZE => (Isa::MicroBlaze, 32),
        uimage_arch::NIOS2 => (Isa::Nios2, 32),
        uimage_arch::BLACKFIN => (Isa::Blackfin, 32),
        uimage_arch::XTENSA => (Isa::Xtensa, 32),
        uimage_arch::ARC => (Isa::Arc, 32),
        uimage_arch::OPENRISC => (Isa::OpenRisc, 32),
        _ => (Isa::Unknown(arch as u32), 32),
    }
}

/// Get uImage OS name.
fn uimage_os_name(os: u8) -> &'static str {
    match os {
        uimage_os::LINUX => "Linux",
        uimage_os::NETBSD => "NetBSD",
        uimage_os::FREEBSD => "FreeBSD",
        uimage_os::OPENBSD => "OpenBSD",
        uimage_os::VXWORKS => "VxWorks",
        uimage_os::QNX => "QNX",
        uimage_os::UBOOT => "U-Boot",
        uimage_os::RTEMS => "RTEMS",
        uimage_os::PLAN9 => "Plan 9",
        uimage_os::EFI => "EFI",
        uimage_os::ARM_TRUSTED => "ARM Trusted Firmware",
        uimage_os::TEE => "TEE",
        uimage_os::OPENSBI => "OpenSBI",
        _ => "Unknown",
    }
}

/// Get uImage arch name.
fn uimage_arch_name(arch: u8) -> &'static str {
    match arch {
        uimage_arch::ARM => "ARM",
        uimage_arch::ARM64 => "ARM64",
        uimage_arch::X86 => "x86",
        uimage_arch::X86_64 => "x86-64",
        uimage_arch::MIPS => "MIPS",
        uimage_arch::MIPS64 => "MIPS64",
        uimage_arch::PPC => "PowerPC",
        uimage_arch::SPARC => "SPARC",
        uimage_arch::SPARC64 => "SPARC64",
        uimage_arch::RISCV => "RISC-V",
        uimage_arch::MICROBLAZE => "MicroBlaze",
        _ => "Unknown",
    }
}

/// Get compression name.
fn comp_name(comp: u8) -> &'static str {
    match comp {
        uimage_comp::NONE => "none",
        uimage_comp::GZIP => "gzip",
        uimage_comp::BZIP2 => "bzip2",
        uimage_comp::LZMA => "lzma",
        uimage_comp::LZO => "lzo",
        uimage_comp::LZ4 => "lz4",
        uimage_comp::ZSTD => "zstd",
        _ => "unknown",
    }
}

/// Parse Linux x86 bzImage.
fn parse_linux_x86(data: &[u8], protocol: u16) -> Result<ClassificationResult> {
    let setup_sects = data[0x1F1] as u32;
    let setup_sects = if setup_sects == 0 { 4 } else { setup_sects };
    let _root_flags = read_u16(data, 0x1F2, true)?;
    let _syssize = read_u32(data, 0x1F4, true)?;

    let loadflags = data[0x211];
    let _code32_start = read_u32(data, 0x214, true)?;
    let _ramdisk_image = read_u32(data, 0x218, true)?;
    let _ramdisk_size = read_u32(data, 0x21C, true)?;

    let kernel_type = if loadflags & 0x01 != 0 {
        "bzImage (big zImage)"
    } else {
        "zImage"
    };

    let mut notes = vec!["Linux x86 boot image".to_string()];
    notes.push(format!("Type: {}", kernel_type));
    notes.push(format!(
        "Protocol version: {}.{}",
        protocol >> 8,
        protocol & 0xFF
    ));
    notes.push(format!("Setup sectors: {}", setup_sects));

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86, 32, Endianness::Little, FileFormat::ZImage);
    result.variant = Variant::new(kernel_type);
    result.metadata = metadata;

    Ok(result)
}

/// Parse Linux ARM64 Image.
fn parse_linux_arm64(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 0x40 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 0x40,
            actual: data.len(),
        });
    }

    let text_offset = read_u32(data, 8, true)? as u64 | ((read_u32(data, 12, true)? as u64) << 32);
    let image_size = read_u32(data, 16, true)? as u64 | ((read_u32(data, 20, true)? as u64) << 32);

    let mut notes = vec!["Linux ARM64 Image".to_string()];
    notes.push(format!("Text offset: 0x{:X}", text_offset));
    notes.push(format!("Image size: {} bytes", image_size));

    let metadata = ClassificationMetadata {
        code_size: Some(image_size),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::AArch64, 64, Endianness::Little, FileFormat::ZImage);
    result.variant = Variant::new("ARM64 Image");
    result.metadata = metadata;

    Ok(result)
}

/// Parse Linux RISC-V Image.
fn parse_linux_riscv(data: &[u8]) -> Result<ClassificationResult> {
    let mut notes = vec!["Linux RISC-V Image".to_string()];

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::RiscV64, 64, Endianness::Little, FileFormat::ZImage);
    result.variant = Variant::new("RISC-V Image");
    result.metadata = metadata;

    Ok(result)
}

/// Parse uImage.
fn parse_uimage(data: &[u8], arch: u8, os: u8, image_type: u8) -> Result<ClassificationResult> {
    if data.len() < UIMAGE_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: UIMAGE_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // uImage header is big-endian
    let _header_crc = read_u32(data, 4, false)?;
    let timestamp = read_u32(data, 8, false)?;
    let data_size = read_u32(data, 12, false)?;
    let load_addr = read_u32(data, 16, false)?;
    let entry_point = read_u32(data, 20, false)?;
    let _data_crc = read_u32(data, 24, false)?;
    let compression = data[0x1F];

    // Read image name (null-terminated, 32 bytes max)
    let name_bytes = &data[0x20..0x40];
    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
    let name = String::from_utf8_lossy(&name_bytes[..name_len]);

    let (isa, bitwidth) = uimage_arch_to_isa(arch);

    let mut notes = vec!["U-Boot uImage".to_string()];
    if !name.is_empty() {
        notes.push(format!("Name: {}", name));
    }
    notes.push(format!("OS: {}", uimage_os_name(os)));
    notes.push(format!("Architecture: {}", uimage_arch_name(arch)));
    notes.push(format!("Compression: {}", comp_name(compression)));
    notes.push(format!("Data size: {} bytes", data_size));
    notes.push(format!("Load address: 0x{:08X}", load_addr));
    notes.push(format!("Entry point: 0x{:08X}", entry_point));

    let metadata = ClassificationMetadata {
        entry_point: Some(entry_point as u64),
        code_size: Some(data_size as u64),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, bitwidth, Endianness::Big, FileFormat::UImage);
    result.variant = Variant::new(format!("{} {}", uimage_os_name(os), uimage_arch_name(arch)));
    result.metadata = metadata;

    Ok(result)
}

/// Parse DTB.
fn parse_dtb(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 40 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 40,
            actual: data.len(),
        });
    }

    let totalsize = read_u32(data, 4, false)?;
    let off_dt_struct = read_u32(data, 8, false)?;
    let off_dt_strings = read_u32(data, 12, false)?;
    let _off_mem_rsvmap = read_u32(data, 16, false)?;
    let version = read_u32(data, 20, false)?;
    let _last_comp_version = read_u32(data, 24, false)?;

    let mut notes = vec!["Device Tree Blob".to_string()];
    notes.push(format!("Version: {}", version));
    notes.push(format!("Total size: {} bytes", totalsize));
    notes.push(format!("Struct offset: 0x{:X}", off_dt_struct));
    notes.push(format!("Strings offset: 0x{:X}", off_dt_strings));

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    // DTB is ISA-independent
    let mut result =
        ClassificationResult::from_format(Isa::Unknown(0), 0, Endianness::Big, FileFormat::Dtb);
    result.variant = Variant::new("FDT");
    result.metadata = metadata;

    Ok(result)
}

/// Parse kernel/boot format.
pub fn parse(data: &[u8], format: KernelFormat) -> Result<ClassificationResult> {
    match format {
        KernelFormat::LinuxX86 { protocol_version } => parse_linux_x86(data, protocol_version),
        KernelFormat::LinuxArm64 => parse_linux_arm64(data),
        KernelFormat::LinuxRiscv => parse_linux_riscv(data),
        KernelFormat::UImage {
            arch,
            os,
            image_type,
        } => parse_uimage(data, arch, os, image_type),
        KernelFormat::Fit | KernelFormat::Dtb => parse_dtb(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uimage_header(arch: u8, os: u8) -> Vec<u8> {
        let mut data = vec![0u8; UIMAGE_HEADER_SIZE + 64];

        // Magic
        data[0..4].copy_from_slice(&UIMAGE_MAGIC.to_be_bytes());
        // Data size
        data[12..16].copy_from_slice(&64u32.to_be_bytes());
        // Load address
        data[16..20].copy_from_slice(&0x80008000u32.to_be_bytes());
        // Entry point
        data[20..24].copy_from_slice(&0x80008000u32.to_be_bytes());
        // OS
        data[0x1C] = os;
        // Arch
        data[0x1D] = arch;
        // Type
        data[0x1E] = uimage_type::KERNEL;
        // Compression
        data[0x1F] = uimage_comp::NONE;
        // Name
        data[0x20..0x2A].copy_from_slice(b"Test Image");

        data
    }

    #[test]
    fn test_detect_uimage() {
        let data = make_uimage_header(uimage_arch::ARM, uimage_os::LINUX);
        let format = detect(&data);
        assert!(matches!(format, Some(KernelFormat::UImage { .. })));
    }

    #[test]
    fn test_parse_uimage_arm() {
        let data = make_uimage_header(uimage_arch::ARM, uimage_os::LINUX);
        let format = detect(&data).unwrap();
        let result = parse(&data, format).unwrap();
        assert_eq!(result.isa, Isa::Arm);
        assert_eq!(result.format, FileFormat::UImage);
    }

    #[test]
    fn test_parse_uimage_riscv() {
        let data = make_uimage_header(uimage_arch::RISCV, uimage_os::LINUX);
        let format = detect(&data).unwrap();
        let result = parse(&data, format).unwrap();
        assert_eq!(result.isa, Isa::RiscV64);
        assert_eq!(result.format, FileFormat::UImage);
    }
}
