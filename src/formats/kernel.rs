//! Kernel and boot images: Linux kernel images (x86 `bzImage`, Arm `zImage`,
//! 64-bit Arm and RISC-V `Image`), U-Boot legacy `uImage`s and FIT images, and
//! flattened device trees.
//!
//! Sources:
//! - U-Boot v2024.10 `include/image.h` (uImage header and the OS,
//!   architecture, image type and compression IDs), `boot/image.c` (the
//!   FIT names of those IDs) and `doc/usage/fit/source_file_format.rst`
//!   (FIT `/images` nodes and external data).
//! - Devicetree Specification v0.4, chapter 5 (flattened devicetree).
//! - Linux v6.6: `Documentation/arch/x86/boot.rst` (setup header),
//!   `arch/arm/boot/compressed/head.S` (zImage header),
//!   `Documentation/arch/arm64/booting.rst`,
//!   `Documentation/arch/riscv/boot-image-header.rst` and `lib/decompress.c`
//!   (how the kernel identifies its compressed payload).
//!
//! Header byte order and code byte order are separate: uImage and FDT
//! headers are always big-endian, and the code byte order comes from the
//! architecture field when it determines one, otherwise from the payload.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{Child, Container, Target};
use crate::types::{ClassificationResult, Endianness, FileFormat, Isa};
use std::borrow::Cow;

mod fdt;
mod fit;
mod linux;
mod uimage;

/// x86 boot sector signature.
pub const BOOT_SIGNATURE: u16 = 0xAA55;

/// Linux boot header magic `HdrS`
pub const HDRS_MAGIC: [u8; 4] = *b"HdrS";

/// ARM64 Image magic at offset 0x38
pub const ARM64_MAGIC: u32 = 0x644D_5241; // "ARM\x64"

/// RISC-V Image magic at offset 0x30
pub const RISCV_MAGIC: [u8; 8] = [b'R', b'I', b'S', b'C', b'V', 0, 0, 0];

/// Arm zImage magic at offset 0x24, stored little-endian.
pub const ZIMAGE_MAGIC: u32 = 0x016F_2818;

/// uImage magic (big-endian)
pub const UIMAGE_MAGIC: u32 = 0x2705_1956;

/// FIT/DTB magic (big-endian)
pub const FDT_MAGIC: u32 = 0xD00D_FEED;

/// uImage header size.
pub const UIMAGE_HEADER_SIZE: usize = 64;

/// uImage OS types.
pub mod uimage_os {
    /// Invalid OS.
    pub const INVALID: u8 = 0;
    /// OpenBSD.
    pub const OPENBSD: u8 = 1;
    /// NetBSD.
    pub const NETBSD: u8 = 2;
    /// FreeBSD.
    pub const FREEBSD: u8 = 3;
    /// 4.4BSD.
    pub const BSD4_4: u8 = 4;
    /// Linux.
    pub const LINUX: u8 = 5;
    /// SVR4.
    pub const SVR4: u8 = 6;
    /// Esix.
    pub const ESIX: u8 = 7;
    /// Solaris.
    pub const SOLARIS: u8 = 8;
    /// Irix.
    pub const IRIX: u8 = 9;
    /// SCO.
    pub const SCO: u8 = 10;
    /// Dell.
    pub const DELL: u8 = 11;
    /// NCR.
    pub const NCR: u8 = 12;
    /// `LynxOS`.
    pub const LYNXOS: u8 = 13;
    /// `VxWorks`.
    pub const VXWORKS: u8 = 14;
    /// pSOS.
    pub const PSOS: u8 = 15;
    /// QNX.
    pub const QNX: u8 = 16;
    /// U-Boot firmware.
    pub const UBOOT: u8 = 17;
    /// RTEMS.
    pub const RTEMS: u8 = 18;
    /// ARTOS.
    pub const ARTOS: u8 = 19;
    /// Unity OS.
    pub const UNITY: u8 = 20;
    /// INTEGRITY.
    pub const INTEGRITY: u8 = 21;
    /// OSE.
    pub const OSE: u8 = 22;
    /// Plan 9.
    pub const PLAN9: u8 = 23;
    /// `OpenRTOS`.
    pub const OPENRTOS: u8 = 24;
    /// Arm Trusted Firmware.
    pub const ARM_TRUSTED: u8 = 25;
    /// Trusted execution environment.
    pub const TEE: u8 = 26;
    /// RISC-V `OpenSBI`.
    pub const OPENSBI: u8 = 27;
    /// EFI firmware.
    pub const EFI: u8 = 28;
}

/// uImage architecture types.
pub mod uimage_arch {
    /// Invalid CPU.
    pub const INVALID: u8 = 0;
    /// Alpha.
    pub const ALPHA: u8 = 1;
    /// 32-bit Arm.
    pub const ARM: u8 = 2;
    /// Intel x86.
    pub const X86: u8 = 3;
    /// IA-64.
    pub const IA64: u8 = 4;
    /// MIPS.
    pub const MIPS: u8 = 5;
    /// MIPS64.
    pub const MIPS64: u8 = 6;
    /// PowerPC.
    pub const PPC: u8 = 7;
    /// IBM S/390.
    pub const S390: u8 = 8;
    /// `SuperH`.
    pub const SH: u8 = 9;
    /// SPARC.
    pub const SPARC: u8 = 10;
    /// SPARC64.
    pub const SPARC64: u8 = 11;
    /// M68K.
    pub const M68K: u8 = 12;
    /// Nios-32.
    pub const NIOS: u8 = 13;
    /// `MicroBlaze`.
    pub const MICROBLAZE: u8 = 14;
    /// Nios II.
    pub const NIOS2: u8 = 15;
    /// Blackfin.
    pub const BLACKFIN: u8 = 16;
    /// AVR32.
    pub const AVR32: u8 = 17;
    /// `ST200` VLIW core.
    pub const ST200: u8 = 18;
    /// U-Boot sandbox (host test build).
    pub const SANDBOX: u8 = 19;
    /// Andes NDS32.
    pub const NDS32: u8 = 20;
    /// `OpenRISC` 1000.
    pub const OPENRISC: u8 = 21;
    /// 64-bit Arm.
    pub const ARM64: u8 = 22;
    /// Synopsys ARC.
    pub const ARC: u8 = 23;
    /// x86-64.
    pub const X86_64: u8 = 24;
    /// Xtensa.
    pub const XTENSA: u8 = 25;
    /// RISC-V.
    pub const RISCV: u8 = 26;
}

/// uImage compression types.
pub mod uimage_comp {
    /// No compression.
    pub const NONE: u8 = 0;
    /// gzip.
    pub const GZIP: u8 = 1;
    /// bzip2.
    pub const BZIP2: u8 = 2;
    /// LZMA-alone.
    pub const LZMA: u8 = 3;
    /// lzop.
    pub const LZO: u8 = 4;
    /// LZ4.
    pub const LZ4: u8 = 5;
    /// Zstandard.
    pub const ZSTD: u8 = 6;
}

/// uImage image types (U-Boot `enum ih_type`).
pub mod uimage_type {
    /// Invalid image.
    pub const INVALID: u8 = 0;
    /// Standalone program.
    pub const STANDALONE: u8 = 1;
    /// OS kernel.
    pub const KERNEL: u8 = 2;
    /// RAM disk.
    pub const RAMDISK: u8 = 3;
    /// Multi-file image.
    pub const MULTI: u8 = 4;
    /// Firmware.
    pub const FIRMWARE: u8 = 5;
    /// Script.
    pub const SCRIPT: u8 = 6;
    /// Filesystem image.
    pub const FILESYSTEM: u8 = 7;
    /// Flattened device tree.
    pub const FLATDT: u8 = 8;
    /// Kirkwood boot image.
    pub const KWBIMAGE: u8 = 9;
    /// Freescale i.MX boot image.
    pub const IMXIMAGE: u8 = 10;
    /// OS kernel that runs from any load address.
    pub const KERNEL_NOLOAD: u8 = 14;
    /// TI Keystone GP header image.
    pub const GPIMAGE: u8 = 17;
    /// Atmel ROM bootable image.
    pub const ATMELIMAGE: u8 = 18;
    /// Typeless loadable image.
    pub const LOADABLE: u8 = 22;
    /// FPGA bitstream.
    pub const FPGA: u8 = 29;
    /// Trusted execution environment OS.
    pub const TEE: u8 = 31;
}

/// Detected kernel/boot format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFormat {
    /// Linux x86 `bzImage`/`zImage`
    LinuxX86 {
        /// Boot protocol version (`0x020F` is 2.15).
        protocol_version: u16,
    },
    /// Linux ARM64 Image
    LinuxArm64,
    /// Linux RISC-V Image
    LinuxRiscv,
    /// Linux EFI zboot image (`vmlinuz.efi`): a PE stub with a compressed
    /// kernel `Image`
    LinuxZboot,
    /// Linux 32-bit Arm `zImage`
    LinuxArm {
        /// Byte order, from the header's magic and endianness flag.
        byte_order: ArmByteOrder,
    },
    /// U-Boot `uImage`
    UImage {
        /// Architecture ID (`uimage_arch`).
        arch: u8,
        /// OS ID (`uimage_os`).
        os: u8,
        /// Image type ID (`uimage_type`).
        image_type: u8,
    },
    /// Flattened Image Tree: a device tree with an `/images` node
    Fit,
    /// Device Tree Blob
    Dtb,
}

/// Byte order of a 32-bit Arm kernel. BE8 kernels (`ARMv6` and later)
/// store data big-endian and instructions little-endian; BE32 kernels
/// store both big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmByteOrder {
    /// Little-endian kernel.
    Little,
    /// Big-endian data, little-endian instructions.
    Be8,
    /// Big-endian data and instructions.
    Be32,
}

/// One U-Boot architecture: uImage ID, FIT name, display name and the
/// architecture it names. The code byte order is left open where the CPU
/// runs either order and the ID does not say which; 64-bit Arm and RISC-V
/// instructions are little-endian in every data byte order.
struct Arch {
    id: u8,
    fit: &'static str,
    name: &'static str,
    target: Option<Target>,
}

const fn arch(id: u8, fit: &'static str, name: &'static str, target: Option<Target>) -> Arch {
    Arch {
        id,
        fit,
        name,
        target,
    }
}

const LITTLE: Option<Endianness> = Some(Endianness::Little);
const BIG: Option<Endianness> = Some(Endianness::Big);

const fn target(isa: Isa, bits: u8, endianness: Option<Endianness>) -> Target {
    Target {
        isa,
        bits,
        endianness,
    }
}

/// U-Boot `uimage_arch` table. `ppc` is an alternative FIT name for
/// `powerpc`. The sandbox architecture is U-Boot's host test build and
/// names no target ISA.
const ARCHES: &[Arch] = &[
    arch(
        uimage_arch::ALPHA,
        "alpha",
        "Alpha",
        Some(target(Isa::Alpha, 64, LITTLE)),
    ),
    arch(
        uimage_arch::ARM,
        "arm",
        "ARM",
        Some(target(Isa::Arm, 32, None)),
    ),
    arch(
        uimage_arch::X86,
        "x86",
        "x86",
        Some(target(Isa::X86, 32, LITTLE)),
    ),
    arch(
        uimage_arch::IA64,
        "ia64",
        "IA-64",
        Some(target(Isa::Ia64, 64, LITTLE)),
    ),
    arch(
        uimage_arch::MIPS,
        "mips",
        "MIPS",
        Some(target(Isa::Mips, 32, None)),
    ),
    arch(
        uimage_arch::MIPS64,
        "mips64",
        "MIPS64",
        Some(target(Isa::Mips64, 64, None)),
    ),
    arch(
        uimage_arch::PPC,
        "powerpc",
        "PowerPC",
        Some(target(Isa::Ppc, 32, None)),
    ),
    arch(
        uimage_arch::PPC,
        "ppc",
        "PowerPC",
        Some(target(Isa::Ppc, 32, None)),
    ),
    arch(
        uimage_arch::S390,
        "s390",
        "S390",
        Some(target(Isa::S390, 32, BIG)),
    ),
    arch(
        uimage_arch::SH,
        "sh",
        "SuperH",
        Some(target(Isa::Sh, 32, None)),
    ),
    arch(
        uimage_arch::SPARC,
        "sparc",
        "SPARC",
        Some(target(Isa::Sparc, 32, BIG)),
    ),
    arch(
        uimage_arch::SPARC64,
        "sparc64",
        "SPARC64",
        Some(target(Isa::Sparc64, 64, BIG)),
    ),
    arch(
        uimage_arch::M68K,
        "m68k",
        "M68K",
        Some(target(Isa::M68k, 32, BIG)),
    ),
    arch(uimage_arch::NIOS, "nios", "Nios", None),
    arch(
        uimage_arch::MICROBLAZE,
        "microblaze",
        "MicroBlaze",
        Some(target(Isa::MicroBlaze, 32, None)),
    ),
    arch(
        uimage_arch::NIOS2,
        "nios2",
        "Nios II",
        Some(target(Isa::Nios2, 32, LITTLE)),
    ),
    arch(
        uimage_arch::BLACKFIN,
        "blackfin",
        "Blackfin",
        Some(target(Isa::Blackfin, 32, LITTLE)),
    ),
    arch(
        uimage_arch::AVR32,
        "avr32",
        "AVR32",
        Some(target(Isa::Avr32, 32, BIG)),
    ),
    arch(uimage_arch::ST200, "st200", "ST200", None),
    arch(uimage_arch::SANDBOX, "sandbox", "Sandbox", None),
    arch(
        uimage_arch::NDS32,
        "nds32",
        "NDS32",
        Some(target(Isa::Nds32, 32, None)),
    ),
    arch(
        uimage_arch::OPENRISC,
        "or1k",
        "OpenRISC",
        Some(target(Isa::OpenRisc, 32, BIG)),
    ),
    arch(
        uimage_arch::ARM64,
        "arm64",
        "ARM64",
        Some(target(Isa::AArch64, 64, LITTLE)),
    ),
    arch(
        uimage_arch::ARC,
        "arc",
        "ARC",
        Some(target(Isa::Arc, 32, None)),
    ),
    arch(
        uimage_arch::X86_64,
        "x86_64",
        "x86-64",
        Some(target(Isa::X86_64, 64, LITTLE)),
    ),
    arch(
        uimage_arch::XTENSA,
        "xtensa",
        "Xtensa",
        Some(target(Isa::Xtensa, 32, None)),
    ),
    arch(
        uimage_arch::RISCV,
        "riscv",
        "RISC-V",
        Some(target(Isa::RiscV64, 64, LITTLE)),
    ),
];

fn arch_by_id(id: u8) -> Option<&'static Arch> {
    ARCHES.iter().find(|a| a.id == id)
}

fn arch_by_name(name: &str) -> Option<&'static Arch> {
    ARCHES.iter().find(|a| a.fit == name)
}

/// U-Boot compression IDs and FIT names, with the codec that decodes each.
/// U-Boot's LZ4 support reads the LZ4 frame format; Linux kernels built
/// with `lz4 -l` use the legacy frame, so [`kernel_codec`] confirms it.
const COMPRESSIONS: &[(u8, &str, Option<Codec>)] = &[
    (uimage_comp::NONE, "none", None),
    (uimage_comp::GZIP, "gzip", Some(Codec::Gzip)),
    (uimage_comp::BZIP2, "bzip2", Some(Codec::Bzip2)),
    (uimage_comp::LZMA, "lzma", Some(Codec::Lzma)),
    (uimage_comp::LZO, "lzo", Some(Codec::Lzop)),
    (uimage_comp::LZ4, "lz4", Some(Codec::Lz4)),
    (uimage_comp::ZSTD, "zstd", Some(Codec::Zstd)),
];

/// U-Boot image type IDs and FIT names (`uimage_type` in `boot/image.c`).
const IMAGE_TYPES: &[(u8, &str, &str)] = &[
    (uimage_type::INVALID, "invalid", "Invalid"),
    (uimage_type::STANDALONE, "standalone", "Standalone program"),
    (uimage_type::KERNEL, "kernel", "Kernel"),
    (uimage_type::RAMDISK, "ramdisk", "RAM disk"),
    (uimage_type::MULTI, "multi", "Multi-file image"),
    (uimage_type::FIRMWARE, "firmware", "Firmware"),
    (uimage_type::SCRIPT, "script", "Script"),
    (uimage_type::FILESYSTEM, "filesystem", "Filesystem"),
    (uimage_type::FLATDT, "flat_dt", "Device tree"),
    (uimage_type::KWBIMAGE, "kwbimage", "Kirkwood boot image"),
    (uimage_type::IMXIMAGE, "imximage", "i.MX boot image"),
    (
        uimage_type::KERNEL_NOLOAD,
        "kernel_noload",
        "Kernel (no load address)",
    ),
    (uimage_type::GPIMAGE, "gpimage", "TI Keystone GP image"),
    (uimage_type::ATMELIMAGE, "atmelimage", "Atmel ROM image"),
    (uimage_type::LOADABLE, "loadable", "Loadable"),
    (uimage_type::FPGA, "fpga", "FPGA bitstream"),
    (uimage_type::TEE, "tee", "Trusted execution environment"),
];

/// Image types whose bytes run on the CPU the architecture field names.
const EXECUTABLE_TYPES: &[&str] = &[
    "standalone",
    "kernel",
    "kernel_noload",
    "firmware",
    "loadable",
    "tee",
];

/// Image types that are never code: FPGA bitstreams and U-Boot scripts.
const OPAQUE_TYPES: &[&str] = &["fpga", "script"];

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::KernelParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated file range 0x{start:X} + {len} B")))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, at, 8)?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(u64::from_le_bytes(bytes))
}

/// Round up to a multiple of four bytes.
fn align4(n: usize) -> Result<usize> {
    Ok(n.checked_add(3)
        .ok_or_else(|| error("Alignment overflow"))?
        & !3)
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Codec of a compressed Linux kernel payload, identified the way
/// `lib/decompress.c` does it (by its leading magic), with the header
/// checks of [`compressed::sniff`] so a two-byte match is not enough.
/// LZMA-alone has only a properties byte; the kernel's `5D 00` prefix is
/// accepted with a plausible dictionary size.
fn kernel_codec(payload: &[u8]) -> Option<Codec> {
    compressed::sniff(payload)
        .or_else(|| compressed::is_plausible_lzma(payload).then_some(Codec::Lzma))
}

/// A component's stored bytes, decoded when the header names a codec. A
/// payload that does not decode is kept as an opaque component and the
/// failure is noted, so the header's own evidence still reports.
fn component<'a>(
    label: String,
    offset: usize,
    stored: &'a [u8],
    codec: Option<Codec>,
    notes: &mut Vec<String>,
) -> Child<'a> {
    let Some(codec) = codec else {
        return Child::stored(label, offset, stored);
    };
    // Linux LZ4 kernels use the legacy frame even where the header says lz4.
    let codec = match (codec, compressed::sniff(stored)) {
        (Codec::Lz4, Some(Codec::Lz4Legacy)) => Codec::Lz4Legacy,
        (codec, _) => codec,
    };
    match compressed::decode(codec, stored) {
        Ok(decoded) => Child::decoded(
            label,
            offset,
            stored.len(),
            Cow::Owned(decoded.data),
            codec.name(),
        ),
        Err(e) => {
            notes.push(format!(
                "{label}: payload does not decode as {} ({e})",
                codec.name()
            ));
            Child::opaque(label, offset, stored)
        }
    }
}

/// Kernel images that must be recognized before the generic PE check:
/// an EFI zboot image is a valid PE file whose DOS header carries `zimg`.
pub fn detect_pe_wrapped(data: &[u8]) -> Option<KernelFormat> {
    linux::is_zboot(data).then_some(KernelFormat::LinuxZboot)
}

/// Detect kernel/boot format.
pub fn detect(data: &[u8]) -> Option<KernelFormat> {
    if data.len() < 4 {
        return None;
    }
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic_be == UIMAGE_MAGIC && data.len() >= UIMAGE_HEADER_SIZE {
        return Some(KernelFormat::UImage {
            arch: data[0x1D],
            os: data[0x1C],
            image_type: data[0x1E],
        });
    }
    if magic_be == FDT_MAGIC {
        // A FIT is a device tree with an /images node.
        let is_fit = fdt::Fdt::parse(data).is_ok_and(|tree| tree.child(0, "images").is_some());
        return Some(if is_fit {
            KernelFormat::Fit
        } else {
            KernelFormat::Dtb
        });
    }
    linux::detect(data)
}

/// Parse a kernel or boot image into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::KernelParseError`] for a truncated or inconsistent
/// header, structure block or payload range.
pub fn parse_container(data: &[u8], format: KernelFormat) -> Result<Container<'_>> {
    match format {
        KernelFormat::LinuxX86 { protocol_version } => linux::x86(data, protocol_version),
        KernelFormat::LinuxArm64 => linux::arm64(data),
        KernelFormat::LinuxRiscv => linux::riscv(data),
        KernelFormat::LinuxArm { byte_order } => linux::arm(data, byte_order),
        KernelFormat::LinuxZboot => linux::zboot(data),
        KernelFormat::UImage { .. } => uimage::parse(data),
        KernelFormat::Fit => fit::parse(data),
        KernelFormat::Dtb => fit::parse_dtb(data),
    }
}

/// Parse kernel/boot format.
///
/// # Errors
///
/// As [`parse_container`].
pub fn parse(data: &[u8], format: KernelFormat) -> Result<ClassificationResult> {
    Ok(parse_container(data, format)?.classification())
}

/// The file format each kernel layout reports.
pub fn file_format(format: KernelFormat) -> FileFormat {
    match format {
        KernelFormat::LinuxX86 { .. }
        | KernelFormat::LinuxArm64
        | KernelFormat::LinuxRiscv
        | KernelFormat::LinuxZboot
        | KernelFormat::LinuxArm { .. } => FileFormat::ZImage,
        KernelFormat::UImage { .. } => FileFormat::UImage,
        KernelFormat::Fit => FileFormat::Fit,
        KernelFormat::Dtb => FileFormat::Dtb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::checksum::crc32;

    /// uImage header for `payload`: magic, header CRC, timestamp 0, size,
    /// load and entry 0x80008000, data CRC, OS, architecture, type, no
    /// compression, name "Test Image".
    fn make_uimage(arch: u8, os: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; UIMAGE_HEADER_SIZE];
        data[0..4].copy_from_slice(&UIMAGE_MAGIC.to_be_bytes());
        let size = u32::try_from(payload.len()).expect("test payload fits in u32");
        data[12..16].copy_from_slice(&size.to_be_bytes());
        data[16..20].copy_from_slice(&0x8000_8000u32.to_be_bytes());
        data[20..24].copy_from_slice(&0x8000_8000u32.to_be_bytes());
        data[24..28].copy_from_slice(&crc32(payload).to_be_bytes());
        data[0x1C] = os;
        data[0x1D] = arch;
        data[0x1E] = uimage_type::KERNEL;
        data[0x1F] = uimage_comp::NONE;
        data[0x20..0x2A].copy_from_slice(b"Test Image");
        let header_crc = crc32(&data);
        data[4..8].copy_from_slice(&header_crc.to_be_bytes());
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn test_detect_uimage() {
        let data = make_uimage(uimage_arch::ARM, uimage_os::LINUX, &[0; 64]);
        let format = detect(&data);
        assert!(matches!(format, Some(KernelFormat::UImage { .. })));
    }

    #[test]
    fn test_parse_uimage_arm() {
        let data = make_uimage(uimage_arch::ARM, uimage_os::LINUX, &[0; 64]);
        let format = detect(&data).unwrap();
        let result = parse(&data, format).unwrap();
        assert_eq!(result.isa, Isa::Arm);
        assert_eq!(result.format, FileFormat::UImage);
        // The header does not say which byte order an Arm kernel uses.
        assert_eq!(result.endianness, Endianness::BiEndian);
    }

    #[test]
    fn test_parse_uimage_riscv() {
        let data = make_uimage(uimage_arch::RISCV, uimage_os::LINUX, &[0; 64]);
        let format = detect(&data).unwrap();
        let result = parse(&data, format).unwrap();
        assert_eq!(result.isa, Isa::RiscV64);
        assert_eq!(result.format, FileFormat::UImage);
    }

    #[test]
    fn uimage_sandbox_architecture_names_no_isa() {
        let data = make_uimage(uimage_arch::SANDBOX, uimage_os::LINUX, &[0; 64]);
        let result = parse(&data, detect(&data).unwrap()).unwrap();
        assert!(matches!(result.isa, Isa::Unknown(_)));
        assert_eq!(result.format, FileFormat::UImage);
    }

    #[test]
    fn uimage_header_and_data_crcs_are_checked() {
        let data = make_uimage(uimage_arch::ARM, uimage_os::LINUX, &[1, 2, 3, 4]);
        let format = detect(&data).unwrap();
        let mut header = data.clone();
        header[0x20] ^= 1;
        assert!(parse(&header, format).is_err());
        let mut payload = data.clone();
        payload[UIMAGE_HEADER_SIZE] ^= 1;
        assert!(parse(&payload, format).is_err());
        for end in 0..data.len() {
            assert!(parse(&data[..end], format).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn arch_table_ids_are_unique_per_name() {
        for a in ARCHES {
            assert_eq!(arch_by_name(a.fit).map(|b| b.id), Some(a.id), "{}", a.fit);
        }
        assert!(arch_by_id(uimage_arch::PPC).is_some());
    }
}
