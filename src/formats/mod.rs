//! Binary file format parsers.
//!
//! This module provides parsers for various executable file formats:
//! - ELF (Executable and Linkable Format)
//! - PE/COFF (Portable Executable)
//! - Mach-O (Mach Object)
//! - COFF (Standalone Common Object File Format)
//! - XCOFF (AIX Extended COFF)
//! - ECOFF (Extended COFF for MIPS/Alpha)
//! - a.out (BSD, Plan 9, Minix)
//! - MZ/NE/LE/LX (DOS and OS/2)
//! - PEF (Classic Mac OS)
//! - WebAssembly
//! - Java class files
//! - DEX/ODEX/VDEX/ART (Android)
//! - Game console formats (XBE, XEX, SELF, NSO, DOL)
//! - Boot/kernel images (zImage, uImage, FIT)
//! - Hex formats (Intel HEX, S-record, TI-TXT)
//! - Archive formats (ar)
//! - Raw binary analysis

pub mod amiga_hunk;
pub mod android;
pub mod aof;
pub mod aout;
pub mod apple;
pub mod ar;
pub mod archives;
pub mod automotive;
pub mod bcf;
pub mod bflt;
pub mod blackfin_ldr;
pub mod bitstream;
pub mod bootmisc;
pub mod checksum;
pub mod chiptune;
pub mod coff;
pub mod compressed;
pub mod console;
pub mod container;
pub mod coreboot;
pub mod d10;
pub mod dex;
pub mod ecoff;
pub mod elf;
pub mod epoc;
pub mod epr;
pub mod erofs;
pub mod esp;
pub mod ext;
pub mod fat;
pub mod fatelf;
pub mod frf;
pub mod goff;
pub mod hex;
pub mod huawei;
pub mod java;
pub mod kernel;
pub mod llvm_bc;
pub mod lod;
pub mod macho;
pub mod mcu;
pub mod mtd;
pub mod mz;
pub mod nintendo;
pub mod ols;
pub mod omf;
pub mod optionrom;
pub mod os9;
pub mod palm;
pub mod partitions;
pub mod pcfw;
pub mod pe;
pub mod pef;
pub mod qnx;
pub mod retro;
pub mod retro2;
pub mod rofs;
pub mod router;
pub mod sgo;
pub mod socboot2;
pub mod socboot;
pub mod som;
pub mod sox;
pub mod spc;
pub mod tds;
pub mod ti_c55x;
pub mod ti;
pub mod tmobj;
pub mod uefi;
pub mod vbf;
pub mod wasm;
pub mod wince;
pub mod xcoff;
pub mod zxtape;

use crate::error::{ClassifierError, Result};
use crate::types::ClassificationResult;

/// Maximum bytes one extraction may produce (decoded payload, expanded
/// image or concatenated load sections), independent of destination
/// address gaps and of declared sizes.
pub const MAX_PAYLOAD: usize = 64 << 20;

/// Magic byte signatures for format detection.
pub mod magic {
    /// ELF magic bytes: 0x7F 'E' 'L' 'F'
    pub const ELF: [u8; 4] = [0x7F, b'E', b'L', b'F'];

    /// PE/COFF DOS stub magic: 'M' 'Z'
    pub const MZ: [u8; 2] = [b'M', b'Z'];

    /// PE signature: 'P' 'E' '\0' '\0'
    pub const PE: [u8; 4] = [b'P', b'E', 0, 0];

    /// Mach-O 32-bit big-endian
    pub const MACHO_32_BE: [u8; 4] = [0xFE, 0xED, 0xFA, 0xCE];

    /// Mach-O 32-bit little-endian
    pub const MACHO_32_LE: [u8; 4] = [0xCE, 0xFA, 0xED, 0xFE];

    /// Mach-O 64-bit big-endian
    pub const MACHO_64_BE: [u8; 4] = [0xFE, 0xED, 0xFA, 0xCF];

    /// Mach-O 64-bit little-endian
    pub const MACHO_64_LE: [u8; 4] = [0xCF, 0xFA, 0xED, 0xFE];

    /// Mach-O fat/universal big-endian
    pub const MACHO_FAT_BE: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

    /// Mach-O fat/universal little-endian
    pub const MACHO_FAT_LE: [u8; 4] = [0xBE, 0xBA, 0xFE, 0xCA];

    /// Mach-O fat/universal 64-bit big-endian (FAT_MAGIC_64)
    pub const MACHO_FAT64_BE: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBF];

    /// Mach-O fat/universal 64-bit little-endian
    pub const MACHO_FAT64_LE: [u8; 4] = [0xBF, 0xBA, 0xFE, 0xCA];

    /// XCOFF 32-bit (AIX)
    pub const XCOFF_32: [u8; 2] = [0x01, 0xDF];

    /// XCOFF 64-bit (AIX)
    pub const XCOFF_64: [u8; 2] = [0x01, 0xF7];

    /// ECOFF MIPS little-endian (MIPSELMAGIC 0x0162 stored as LE)
    pub const ECOFF_MIPS_LE: [u8; 2] = [0x62, 0x01];

    /// ECOFF MIPS big-endian (magic 0x0160 stored as BE)
    pub const ECOFF_MIPS_BE: [u8; 2] = [0x01, 0x60];

    /// ECOFF Alpha (magic 0x0183 stored as LE)
    pub const ECOFF_ALPHA: [u8; 2] = [0x83, 0x01];

    /// WebAssembly magic: "\0asm"
    pub const WASM: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

    /// Java class file magic: 0xCAFEBABE
    pub const JAVA_CLASS: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

    /// DEX magic: "dex\n"
    pub const DEX: [u8; 4] = [b'd', b'e', b'x', b'\n'];

    /// bFLT magic: "bFLT"
    pub const BFLT: [u8; 4] = [b'b', b'F', b'L', b'T'];

    /// PEF magic: "Joy!" + "peff"
    pub const PEF_TAG1: [u8; 4] = [b'J', b'o', b'y', b'!'];

    /// ar archive magic: "!<arch>\n"
    pub const AR: [u8; 8] = [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n'];

    /// U-Boot uImage magic
    pub const UIMAGE: u32 = 0x27051956;

    /// FDT/DTB magic
    pub const FDT: u32 = 0xD00DFEED;

    /// XBE (Xbox) magic: "XBEH"
    pub const XBE: [u8; 4] = [b'X', b'B', b'E', b'H'];

    /// XEX (Xbox 360) magic: "XEX2"
    pub const XEX: [u8; 4] = [b'X', b'E', b'X', b'2'];

    /// NSO (Switch) magic: "NSO0"
    pub const NSO: [u8; 4] = [b'N', b'S', b'O', b'0'];

    /// PS3 SELF magic: "SCE\0"
    pub const PS3_SELF: [u8; 4] = [b'S', b'C', b'E', 0];

    /// FatELF magic
    pub const FATELF: u32 = 0x1F0E70FA;

    /// GOFF record marker
    pub const GOFF: u8 = 0x03;

    /// LLVM bitcode magic: "BC" + 0xC0DE
    pub const LLVM_BC: [u8; 4] = [b'B', b'C', 0xC0, 0xDE];
}

/// Detected file format with parsing context.
#[derive(Debug, Clone)]
pub enum DetectedFormat {
    /// ELF format with class (32/64) and endianness
    Elf { class: u8, endian: u8 },
    /// PE/COFF with PE header offset
    Pe { pe_offset: u32 },
    /// Mach-O with bitwidth and endianness
    MachO { bits: u8, big_endian: bool },
    /// Mach-O fat/universal binary
    MachOFat { big_endian: bool, fat64: bool },
    /// Standalone COFF (Windows object files)
    Coff { machine: u16 },
    /// XCOFF (AIX)
    Xcoff { bits: u8 },
    /// ECOFF
    Ecoff { variant: ecoff::EcoffVariant },
    /// a.out (BSD, Plan 9, Minix)
    Aout { variant: aout::AoutVariant },
    /// DOS MZ / NE / LE / LX
    Mz { variant: mz::ExtendedType },
    /// PEF (Classic Mac OS)
    Pef,
    /// WebAssembly
    Wasm,
    /// Java class file
    JavaClass,
    /// DEX/ODEX/VDEX/ART (Android)
    Dex { variant: dex::DexVariant },
    /// bFLT (uClinux)
    Bflt,
    /// Game console formats
    Console { variant: console::ConsoleFormat },
    /// Kernel/boot images
    Kernel { variant: kernel::KernelFormat },
    /// ar archive
    Ar { variant: ar::ArVariant },
    /// Intel HEX / S-record / TI-TXT
    Hex { variant: hex::HexVariant },
    /// OMF object module
    Omf,
    /// HP-UX SOM
    Som,
    /// ARM AOF/AXF container
    Aof,
    /// Symbian EPOC/E32 image
    Epoc,
    /// Palm PDB/PRC container
    Palm,
    /// Amiga Hunk format
    AmigaHunk,
    /// Turbo Debugger Symbols
    Tds,
    /// OS-9 module
    Os9,
    /// GOFF (IBM z/Architecture)
    Goff,
    /// LLVM bitcode
    LlvmBc { variant: llvm_bc::LlvmVariant },
    /// FatELF multi-architecture
    FatElf,
    /// WinOLS Project File container
    Ols,
    /// ECU EEPROM/Flash dump container (EPR)
    Epr,
    /// VW ODIS SGO firmware container
    Sgo,
    /// Volvo/Ford VBF firmware container
    Vbf,
    /// VW/Audi FRF encrypted flash container
    Frf,
    /// SMS-Soft CombiLoader BCF container
    Bcf,
    /// VAG/Simos SOX encrypted container
    Sox,
    /// AOR AR-DV10 firmware container
    D10,
    /// TI C55x serial boot table with validated load records.
    TiC55xBoot,
    /// TI firmware, boot, and hex utility containers.
    Ti { variant: ti::Variant },
    /// SNES SPC700 sound file
    Spc,
    /// TriMedia object module
    TmObj,
    /// Motorola DSP LOD load file
    Lod,
    /// A layout built on the shared container model ([`container`]).
    Container {
        /// The recognized layout.
        kind: container::Kind,
    },
    /// Unknown/raw format
    Raw,
}

/// Detect the file format from magic bytes.
pub fn detect_format(data: &[u8]) -> DetectedFormat {
    if data.len() < 4 {
        // Check for text-based hex formats (can work with minimal data)
        if let Some(variant) = hex::detect(data) {
            return DetectedFormat::Hex { variant };
        }
        return DetectedFormat::Raw;
    }

    // TI MCELF has ordinary ELF magic but carries core-mapping notes.
    if let Some(variant) = ti::detect_strong(data) {
        return DetectedFormat::Ti { variant };
    }

    // Linux EFI zboot images are valid PE files; their DOS header names
    // the compressed kernel, so they are checked before PE.
    if let Some(variant) = kernel::detect_pe_wrapped(data) {
        return DetectedFormat::Kernel { variant };
    }

    // Wii U RPX/RPL files have ordinary ELF magic but Cafe OS `e_ident`
    // bytes and zlib-compressed sections that the ELF parser cannot read.
    if let Some(layout) = retro::detect_rpx(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Retro(layout),
        };
    }

    // ELF
    if data[..4] == magic::ELF {
        if data.len() >= 6 {
            return DetectedFormat::Elf {
                class: data[4],
                endian: data[5],
            };
        }
        return DetectedFormat::Raw;
    }

    // FatELF (check before Mach-O since magic could conflict)
    if fatelf::detect(data) {
        return DetectedFormat::FatElf;
    }

    // PE/COFF - check for PE first, then fall through to MZ/NE/LE/LX
    if data.len() >= 2 && data[..2] == magic::MZ {
        if data.len() >= 0x40 {
            let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
            let pe_off = pe_offset as usize;
            if pe_off + 4 <= data.len() && data[pe_off..pe_off + 4] == magic::PE {
                return DetectedFormat::Pe { pe_offset };
            }
        }
        // Not PE, try MZ/NE/LE/LX
        if let Some(variant) = mz::detect(data) {
            return DetectedFormat::Mz { variant };
        }
    }

    // Mach-O (check before Java class since 0xCAFEBABE conflicts with fat binary)
    let magic4 = &data[..4];
    if magic4 == magic::MACHO_32_BE {
        return DetectedFormat::MachO {
            bits: 32,
            big_endian: true,
        };
    }
    if magic4 == magic::MACHO_32_LE {
        return DetectedFormat::MachO {
            bits: 32,
            big_endian: false,
        };
    }
    if magic4 == magic::MACHO_64_BE {
        return DetectedFormat::MachO {
            bits: 64,
            big_endian: true,
        };
    }
    if magic4 == magic::MACHO_64_LE {
        return DetectedFormat::MachO {
            bits: 64,
            big_endian: false,
        };
    }
    // Mach-O fat 64-bit (0xCAFEBABF / 0xBFBAFECA) — check before 32-bit since no Java conflict
    if magic4 == magic::MACHO_FAT64_BE {
        return DetectedFormat::MachOFat {
            big_endian: true,
            fat64: true,
        };
    }
    if magic4 == magic::MACHO_FAT64_LE {
        return DetectedFormat::MachOFat {
            big_endian: false,
            fat64: true,
        };
    }
    // Mach-O fat 32-bit uses 0xCAFEBABE which conflicts with Java class files
    // Differentiate by checking if it looks like valid fat header
    if magic4 == magic::MACHO_FAT_BE {
        // Check if it's a valid Mach-O fat binary vs Java class
        if data.len() >= 8 {
            let nfat_arch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            // Java class files have minor/major version here (usually small numbers like 0, 52-65)
            // Mach-O fat binaries have nfat_arch (usually 1-4)
            // If nfat_arch is reasonable and followed by valid fat arch entries, it's Mach-O
            if nfat_arch > 0 && nfat_arch <= 20 {
                // Further check: see if we have enough data for fat_arch entries
                let fat_arch_size = 20; // Each fat_arch is 20 bytes
                if data.len() >= 8 + (nfat_arch as usize * fat_arch_size) {
                    // Check if first fat_arch looks valid (cputype should be reasonable)
                    let cputype = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                    // Valid cputypes are typically 7, 12, 18, 0x01000007, 0x0100000c, etc.
                    if cputype > 0 && (cputype < 100 || cputype > 0x01000000) {
                        return DetectedFormat::MachOFat {
                            big_endian: true,
                            fat64: false,
                        };
                    }
                }
            }
        }
        // Fall through to check for Java class
    }
    if magic4 == magic::MACHO_FAT_LE {
        return DetectedFormat::MachOFat {
            big_endian: false,
            fat64: false,
        };
    }

    // Java class (after Mach-O fat check since 0xCAFEBABE conflicts)
    if java::detect(data) {
        return DetectedFormat::JavaClass;
    }

    // WebAssembly
    if wasm::detect(data) {
        return DetectedFormat::Wasm;
    }

    // DEX/ODEX/VDEX/ART (Android)
    if let Some(variant) = dex::detect(data) {
        return DetectedFormat::Dex { variant };
    }

    // PEF (Classic Mac OS)
    if pef::detect(data) {
        return DetectedFormat::Pef;
    }

    // bFLT (uClinux)
    if bflt::detect(data) {
        return DetectedFormat::Bflt;
    }

    // LLVM bitcode
    if let Some(variant) = llvm_bc::detect(data) {
        return DetectedFormat::LlvmBc { variant };
    }

    // VW ODIS SGO firmware container (strong 16-byte magic)
    if sgo::detect(data) {
        return DetectedFormat::Sgo;
    }

    // Volvo/Ford VBF firmware container (ASCII magic "vbf_version")
    if vbf::detect(data) {
        return DetectedFormat::Vbf;
    }

    // VW/Audi FRF encrypted flash container (8-byte magic)
    if frf::detect(data) {
        return DetectedFormat::Frf;
    }

    // SMS-Soft CombiLoader BCF container (16-byte ASCII magic)
    if bcf::detect(data) {
        return DetectedFormat::Bcf;
    }

    // VAG/Simos SOX encrypted container (structural header check)
    if sox::detect(data) {
        return DetectedFormat::Sox;
    }

    // AOR AR-DV10 firmware revision/build header and record ID.
    if d10::detect(data) {
        return DetectedFormat::D10;
    }

    // TI C55x serial boot table: validate structure because the magic is only 16 bits.
    if ti_c55x::detect(data) {
        return DetectedFormat::TiC55xBoot;
    }

    // Automotive flash containers: ODX root element, CUW magic, or an RWD
    // signature whose trailing checksum matches.
    if let Some(layout) = automotive::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Automotive(layout),
        };
    }

    // Chiptune programs: NSF, NSFe, PSID/RSID and GBS headers; the PSF
    // signature and version byte, HESM, KSCC/KSSX, SAP, ZXAYEMUL, SNDH at
    // offset 12 and the Pack-Ice magic.
    if let Some(layout) = chiptune::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Chiptune(layout),
        };
    }

    // Blackfin LDR streams with signed, checksummed BF54x block headers.
    if let Some(layout) = blackfin_ldr::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::BlackfinLdr(layout),
        };
    }

    // Huawei UPDATE.APP: entry magic `55 AA 5A A5` after a zero prefix.
    // Checked before option ROMs, which share the `55 AA` prefix.
    if let Some(layout) = huawei::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Huawei(layout),
        };
    }

    // PCI expansion ROMs: `55 AA` and a PCIR data structure.
    if let Some(layout) = optionrom::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::OptionRom(layout),
        };
    }

    // ZX Spectrum TZX tapes (`ZXTape!` signature).
    if let Some(layout) = zxtape::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::ZxTape(layout),
        };
    }

    // FPGA bitstreams: a Xilinx `.bit` header, the POF magic, or a Lattice
    // comment block immediately followed by its preamble.
    if let Some(layout) = bitstream::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Bitstream(layout),
        };
    }

    // MCU update images: UF2 block magics, the DfuSe signature or the GBL
    // header tag at offset 0.
    if let Some(layout) = mcu::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Mcu(layout),
        };
    }

    // SoC boot ROM images: eGON.BT0 and TOC0 names, Rockchip tags (one
    // RC4-scrambled), MediaTek device and GFH names, the Qualcomm SBL
    // codeword and magic.
    if let Some(layout) = socboot2::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::SocBoot2(layout),
        };
    }

    // Sega 32X ROMs are Mega Drive ROMs with the 32X security program, so
    // they are checked before the Mega Drive check in `retro::detect`.
    if let Some(layout) = retro2::detect_32x(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Retro2(layout),
        };
    }

    // Console executables and ROM images: identification strings at fixed
    // offsets (`SEGA` at 0x100, `PS-X EXE`, `SEGA SEGAKATANA`, `NCCH` at
    // 0x100, `3DSX`, `\0PBP`).
    if let Some(layout) = retro::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Retro(layout),
        };
    }

    // Apple Image4 (a DER SEQUENCE whose first element is the IA5String
    // "IMG4", "IM4P", "IM4M" or "IM4R") and dyld shared caches ("dyld_v1").
    // Before the compressed streams: an IM4P payload is often LZFSE or LZSS,
    // and the container must report itself.
    if let Some(layout) = apple::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Apple(layout),
        };
    }

    // Android boot, vendor_boot, sparse, OTA, bootloader-pack, DTBO and
    // vbmeta images, and super images (geometry magic at 0 or 4096).
    // Their magics are distinct from every format above.
    if let Some(layout) = android::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Android(layout),
        };
    }

    // SoC boot images: the BOOT.BIN and Secure Binary magics, and an i.MX
    // IVT at a documented offset whose pointers and boot data are
    // consistent.
    if let Some(layout) = socboot::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::SocBoot(layout),
        };
    }

    // Nintendo console ROMs: the iNES and N64 first words, or the DS, GBA
    // and Game Boy logos with their header checksums.
    if let Some(layout) = nintendo::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Nintendo(layout),
        };
    }

    // Archives: a ZIP local header (or the end record of an empty ZIP), the
    // tar magic at 257 with a valid header checksum, or an ASCII CPIO magic
    // with a valid first header.
    if let Some(layout) = archives::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Archive(layout),
        };
    }

    // Read-only filesystem images: the SquashFS, CramFS or romfs magic.
    // A CramFS superblock may also follow a 512-byte boot-code pad.
    if let Some(layout) = rofs::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Rofs(layout),
        };
    }

    // UBI erase-counter header (`UBI#`) and UBIFS superblock node.
    if let Some(layout) = mtd::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Mtd(layout),
        };
    }

    // ext2/3/4: magic 0xEF53 at 0x438 and a consistent superblock geometry.
    // Checked after the executable and firmware formats, whose headers lie
    // in the first kilobyte that an ext image leaves to the boot loader.
    if let Some(layout) = ext::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Ext(layout),
        };
    }

    // UEFI and PC flash images: the flash descriptor signature at 0x10 (or
    // 0x0), `_FVH` at 0x28, or a TE header whose machine is known.
    if let Some(layout) = uefi::detect(data) {
        // coreboot images for Intel platforms begin with a flash descriptor,
        // but their BIOS region holds CBFS, not firmware volumes. A complete
        // FMAP maps every area, the descriptor and ME region included, so
        // it describes the image better than the descriptor does.
        if layout == uefi::Layout::FlashDescriptor {
            if let Some(layout) = coreboot::detect_weak(data) {
                return DetectedFormat::Container {
                    kind: container::Kind::Coreboot(layout),
                };
            }
        }
        return DetectedFormat::Container {
            kind: container::Kind::Uefi(layout),
        };
    }

    // Chromium FMAP (`__FMAP__`) or coreboot CBFS (`LARCHIVE`) at offset 0.
    if let Some(layout) = coreboot::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Coreboot(layout),
        };
    }

    // Router firmware wrappers with a magic at offset 0: Broadcom TRX,
    // Netgear CHK and D-Link SEAMA.
    if let Some(layout) = router::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Router(layout),
        };
    }

    // Espressif flash dumps: the partition table at 0x8000 has a magic on
    // every record up to its terminator.
    if let Some(layout) = esp::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Esp(layout),
        };
    }

    // QNX images: `imagefs` at offset 0, or the startup header signature at
    // offset 0 or after a boot prefix that its `preboot_size` names.
    if let Some(layout) = qnx::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Qnx(layout),
        };
    }

    // Windows CE BIN files: the seven sync bytes `B000FF\n` at offset 0.
    if let Some(layout) = wince::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::WinCe(layout),
        };
    }

    // PC firmware blobs with a magic: the AMD microcode container magic,
    // `$FPT` at 0x10 or 0, `$CPD` at 0, or a PSP or BIOS directory cookie at
    // 0. Intel flash descriptors are claimed above, so an ME region inside
    // one is reached only as a descriptor child.
    if let Some(layout) = pcfw::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::PcFw(layout),
        };
    }

    // Miscellaneous boot images: the OP-TEE `OPTE` magic with header
    // version 1 or 2, the Amlogic magic at offset 8, `IMAGEWTY` (also after
    // RC6-decrypting the first block with the published header key) and the
    // barebox magic after the exception-vector words.
    if let Some(layout) = bootmisc::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::BootMisc(layout),
        };
    }

    // Console and home-computer images: identification strings at fixed
    // offsets (`SEGA SEGASATURN `, `SEGADISCSYSTEM`, `LYNX`, `ATARI7800`,
    // `C64 CARTRIDGE`, the SNK code, `TMR SEGA`), and GEMDOS programs whose
    // sizes and relocation table are consistent. After the Mega Drive
    // check, as PicoDrive tests the Mega Drive header before `TMR SEGA`.
    if let Some(layout) = retro2::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Retro2(layout),
        };
    }

    // EROFS: magic 0xE0F5E1E2 at 1024. Checked after the executable and
    // firmware formats, whose headers lie in the first kilobyte that EROFS
    // leaves unused.
    if let Some(layout) = erofs::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Erofs(layout),
        };
    }

    // Partition tables with a magic: the GPT header `EFI PART` at LBA 1 (512-
    // or 4096-byte blocks) and the Apple driver descriptor `ER` with a `PM`
    // map entry at block 1. After the filesystem and firmware formats, which
    // describe their own first sectors.
    if let Some(layout) = partitions::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Partitions(layout),
        };
    }

    // exFAT: the file system name `EXFAT   ` at offset 3.
    if let Some(layout) = fat::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Fat(layout),
        };
    }

    // Magic-bearing compressed streams. Checked after the executable and
    // firmware formats, none of which start with a codec magic.
    if let Some(codec) = compressed::detect(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Compressed(codec),
        };
    }

    // ar archive
    if let Some(variant) = ar::detect(data) {
        return DetectedFormat::Ar { variant };
    }

    // Game console formats
    if let Some(variant) = console::detect(data) {
        return DetectedFormat::Console { variant };
    }

    // Kernel/boot images
    if let Some(variant) = kernel::detect(data) {
        return DetectedFormat::Kernel { variant };
    }

    // GOFF (IBM z/Architecture) - check before generic COFF
    if goff::detect(data) {
        return DetectedFormat::Goff;
    }

    // a.out (BSD, Plan 9, Minix)
    if let Some(variant) = aout::detect(data) {
        return DetectedFormat::Aout { variant };
    }

    // XCOFF: a two-byte magic, so the header and section table must agree.
    if let Some(bits) = xcoff::detect(data) {
        return DetectedFormat::Xcoff { bits };
    }

    // ECOFF (check before standalone COFF since ECOFF has specific magic)
    if let Some(variant) = ecoff::detect(data) {
        return DetectedFormat::Ecoff { variant };
    }

    // Text-based hex formats (Intel HEX, S-record, TI-TXT)
    if let Some(variant) = hex::detect(data) {
        return DetectedFormat::Hex { variant };
    }

    // Standalone COFF (Windows object files)
    // Must be checked after other formats since COFF detection is heuristic-based
    if let Some(machine) = coff::detect(data) {
        return DetectedFormat::Coff { machine };
    }

    // OMF object modules
    if omf::detect(data) {
        return DetectedFormat::Omf;
    }

    // Turbo Debugger symbols
    if tds::detect(data) {
        return DetectedFormat::Tds;
    }

    // HP-UX SOM
    if som::detect(data) {
        return DetectedFormat::Som;
    }

    // ARM AOF/AXF
    if aof::detect(data) {
        return DetectedFormat::Aof;
    }

    // Amiga Hunk
    if amiga_hunk::detect(data) {
        return DetectedFormat::AmigaHunk;
    }

    // SNES SPC700 sound files (27-byte ASCII signature)
    if spc::detect(data) {
        return DetectedFormat::Spc;
    }

    // TriMedia object modules (magic and version in the header)
    if tmobj::detect(data) {
        return DetectedFormat::TmObj;
    }

    // Motorola DSP LOD load files (text records)
    if lod::detect(data) {
        return DetectedFormat::Lod;
    }

    // OS-9 modules
    if os9::detect(data) {
        return DetectedFormat::Os9;
    }

    // Palm containers
    if palm::detect(data) {
        return DetectedFormat::Palm;
    }

    // Symbian EPOC/E32 images
    if epoc::detect(data) {
        return DetectedFormat::Epoc;
    }

    // WinOLS Project File
    if ols::detect(data) {
        return DetectedFormat::Ols;
    }

    // ECU EEPROM/Flash dump (EPR container)
    // Checked late because it uses structural heuristics (no magic bytes)
    if epr::detect(data) {
        return DetectedFormat::Epr;
    }

    // Mercedes CFF has no magic: its checksum and header must be consistent.
    if let Some(layout) = automotive::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Automotive(layout),
        };
    }

    // BF53x/BF56x LDR streams have no signature: a complete block walk is
    // required.
    if let Some(layout) = blackfin_ldr::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::BlackfinLdr(layout),
        };
    }

    // Legacy option ROMs: `55 AA`, a size and a zero byte sum.
    if let Some(layout) = optionrom::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::OptionRom(layout),
        };
    }

    // ZX Spectrum TAP tapes: every block's checksum, a header block first.
    if let Some(layout) = zxtape::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::ZxTape(layout),
        };
    }

    // Headerless FPGA bitstreams: the Xilinx synchronization sequence with a
    // valid packet stream, an iCE40 command stream with its CRC, or a
    // Cyclone V option frame with its CRC.
    if let Some(layout) = bitstream::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Bitstream(layout),
        };
    }

    // Cypress .cyacd/.cyacd2 text has no magic: the header and every row
    // must parse, and every .cyacd row checksum must match.
    if let Some(layout) = mcu::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Mcu(layout),
        };
    }

    // The 40-byte Qualcomm MBN header has no magic: its sizes and pointers
    // must be consistent with the file.
    if let Some(layout) = socboot2::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::SocBoot2(layout),
        };
    }

    // i.MX AHAB containers have a two-byte key (version and tag): the
    // header, image array and signature block header must validate.
    if let Some(layout) = socboot::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::SocBoot(layout),
        };
    }

    // The SNES internal header has no magic: checksum, complement, map mode,
    // title and reset vector must all be consistent.
    if let Some(layout) = nintendo::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Nintendo(layout),
        };
    }

    // Old binary CPIO has a two-byte magic: every header up to the trailer
    // must be valid.
    if let Some(layout) = archives::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Archive(layout),
        };
    }

    // JFFS2 has a 16-bit node magic, so it is recognized only when every
    // node in the image validates.
    if let Some(layout) = mtd::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Mtd(layout),
        };
    }

    // TE images with an unknown machine (only the two-byte `VZ` signature,
    // so every loader check must pass) and flash device images whose first
    // firmware volume follows leading data (the whole image must parse).
    if let Some(layout) = uefi::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Uefi(layout),
        };
    }

    // An FMAP found by search inside a flash image, or a legacy CBFS ROM
    // found through its end pointer: only for inputs nothing else claims.
    if let Some(layout) = coreboot::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Coreboot(layout),
        };
    }

    // TP-Link firmware headers and SafeLoader images have no magic; the
    // whole header structure must validate.
    if let Some(layout) = router::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Router(layout),
        };
    }

    // Espressif images: the magic is one byte (0xE9 also starts x86
    // `JMP rel32` code), so the whole segment walk, the checksum, the digest
    // the header flags, the entry point and the trailing bytes must validate.
    if let Some(layout) = esp::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Esp(layout),
        };
    }

    // Raw Windows CE ROM images have no header: `ECEC` at 0x40 must lead to
    // one ROMHDR consistent with its own position and complete tables.
    if let Some(layout) = wince::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::WinCe(layout),
        };
    }

    // Intel microcode (no magic: every update must validate, checksums
    // included) and AMD flash images (an EFS signature at a documented
    // offset leading to valid directories). After the UEFI and coreboot weak
    // checks, so the EFS never takes an Intel flash descriptor image (its
    // signature is claimed above), an FMAP image (AMD coreboot builds carry
    // one that maps the EFS area too) or a UEFI flash device image: those
    // describe the whole flash, the EFS only its PSP part.
    if let Some(layout) = pcfw::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::PcFw(layout),
        };
    }

    // Snapshots, MSX cartridges and WonderSwan footers have no magic: every
    // block must decode, every address fit, or the checksum match.
    if let Some(layout) = retro2::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Retro2(layout),
        };
    }

    // FAT12/16/32 boot sectors have no magic: the BPB, the FAT type by
    // cluster count and FAT[0] must be consistent. FAT must run before the
    // MBR partition-table check, because a FAT boot sector also ends in
    // `55 AA` and its boot code (or the fake partition table `mkfs.fat
    // --mbr` writes) occupies the partition-table bytes.
    if let Some(layout) = fat::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Fat(layout),
        };
    }

    // MBR: only the two-byte boot signature that boot sectors share, so last
    // among the weak checks for disk images; FAT, exFAT and NTFS boot
    // sectors are refused, and a protective MBR is reported as GPT.
    if let Some(layout) = partitions::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Partitions(layout),
        };
    }

    // zlib and LZMA-alone: two-byte or properties-only signatures,
    // recognized only from a complete decode.
    if let Some(codec) = compressed::detect_weak(data) {
        return DetectedFormat::Container {
            kind: container::Kind::Compressed(codec),
        };
    }

    if let Some(variant) = ti::detect_weak(data) {
        return DetectedFormat::Ti { variant };
    }

    DetectedFormat::Raw
}

/// Parse a binary with a recognised container format.
///
/// This is the single format dispatch of the crate. [`DetectedFormat::Raw`]
/// has no container to parse and returns an error; raw data goes through
/// [`crate::heuristics`].
pub fn parse_detected(data: &[u8], format: &DetectedFormat) -> Result<ClassificationResult> {
    match *format {
        DetectedFormat::Elf { class, endian } => elf::parse(data, class, endian),
        DetectedFormat::Pe { pe_offset } => pe::parse(data, pe_offset),
        DetectedFormat::MachO { bits, big_endian } => macho::parse(data, bits, big_endian),
        DetectedFormat::MachOFat { big_endian, .. } => macho::parse_fat(data, big_endian),
        DetectedFormat::Coff { .. } => coff::parse(data),
        DetectedFormat::Xcoff { bits } => xcoff::parse(data, bits),
        DetectedFormat::Ecoff { variant } => ecoff::parse(data, variant),
        DetectedFormat::Aout { variant } => aout::parse(data, variant),
        DetectedFormat::Mz { variant } => mz::parse(data, variant),
        DetectedFormat::Pef => pef::parse(data),
        DetectedFormat::Wasm => wasm::parse(data),
        DetectedFormat::JavaClass => java::parse(data),
        DetectedFormat::Dex { variant } => dex::parse(data, variant),
        DetectedFormat::Bflt => bflt::parse(data),
        DetectedFormat::Console { variant } => console::parse(data, variant),
        DetectedFormat::Kernel { variant } => kernel::parse(data, variant),
        DetectedFormat::Ar { variant } => ar::parse(data, variant),
        DetectedFormat::Hex { variant } => hex::parse(data, variant),
        DetectedFormat::Omf => omf::parse(data),
        DetectedFormat::Som => som::parse(data),
        DetectedFormat::Aof => aof::parse(data),
        DetectedFormat::Epoc => epoc::parse(data),
        DetectedFormat::Palm => palm::parse(data),
        DetectedFormat::AmigaHunk => amiga_hunk::parse(data),
        DetectedFormat::Tds => tds::parse(data),
        DetectedFormat::Os9 => os9::parse(data),
        DetectedFormat::Goff => goff::parse(data),
        DetectedFormat::LlvmBc { variant } => llvm_bc::parse(data, variant),
        DetectedFormat::FatElf => fatelf::parse(data),
        DetectedFormat::Ols => ols::parse(data),
        DetectedFormat::Epr => epr::parse(data),
        DetectedFormat::Sgo => sgo::parse(data),
        DetectedFormat::Vbf => vbf::parse(data),
        DetectedFormat::Frf => frf::parse(data),
        DetectedFormat::Bcf => bcf::parse(data),
        DetectedFormat::Sox => sox::parse(data),
        DetectedFormat::D10 => d10::parse(data),
        DetectedFormat::TiC55xBoot => ti_c55x::parse(data),
        DetectedFormat::Ti { variant } => ti::parse(data, variant),
        DetectedFormat::Spc => spc::parse(data),
        DetectedFormat::TmObj => tmobj::parse(data),
        DetectedFormat::Lod => lod::parse(data),
        DetectedFormat::Container { kind } => {
            container::parse(data, kind).map(|c| c.classification())
        }
        DetectedFormat::Raw => Err(crate::error::ClassifierError::UnknownFormat {
            magic: data.iter().take(4).copied().collect(),
        }),
    }
}

/// Parse a format built on the shared container model. Returns `None` for
/// formats that are classified by their own path in `lib.rs`.
pub fn parse_container_model<'a>(
    data: &'a [u8],
    format: &DetectedFormat,
) -> Option<Result<container::Container<'a>>> {
    match *format {
        DetectedFormat::Container { kind } => Some(container::parse(data, kind)),
        DetectedFormat::Kernel { variant } => Some(kernel::parse_container(data, variant)),
        DetectedFormat::Bflt => Some(bflt::parse_container(data)),
        _ => None,
    }
}

/// Read bytes with bounds checking.
pub fn read_bytes<'a>(data: &'a [u8], offset: usize, len: usize) -> Result<&'a [u8]> {
    if offset + len > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset,
            expected: len,
            actual: data.len().saturating_sub(offset),
        });
    }
    Ok(&data[offset..offset + len])
}

/// Read a u16 with specified endianness.
pub fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> Result<u16> {
    let bytes = read_bytes(data, offset, 2)?;
    Ok(if little_endian {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_be_bytes([bytes[0], bytes[1]])
    })
}

/// Read a u32 with specified endianness.
pub fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Result<u32> {
    let bytes = read_bytes(data, offset, 4)?;
    Ok(if little_endian {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

/// Read a u64 with specified endianness.
pub fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> Result<u64> {
    let bytes = read_bytes(data, offset, 8)?;
    Ok(if little_endian {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    } else {
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_elf() {
        let data = [0x7F, b'E', b'L', b'F', 2, 1, 0, 0];
        match detect_format(&data) {
            DetectedFormat::Elf {
                class: 2,
                endian: 1,
            } => {}
            _ => panic!("Expected ELF detection"),
        }
    }

    #[test]
    fn test_detect_macho() {
        let data = [0xCF, 0xFA, 0xED, 0xFE];
        match detect_format(&data) {
            DetectedFormat::MachO {
                bits: 64,
                big_endian: false,
            } => {}
            _ => panic!("Expected Mach-O 64 LE detection"),
        }
    }

    #[test]
    fn test_read_u32() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32(&data, 0, true).unwrap(), 0x04030201);
        assert_eq!(read_u32(&data, 0, false).unwrap(), 0x01020304);
    }

    #[test]
    fn test_detect_wasm() {
        let data = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        match detect_format(&data) {
            DetectedFormat::Wasm => {}
            other => panic!("Expected Wasm, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_java_class() {
        // Java class file magic 0xCAFEBABE followed by valid version
        let data = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
        match detect_format(&data) {
            DetectedFormat::JavaClass => {}
            other => panic!("Expected JavaClass, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_dex() {
        let data = [b'd', b'e', b'x', b'\n', b'0', b'3', b'5', 0x00];
        match detect_format(&data) {
            DetectedFormat::Dex {
                variant: dex::DexVariant::Dex { .. },
            } => {}
            other => panic!("Expected Dex, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_pef() {
        // "Joy!" + "peff"
        let data = [b'J', b'o', b'y', b'!', b'p', b'e', b'f', b'f', 0, 0, 0, 0];
        match detect_format(&data) {
            DetectedFormat::Pef => {}
            other => panic!("Expected Pef, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_bflt() {
        let data = [b'b', b'F', b'L', b'T', 0, 0, 0, 4];
        match detect_format(&data) {
            DetectedFormat::Bflt => {}
            other => panic!("Expected Bflt, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_ar() {
        let data = [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n'];
        match detect_format(&data) {
            DetectedFormat::Ar { .. } => {}
            other => panic!("Expected Ar, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_llvm_bc() {
        let data = [b'B', b'C', 0xC0, 0xDE, 0, 0, 0, 0];
        match detect_format(&data) {
            DetectedFormat::LlvmBc {
                variant: llvm_bc::LlvmVariant::Bitcode,
            } => {}
            other => panic!("Expected LlvmBc Bitcode, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_console_xbe() {
        let data = [b'X', b'B', b'E', b'H', 0, 0, 0, 0];
        match detect_format(&data) {
            DetectedFormat::Console {
                variant: console::ConsoleFormat::Xbe,
            } => {}
            other => panic!("Expected Console Xbe, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_console_nso() {
        let data = [b'N', b'S', b'O', b'0', 0, 0, 0, 0];
        match detect_format(&data) {
            DetectedFormat::Console {
                variant: console::ConsoleFormat::Nso,
            } => {}
            other => panic!("Expected Console Nso, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_intel_hex() {
        let data = b":020000040800F2\r\n:1000000000";
        match detect_format(data) {
            DetectedFormat::Hex {
                variant: hex::HexVariant::IntelHex { .. },
            } => {}
            other => panic!("Expected Intel HEX, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_srec() {
        let data = b"S00600004844521B\r\n";
        match detect_format(data) {
            DetectedFormat::Hex {
                variant: hex::HexVariant::Srec { .. },
            } => {}
            other => panic!("Expected S-record, got {:?}", other),
        }
    }
}
