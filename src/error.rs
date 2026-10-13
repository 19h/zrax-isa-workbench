//! Error types for the Zrax classifier.
//!
//! This module defines all error types used throughout the classifier,
//! providing detailed error information for debugging and user feedback.

use thiserror::Error;

/// Primary error type for the Zrax classifier.
#[derive(Debug, Error)]
pub enum ClassifierError {
    /// IO error during file operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The file is too small to contain valid binary data.
    #[error("File too small: expected at least {expected} bytes, got {actual}")]
    FileTooSmall { expected: usize, actual: usize },

    /// Invalid magic bytes for the detected format.
    #[error("Invalid magic bytes: expected {expected}, got {actual}")]
    InvalidMagic { expected: String, actual: String },

    /// Unsupported or unknown file format.
    #[error("Unknown file format: magic bytes {magic:02X?}")]
    UnknownFormat { magic: Vec<u8> },

    /// Error parsing ELF format.
    #[error("ELF parse error: {message}")]
    ElfParseError { message: String },

    /// Error parsing AOR AR-DV10 firmware.
    #[error("D10 parse error: {message}")]
    D10ParseError { message: String },

    /// Error parsing a TI C55x serial boot table.
    #[error("TI C55x boot-table parse error: {message}")]
    TiC55xBootParseError { message: String },

    #[error("TI container parse error: {message}")]
    TiContainerParseError { message: String },

    /// Error decoding a compressed stream (gzip, xz, LZ4, Zstandard, ...).
    #[error("Compressed stream parse error: {message}")]
    CompressedParseError {
        /// What is wrong with the stream.
        message: String,
    },

    /// The concatenated load sections of a container exceed the
    /// per-extraction limit.
    #[error("Decoded payload exceeds {} MiB", .limit >> 20)]
    PayloadLimit {
        /// The limit in bytes.
        limit: usize,
    },

    /// Error parsing an ARM Image Format (AIF) executable image.
    #[error("ARM AIF parse error: {message}")]
    AifParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a partition table (MBR, GPT or Apple Partition Map).
    #[error("Partition table parse error: {message}")]
    PartitionParseError {
        /// What is wrong with the table.
        message: String,
    },

    /// Error parsing a FAT12, FAT16, FAT32 or exFAT volume.
    #[error("FAT filesystem parse error: {message}")]
    FatParseError {
        /// What is wrong with the volume.
        message: String,
    },

    /// Error parsing an ISO 9660 optical disc filesystem image.
    #[error("ISO 9660 parse error: {message}")]
    Iso9660ParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a console disc image (`GameCube`, Wii, Xbox XDVDFS).
    #[error("Console disc parse error: {message}")]
    ConsoleDiscParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a Java runtime image (jimage) or JMOD file.
    #[error("Java image parse error: {message}")]
    JavaImageParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a Windows minidump or kernel crash dump.
    #[error("Minidump parse error: {message}")]
    MinidumpParseError {
        /// What is wrong with the dump.
        message: String,
    },

    /// Error parsing a `NetWare` Loadable Module (i386, SPARC, PowerPC or
    /// Alpha NLM).
    #[error("NetWare module parse error: {message}")]
    NlmParseError {
        /// What is wrong with the module.
        message: String,
    },

    /// Error parsing a PC/GEOS geode (`.geo` application, library or
    /// driver).
    #[error("GEOS geode parse error: {message}")]
    GeosParseError {
        /// What is wrong with the geode.
        message: String,
    },

    /// Error parsing a Psy-Q (SN Systems) LNK object file.
    #[error("PsyQ object parse error: {message}")]
    PsyqParseError {
        /// What is wrong with the object file.
        message: String,
    },

    /// Error parsing an Espressif firmware image or flash dump (ESP32
    /// family, ESP8266, ESP-IDF partition table).
    #[error("Espressif image parse error: {message}")]
    EspParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing an EROFS filesystem image.
    #[error("EROFS parse error: {message}")]
    ErofsParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a console or home-computer image (Master System,
    /// 32X, Saturn IP.BIN, Sega CD, MSX, Lynx, Atari 7800, C64 CRT, Atari
    /// ST program, ZX Spectrum snapshot, `WonderSwan`, Neo Geo Pocket).
    #[error("Console or home computer image parse error: {message}")]
    RetroHomeParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a miscellaneous boot image (OP-TEE header, Amlogic
    /// burning image, Allwinner `IMAGEWTY`, barebox).
    #[error("Boot image parse error: {message}")]
    BootImageParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a QNX Neutrino image filesystem (bootable IFS or bare
    /// `imagefs`).
    #[error("QNX image parse error: {message}")]
    QnxParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a Windows CE BIN file or raw ROM image.
    #[error("Windows CE image parse error: {message}")]
    WinCeParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a PC firmware blob: Intel microcode updates, AMD
    /// microcode containers, Intel ME flash partition tables and code
    /// partition directories, AMD Embedded Firmware Structures and PSP or
    /// BIOS directories.
    #[error("PC firmware parse error: {message}")]
    PcFirmwareParseError {
        /// What is wrong with the blob.
        message: String,
    },

    /// Error parsing an FPGA configuration bitstream (Xilinx, Lattice,
    /// Intel).
    #[error("FPGA bitstream parse error: {message}")]
    BitstreamParseError {
        /// What is wrong with the bitstream.
        message: String,
    },

    /// Error parsing an MCU update image (UF2, `DfuSe`, GBL, `.cyacd`).
    #[error("MCU image parse error: {message}")]
    McuImageParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a router firmware wrapper (Broadcom TRX, Netgear CHK,
    /// D-Link SEAMA, TP-Link firmware headers and `SafeLoader` images).
    #[error("Router firmware parse error: {message}")]
    RouterImageParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a UEFI firmware volume (FFS files and sections), a TE
    /// image or an Intel flash descriptor image.
    #[error("UEFI firmware parse error: {message}")]
    UefiParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a flash filesystem image (UBI, UBIFS or JFFS2).
    #[error("Flash filesystem parse error: {message}")]
    MtdParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a read-only filesystem image (Squashfs, Cramfs,
    /// romfs).
    #[error("Read-only filesystem parse error: {message}")]
    RofsParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a system-on-chip boot ROM image (Allwinner eGON or TOC0,
    /// Rockchip, `MediaTek` preloader, Qualcomm MBN).
    #[error("SoC loader parse error: {message}")]
    SocBoot2ParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a console executable or ROM image (Mega Drive ROM,
    /// PS-X EXE, Dreamcast IP.BIN, Wii U RPX/RPL, 3DS NCCH/3DSX, PSP PBP).
    #[error("Console image parse error: {message}")]
    RetroConsoleParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing an Apple image: Image4 (IMG4, IM4P, IM4M, IM4R) or a
    /// dyld shared cache.
    #[error("Apple image parse error: {message}")]
    AppleParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing an Android image: boot or `vendor_boot` image, sparse
    /// image, OTA payload or bootloader pack.
    #[error("Android image parse error: {message}")]
    AndroidParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a system-on-chip boot image (Xilinx `BOOT.BIN`, NXP i.MX
    /// image, NXP Secure Binary).
    #[error("SoC boot image parse error: {message}")]
    SocBootParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing a Nintendo console ROM image (DS, GBA, Game Boy, NES,
    /// SNES, Nintendo 64).
    #[error("Nintendo ROM parse error: {message}")]
    NintendoRomParseError {
        /// What is wrong with the image.
        message: String,
    },

    /// Error parsing an archive container (ZIP, tar, CPIO).
    #[error("Archive container parse error: {message}")]
    ArchivesParseError {
        /// What is wrong with the archive.
        message: String,
    },

    /// Error parsing an ext2, ext3 or ext4 filesystem image.
    #[error("ext filesystem parse error: {message}")]
    ExtParseError {
        /// What is wrong with the filesystem.
        message: String,
    },

    /// Error parsing a Chromium FMAP flash image or a coreboot CBFS.
    #[error("coreboot image parse error: {message}")]
    CorebootParseError {
        /// What is wrong with the map or file system.
        message: String,
    },

    /// Error parsing an automotive flash container (ODX, RWD, CUW, CFF).
    #[error("Automotive container parse error: {message}")]
    AutomotiveParseError {
        /// What is wrong with the container.
        message: String,
    },

    /// Error parsing a chiptune program file (NSF, SID, GBS, PSF, HES, KSS,
    /// SAP, AY, SNDH, Pack-Ice).
    #[error("Chiptune parse error: {message}")]
    ChiptuneParseError {
        /// What is wrong with the file.
        message: String,
    },

    /// Error parsing a Blackfin LDR boot stream.
    #[error("Blackfin LDR parse error: {message}")]
    BlackfinLdrParseError {
        /// What is wrong with the stream.
        message: String,
    },

    /// Error parsing a PCI or ISA option ROM.
    #[error("Option ROM parse error: {message}")]
    OptionRomParseError {
        /// What is wrong with the ROM.
        message: String,
    },

    /// Error parsing a Huawei `UPDATE.APP` package.
    #[error("Huawei package parse error: {message}")]
    HuaweiParseError {
        /// What is wrong with the package.
        message: String,
    },

    /// Error parsing a ZX Spectrum tape image (TZX, TAP).
    #[error("ZX Spectrum tape parse error: {message}")]
    ZxTapeParseError {
        /// What is wrong with the tape image.
        message: String,
    },

    /// Error parsing PE/COFF format.
    #[error("PE/COFF parse error: {message}")]
    PeParseError { message: String },

    /// Error parsing Mach-O format.
    #[error("Mach-O parse error: {message}")]
    MachOParseError { message: String },

    /// Unknown or unsupported e_machine value in ELF.
    #[error("Unknown ELF e_machine value: {value} (0x{value:04X})")]
    UnknownElfMachine { value: u16 },

    /// Unknown or unsupported PE machine type.
    #[error("Unknown PE machine type: {value} (0x{value:04X})")]
    UnknownPeMachine { value: u16 },

    /// Unknown or unsupported Mach-O CPU type.
    #[error("Unknown Mach-O CPU type: {value} (0x{value:08X})")]
    UnknownMachOCpuType { value: u32 },

    /// Truncated data when reading.
    #[error("Truncated data at offset {offset}: expected {expected} bytes, got {actual}")]
    TruncatedData {
        offset: usize,
        expected: usize,
        actual: usize,
    },

    /// Error parsing a.out format.
    #[error("a.out parse error: {message}")]
    AoutParseError { message: String },

    /// Error parsing DOS/NE/LE format.
    #[error("DOS/NE/LE parse error: {message}")]
    DosParseError { message: String },

    /// Error parsing PEF format.
    #[error("PEF parse error: {message}")]
    PefParseError { message: String },

    /// Error parsing hex format (Intel HEX, S-record, TI-TXT).
    #[error("Hex format parse error: {message}")]
    HexParseError { message: String },

    /// Error parsing bFLT format.
    #[error("bFLT parse error: {message}")]
    BfltParseError { message: String },

    /// Error parsing GOFF format.
    #[error("GOFF parse error: {message}")]
    GoffParseError { message: String },

    /// Error parsing WebAssembly.
    #[error("WebAssembly parse error: {message}")]
    WasmParseError { message: String },

    /// Error parsing Java class file.
    #[error("Java class parse error: {message}")]
    JavaClassParseError { message: String },

    /// Error parsing DEX/ODEX.
    #[error("DEX parse error: {message}")]
    DexParseError { message: String },

    /// Error parsing game console format.
    #[error("Console format parse error: {message}")]
    ConsoleParseError { message: String },

    /// Error parsing kernel/boot image.
    #[error("Kernel image parse error: {message}")]
    KernelParseError { message: String },

    /// Error parsing archive format.
    #[error("Archive parse error: {message}")]
    ArchiveParseError { message: String },

    /// Invalid checksum in format.
    #[error("Invalid checksum: expected {expected}, got {actual}")]
    InvalidChecksum { expected: String, actual: String },

    /// Invalid section or segment.
    #[error("Invalid {kind} at index {index}: {message}")]
    InvalidSection {
        kind: String,
        index: usize,
        message: String,
    },

    /// Heuristic analysis failed to determine architecture.
    #[error("Heuristic analysis inconclusive: confidence {confidence:.2}% below threshold {threshold:.2}%")]
    HeuristicInconclusive { confidence: f64, threshold: f64 },

    /// Multiple architectures detected (e.g., fat binary).
    #[error("Multiple architectures detected: {architectures:?}")]
    MultipleArchitectures { architectures: Vec<String> },

    /// Configuration error.
    #[error("Configuration error: {message}")]
    ConfigError { message: String },
}

/// Result type alias for classifier operations.
pub type Result<T> = std::result::Result<T, ClassifierError>;

/// Extension trait for adding context to errors.
pub trait ResultExt<T> {
    /// Add context to an error.
    fn context(self, msg: impl Into<String>) -> Result<T>;
}

impl<T> ResultExt<T> for Result<T> {
    fn context(self, msg: impl Into<String>) -> Result<T> {
        self.map_err(|e| ClassifierError::ElfParseError {
            message: format!("{}: {}", msg.into(), e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ClassifierError::FileTooSmall {
            expected: 16,
            actual: 4,
        };
        assert!(err.to_string().contains("16"));
        assert!(err.to_string().contains("4"));
    }

    #[test]
    fn test_unknown_machine() {
        let err = ClassifierError::UnknownElfMachine { value: 0xBEEF };
        let msg = err.to_string();
        assert!(msg.contains("BEEF"));
    }
}
