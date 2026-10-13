//! The shared container model.
//!
//! A container either loads sections (bytes bound for target memory) or
//! wraps children (independent images: kernels, ramdisks, partitions,
//! filesystem members, cores). This generalizes the TI container model
//! (`formats::ti`) so that every family built on it is classified by one
//! path in `lib.rs`: children on their own, sections as one payload, and the
//! container's own target field over both.
//!
//! Coordinates: `offset` and `stored_size` always refer to the stored bytes
//! in the input file, so hex and entropy views can show them. `data` is the
//! bytes that are analyzed; when a codec or other transform produced them,
//! `transform` names it and the bytes are owned.

use crate::error::{ClassifierError, Result};
use crate::formats::{
    archives, automotive, bitstream, blackfin_ldr, chiptune, compressed, coreboot, erofs, ext,
    huawei, mcu, mtd, nintendo, optionrom, pcfw, rofs, router, socboot, socboot2, uefi, wince,
    zxtape, MAX_PAYLOAD,
};
use crate::types::{
    ClassificationResult, Endianness, FileFormat, Isa, MetadataEntry, MetadataKey, MetadataValue,
    Variant,
};
use std::borrow::Cow;

/// Most components one container lists. Formats stop enumerating there
/// and record how many they left out.
pub const MAX_COMPONENTS: usize = 4096;

/// Most decoded bytes one container extracts across all of its components
/// (filesystem members, partitions, expanded images), in addition to the
/// per-component [`MAX_PAYLOAD`] limit. Formats stop extracting there and
/// record what they left out.
pub const MAX_EXTRACTED: usize = 256 << 20;

/// Whether `prefix`, the first bytes of a member, starts a format the
/// classifier recognizes. Archive and filesystem parsers use it to avoid
/// extracting members that would only be listed if recognized; weak
/// formats that need their whole input may not be recognized from a
/// prefix.
pub fn is_recognized(prefix: &[u8]) -> bool {
    !matches!(super::detect_format(prefix), super::DetectedFormat::Raw)
}

/// A layout recognized by [`crate::formats::detect_format`] and parsed into
/// a [`Container`]. Each family keeps its own layout enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A standalone compressed stream.
    Compressed(compressed::Codec),
    /// An automotive flash container.
    Automotive(automotive::Layout),
    /// A chiptune program file.
    Chiptune(chiptune::Layout),
    /// A Blackfin LDR boot stream.
    BlackfinLdr(blackfin_ldr::Layout),
    /// A PCI or legacy option ROM.
    OptionRom(optionrom::Layout),
    /// A Huawei `UPDATE.APP` package.
    Huawei(huawei::Layout),
    /// A ZX Spectrum tape image.
    ZxTape(zxtape::Layout),
    /// An FPGA configuration bitstream.
    Bitstream(bitstream::Layout),
    /// An MCU update image (UF2, `DfuSe`, GBL, `.cyacd`, DFU suffix, EBL,
    /// Nordic init packet).
    Mcu(mcu::Layout),
    /// A system-on-chip boot ROM image (Allwinner, Rockchip, `MediaTek`,
    /// Qualcomm).
    SocBoot2(socboot2::Layout),
    /// A console executable or ROM image.
    Retro(super::retro::Layout),
    /// An Apple Image4 file or dyld shared cache.
    Apple(super::apple::Layout),
    /// An Android boot, `vendor_boot`, sparse, OTA, bootloader-pack,
    /// `super`, DTBO or vbmeta image.
    Android(super::android::Layout),
    /// A system-on-chip boot image (Xilinx `BOOT.BIN`, NXP i.MX, NXP Secure
    /// Binary).
    SocBoot(socboot::Layout),
    /// A Nintendo console ROM image.
    Nintendo(nintendo::Layout),
    /// A ZIP, tar or CPIO archive.
    Archive(archives::Layout),
    /// A read-only filesystem image (Squashfs, Cramfs, romfs).
    Rofs(rofs::Layout),
    /// A flash filesystem image: UBI, UBIFS or JFFS2.
    Mtd(mtd::Layout),
    /// An ext2, ext3 or ext4 filesystem image.
    Ext(ext::Layout),
    /// A UEFI firmware volume, TE image or Intel flash descriptor image.
    Uefi(uefi::Layout),
    /// A Chromium FMAP flash image or a coreboot CBFS.
    Coreboot(coreboot::Layout),
    /// A router firmware wrapper.
    Router(router::Layout),
    /// An Espressif image or flash dump.
    Esp(super::esp::Layout),
    /// A QNX Neutrino bootable image or image filesystem.
    Qnx(super::qnx::Layout),
    /// A Windows CE BIN file or raw ROM image.
    WinCe(wince::Layout),
    /// A PC firmware blob: microcode, Intel ME partition tables, AMD PSP
    /// directories.
    PcFw(pcfw::Layout),
    /// A miscellaneous boot image: OP-TEE header, Amlogic burning image,
    /// Allwinner `IMAGEWTY` or barebox.
    BootMisc(super::bootmisc::Layout),
    /// A console or home-computer image (Master System, 32X, Saturn, Sega
    /// CD, MSX, Lynx, 7800, C64, Atari ST, ZX Spectrum, `WonderSwan`, Neo
    /// Geo Pocket).
    Retro2(super::retro2::Layout),
    /// An EROFS filesystem image.
    Erofs(erofs::Layout),
    /// A partition table: MBR, GPT or Apple Partition Map.
    Partitions(super::partitions::Layout),
    /// A FAT12, FAT16, FAT32 or exFAT volume.
    Fat(super::fat::Layout),
    /// An ISO 9660 optical disc filesystem image.
    Iso9660(super::iso9660::Layout),
    /// A console disc image: `GameCube`, Wii or Xbox XDVDFS.
    Discs(super::discs::Layout),
    /// A Java runtime image (jimage) or JMOD file.
    JavaImage(super::javaimage::Layout),
    /// A Windows minidump or kernel crash dump.
    Minidump(super::minidump::Layout),
    /// A `NetWare` Loadable Module.
    Nlm(super::nlm::Layout),
    /// A PC/GEOS geode.
    Geos(super::geos::Layout),
    /// A Psy-Q (SN Systems) LNK object file.
    Psyq(super::psyq::Layout),
    /// An ARM Image Format (AIF) executable image.
    Aif(super::aif::Layout),
    /// A Symbian OS v9 SIS installation package.
    Sis(super::sis::Layout),
    /// A UEFI capsule: FMP, nested FMP, JSON, Windows UX, `EFI_CAPSULE_GUID`
    /// or a vendor capsule header.
    Capsule(super::capsule::Layout),
    /// A virtual disk image: QCOW2, VMDK, VHD, VHDX or VDI.
    VirtualDisk(super::vdisk::Layout),
    /// A compressed or packed disc container: GCZ, CISO, WBFS, CSO or ZSO.
    DiscImage(super::discimg::Layout),
    /// A Commodore disk or tape image: D64, D71, D81 or T64.
    Cbm(super::cbm::Layout),
    /// An Amiga disk image: ADF floppy, Rigid Disk Block disk or hardfile.
    Adf(super::adf::Layout),
    /// An Atari 8-bit ATR disk image or DOS binary load file.
    Atari8(super::atari8::Layout),
    /// An Apple II disk image: DOS 3.3, `ProDOS` or 2IMG.
    Apple2(super::apple2::Layout),
    /// An Amstrad CPC or Spectrum +3 disk image, or a file with an AMSDOS
    /// or +3DOS header.
    CpcDsk(super::cpcdsk::Layout),
    /// A Nintendo 3DS NCSD image or CIA, or a Nintendo Switch PFS0 archive
    /// or XCI gamecard image.
    Nintendo2(super::nintendo2::Layout),
    /// An Apple disk image: UDIF or encrypted.
    Dmg(super::dmg::Layout),
    /// An HFS Plus or HFSX volume, plain or in an HFS wrapper.
    HfsPlus(super::hfsplus::Layout),
    /// An Xbox 360 STFS package (`XContent` `CON `, `LIVE` or `PIRS`).
    Stfs(super::stfs::Layout),
    /// A firmware package wrapper: `MikroTik` NPK, Ubiquiti firmware image or
    /// `ChromeOS` kernel partition.
    FwPack(super::fwpack::Layout),
    /// An APFS container.
    Apfs(super::apfs::Layout),
    /// A Microsoft cabinet file.
    Cab(super::cab::Layout),
    /// A Microsoft Full Flash Update (FFU) image.
    Ffu(super::ffu::Layout),
    /// An RPM package.
    Rpm(super::rpm::Layout),
    /// An application bundle: `PyInstaller` archive, Electron ASAR archive or
    /// .NET single-file bundle.
    AppBundle(super::appbundle::Layout),
}

impl Kind {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Compressed(codec) => codec.format(),
            Self::Automotive(layout) => layout.format(),
            Self::Chiptune(layout) => layout.format(),
            Self::BlackfinLdr(layout) => layout.format(),
            Self::OptionRom(layout) => layout.format(),
            Self::Huawei(layout) => layout.format(),
            Self::ZxTape(layout) => layout.format(),
            Self::Bitstream(layout) => layout.format(),
            Self::Mcu(layout) => layout.format(),
            Self::SocBoot2(layout) => layout.format(),
            Self::Retro(layout) => layout.format(),
            Self::Apple(layout) => layout.format(),
            Self::Android(layout) => layout.format(),
            Self::SocBoot(layout) => layout.format(),
            Self::Nintendo(layout) => layout.format(),
            Self::Archive(layout) => layout.format(),
            Self::Rofs(layout) => layout.format(),
            Self::Mtd(layout) => layout.format(),
            Self::Ext(layout) => layout.format(),
            Self::Uefi(layout) => layout.format(),
            Self::Coreboot(layout) => layout.format(),
            Self::Router(layout) => layout.format(),
            Self::Esp(layout) => layout.format(),
            Self::Qnx(layout) => layout.format(),
            Self::WinCe(layout) => layout.format(),
            Self::PcFw(layout) => layout.format(),
            Self::BootMisc(layout) => layout.format(),
            Self::Retro2(layout) => layout.format(),
            Self::Erofs(layout) => layout.format(),
            Self::Partitions(layout) => layout.format(),
            Self::Fat(layout) => layout.format(),
            Self::Iso9660(layout) => layout.format(),
            Self::Discs(layout) => layout.format(),
            Self::JavaImage(layout) => layout.format(),
            Self::Minidump(layout) => layout.format(),
            Self::Nlm(layout) => layout.format(),
            Self::Geos(layout) => layout.format(),
            Self::Psyq(layout) => layout.format(),
            Self::Aif(layout) => layout.format(),
            Self::Sis(layout) => layout.format(),
            Self::Capsule(layout) => layout.format(),
            Self::VirtualDisk(layout) => layout.format(),
            Self::DiscImage(layout) => layout.format(),
            Self::Cbm(layout) => layout.format(),
            Self::Adf(layout) => layout.format(),
            Self::Atari8(layout) => layout.format(),
            Self::Apple2(layout) => layout.format(),
            Self::CpcDsk(layout) => layout.format(),
            Self::Nintendo2(layout) => layout.format(),
            Self::Dmg(layout) => layout.format(),
            Self::HfsPlus(layout) => layout.format(),
            Self::Stfs(layout) => layout.format(),
            Self::FwPack(layout) => layout.format(),
            Self::Apfs(layout) => layout.format(),
            Self::Cab(layout) => layout.format(),
            Self::Ffu(layout) => layout.format(),
            Self::Rpm(layout) => layout.format(),
            Self::AppBundle(layout) => layout.format(),
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Compressed(codec) => codec.label(),
            Self::Automotive(layout) => layout.label(),
            Self::Chiptune(layout) => layout.label(),
            Self::BlackfinLdr(layout) => layout.label(),
            Self::OptionRom(layout) => layout.label(),
            Self::Huawei(layout) => layout.label(),
            Self::ZxTape(layout) => layout.label(),
            Self::Bitstream(layout) => layout.label(),
            Self::Mcu(layout) => layout.label(),
            Self::SocBoot2(layout) => layout.label(),
            Self::Retro(layout) => layout.label(),
            Self::Apple(layout) => layout.label(),
            Self::Android(layout) => layout.label(),
            Self::SocBoot(layout) => layout.label(),
            Self::Nintendo(layout) => layout.label(),
            Self::Archive(layout) => layout.label(),
            Self::Rofs(layout) => layout.label(),
            Self::Mtd(layout) => layout.label(),
            Self::Ext(layout) => layout.label(),
            Self::Uefi(layout) => layout.label(),
            Self::Coreboot(layout) => layout.label(),
            Self::Router(layout) => layout.label(),
            Self::Esp(layout) => layout.label(),
            Self::Qnx(layout) => layout.label(),
            Self::WinCe(layout) => layout.label(),
            Self::PcFw(layout) => layout.label(),
            Self::BootMisc(layout) => layout.label(),
            Self::Retro2(layout) => layout.label(),
            Self::Erofs(layout) => layout.label(),
            Self::Partitions(layout) => layout.label(),
            Self::Fat(layout) => layout.label(),
            Self::Iso9660(layout) => layout.label(),
            Self::Discs(layout) => layout.label(),
            Self::JavaImage(layout) => layout.label(),
            Self::Minidump(layout) => layout.label(),
            Self::Nlm(layout) => layout.label(),
            Self::Geos(layout) => layout.label(),
            Self::Psyq(layout) => layout.label(),
            Self::Aif(layout) => layout.label(),
            Self::Sis(layout) => layout.label(),
            Self::Capsule(layout) => layout.label(),
            Self::VirtualDisk(layout) => layout.label(),
            Self::DiscImage(layout) => layout.label(),
            Self::Cbm(layout) => layout.label(),
            Self::Adf(layout) => layout.label(),
            Self::Atari8(layout) => layout.label(),
            Self::Apple2(layout) => layout.label(),
            Self::CpcDsk(layout) => layout.label(),
            Self::Nintendo2(layout) => layout.label(),
            Self::Dmg(layout) => layout.label(),
            Self::HfsPlus(layout) => layout.label(),
            Self::Stfs(layout) => layout.label(),
            Self::FwPack(layout) => layout.label(),
            Self::Apfs(layout) => layout.label(),
            Self::Cab(layout) => layout.label(),
            Self::Ffu(layout) => layout.label(),
            Self::Rpm(layout) => layout.label(),
            Self::AppBundle(layout) => layout.label(),
        }
    }

    /// Recognized from complete structure rather than a magic value.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Compressed(codec) => codec.is_weak(),
            Self::Automotive(layout) => layout.is_weak(),
            Self::Chiptune(layout) => layout.is_weak(),
            Self::BlackfinLdr(layout) => layout.is_weak(),
            Self::OptionRom(layout) => layout.is_weak(),
            Self::Huawei(layout) => layout.is_weak(),
            Self::ZxTape(layout) => layout.is_weak(),
            Self::Bitstream(layout) => layout.is_weak(),
            Self::Mcu(layout) => layout.is_weak(),
            Self::SocBoot2(layout) => layout.is_weak(),
            Self::Retro(layout) => layout.is_weak(),
            Self::Apple(layout) => layout.is_weak(),
            Self::Android(layout) => layout.is_weak(),
            Self::SocBoot(layout) => layout.is_weak(),
            Self::Nintendo(layout) => layout.is_weak(),
            Self::Archive(layout) => layout.is_weak(),
            Self::Rofs(layout) => layout.is_weak(),
            Self::Mtd(layout) => layout.is_weak(),
            Self::Ext(layout) => layout.is_weak(),
            Self::Uefi(layout) => layout.is_weak(),
            Self::Coreboot(layout) => layout.is_weak(),
            Self::Router(layout) => layout.is_weak(),
            Self::Esp(layout) => layout.is_weak(),
            Self::Qnx(layout) => layout.is_weak(),
            Self::WinCe(layout) => layout.is_weak(),
            Self::PcFw(layout) => layout.is_weak(),
            Self::BootMisc(layout) => layout.is_weak(),
            Self::Retro2(layout) => layout.is_weak(),
            Self::Erofs(layout) => layout.is_weak(),
            Self::Partitions(layout) => layout.is_weak(),
            Self::Fat(layout) => layout.is_weak(),
            Self::Iso9660(layout) => layout.is_weak(),
            Self::Discs(layout) => layout.is_weak(),
            Self::JavaImage(layout) => layout.is_weak(),
            Self::Minidump(layout) => layout.is_weak(),
            Self::Nlm(layout) => layout.is_weak(),
            Self::Geos(layout) => layout.is_weak(),
            Self::Psyq(layout) => layout.is_weak(),
            Self::Aif(layout) => layout.is_weak(),
            Self::Sis(layout) => layout.is_weak(),
            Self::Capsule(layout) => layout.is_weak(),
            Self::VirtualDisk(layout) => layout.is_weak(),
            Self::DiscImage(layout) => layout.is_weak(),
            Self::Cbm(layout) => layout.is_weak(),
            Self::Adf(layout) => layout.is_weak(),
            Self::Atari8(layout) => layout.is_weak(),
            Self::Apple2(layout) => layout.is_weak(),
            Self::CpcDsk(layout) => layout.is_weak(),
            Self::Nintendo2(layout) => layout.is_weak(),
            Self::Dmg(layout) => layout.is_weak(),
            Self::HfsPlus(layout) => layout.is_weak(),
            Self::Stfs(layout) => layout.is_weak(),
            Self::FwPack(layout) => layout.is_weak(),
            Self::Apfs(layout) => layout.is_weak(),
            Self::Cab(layout) => layout.is_weak(),
            Self::Ffu(layout) => layout.is_weak(),
            Self::Rpm(layout) => layout.is_weak(),
            Self::AppBundle(layout) => layout.is_weak(),
        }
    }
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// The layout's parse error when `data` does not hold a valid instance.
pub fn parse(data: &[u8], kind: Kind) -> Result<Container<'_>> {
    match kind {
        Kind::Compressed(codec) => compressed::parse_container(data, codec),
        Kind::Automotive(layout) => automotive::parse_container(data, layout),
        Kind::Chiptune(layout) => chiptune::parse_container(data, layout),
        Kind::BlackfinLdr(layout) => blackfin_ldr::parse_container(data, layout),
        Kind::OptionRom(layout) => optionrom::parse_container(data, layout),
        Kind::Huawei(layout) => huawei::parse_container(data, layout),
        Kind::ZxTape(layout) => zxtape::parse_container(data, layout),
        Kind::Bitstream(layout) => bitstream::parse_container(data, layout),
        Kind::Mcu(layout) => mcu::parse_container(data, layout),
        Kind::SocBoot2(layout) => socboot2::parse_container(data, layout),
        Kind::Retro(layout) => super::retro::parse_container(data, layout),
        Kind::Apple(layout) => super::apple::parse_container(data, layout),
        Kind::Android(layout) => super::android::parse_container(data, layout),
        Kind::SocBoot(layout) => socboot::parse_container(data, layout),
        Kind::Nintendo(layout) => nintendo::parse_container(data, layout),
        Kind::Archive(layout) => archives::parse_container(data, layout),
        Kind::Rofs(layout) => rofs::parse_container(data, layout),
        Kind::Mtd(layout) => mtd::parse_container(data, layout),
        Kind::Ext(layout) => ext::parse_container(data, layout),
        Kind::Uefi(layout) => uefi::parse_container(data, layout),
        Kind::Coreboot(layout) => coreboot::parse_container(data, layout),
        Kind::Router(layout) => router::parse_container(data, layout),
        Kind::Esp(layout) => super::esp::parse_container(data, layout),
        Kind::Qnx(layout) => super::qnx::parse_container(data, layout),
        Kind::WinCe(layout) => wince::parse_container(data, layout),
        Kind::PcFw(layout) => pcfw::parse_container(data, layout),
        Kind::BootMisc(layout) => super::bootmisc::parse_container(data, layout),
        Kind::Retro2(layout) => super::retro2::parse_container(data, layout),
        Kind::Erofs(layout) => erofs::parse_container(data, layout),
        Kind::Partitions(layout) => super::partitions::parse_container(data, layout),
        Kind::Fat(layout) => super::fat::parse_container(data, layout),
        Kind::Iso9660(layout) => super::iso9660::parse_container(data, layout),
        Kind::Discs(layout) => super::discs::parse_container(data, layout),
        Kind::JavaImage(layout) => super::javaimage::parse_container(data, layout),
        Kind::Minidump(layout) => super::minidump::parse_container(data, layout),
        Kind::Nlm(layout) => super::nlm::parse_container(data, layout),
        Kind::Geos(layout) => super::geos::parse_container(data, layout),
        Kind::Psyq(layout) => super::psyq::parse_container(data, layout),
        Kind::Aif(layout) => super::aif::parse_container(data, layout),
        Kind::Sis(layout) => super::sis::parse_container(data, layout),
        Kind::Capsule(layout) => super::capsule::parse_container(data, layout),
        Kind::VirtualDisk(layout) => super::vdisk::parse_container(data, layout),
        Kind::DiscImage(layout) => super::discimg::parse_container(data, layout),
        Kind::Cbm(layout) => super::cbm::parse_container(data, layout),
        Kind::Adf(layout) => super::adf::parse_container(data, layout),
        Kind::Atari8(layout) => super::atari8::parse_container(data, layout),
        Kind::Apple2(layout) => super::apple2::parse_container(data, layout),
        Kind::CpcDsk(layout) => super::cpcdsk::parse_container(data, layout),
        Kind::Nintendo2(layout) => super::nintendo2::parse_container(data, layout),
        Kind::Dmg(layout) => super::dmg::parse_container(data, layout),
        Kind::HfsPlus(layout) => super::hfsplus::parse_container(data, layout),
        Kind::Stfs(layout) => super::stfs::parse_container(data, layout),
        Kind::FwPack(layout) => super::fwpack::parse_container(data, layout),
        Kind::Apfs(layout) => super::apfs::parse_container(data, layout),
        Kind::Cab(layout) => super::cab::parse_container(data, layout),
        Kind::Ffu(layout) => super::ffu::parse_container(data, layout),
        Kind::Rpm(layout) => super::rpm::parse_container(data, layout),
        Kind::AppBundle(layout) => super::appbundle::parse_container(data, layout),
    }
}

/// An architecture named by a format field. The code byte order is `None`
/// when the field does not determine it; the classifier then takes it from
/// the code, or reports it as undetermined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// Architecture named by the format.
    pub isa: Isa,
    /// Register width in bits.
    pub bits: u8,
    /// Code byte order, when the format determines it.
    pub endianness: Option<Endianness>,
}

impl Target {
    /// A target whose byte order the format determines.
    pub const fn new(isa: Isa, bits: u8, endianness: Endianness) -> Self {
        Self {
            isa,
            bits,
            endianness: Some(endianness),
        }
    }

    /// A target whose byte order the format leaves open.
    pub const fn without_byte_order(isa: Isa, bits: u8) -> Self {
        Self {
            isa,
            bits,
            endianness: None,
        }
    }
}

/// Bytes that the container loads into target memory.
#[derive(Debug)]
pub struct Section<'a> {
    /// Display label.
    pub label: String,
    /// Destination address; units are stated in the container notes.
    pub address: u64,
    /// File offset of the stored bytes.
    pub offset: usize,
    /// Stored size in the file, in bytes.
    pub stored_size: usize,
    /// Bytes as loaded (decoded when `transform` is set).
    pub data: Cow<'a, [u8]>,
    /// Codec or transform that produced `data` from the stored bytes.
    pub transform: Option<&'static str>,
}

/// Whether a child is classified when its bytes are not a recognized format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classify {
    /// Firmware components: always classified, by the code model if needed.
    Always,
    /// Archive and filesystem members: listed only when they are a
    /// recognized format, as `ar` members are.
    IfRecognized,
    /// Raw code that goes straight to the code model and is never parsed
    /// as a nested container (an option ROM image starts with the ROM's own
    /// header).
    Code,
}

/// An embedded image that is classified on its own.
#[derive(Debug)]
pub struct Child<'a> {
    /// Display label (component role or member path).
    pub label: String,
    /// File offset of the stored bytes.
    pub offset: usize,
    /// Stored size in the file, in bytes.
    pub stored_size: usize,
    /// Bytes to classify (decoded when `transform` is set).
    pub data: Cow<'a, [u8]>,
    /// Codec or transform that produced `data` from the stored bytes.
    pub transform: Option<&'static str>,
    /// Data-only, encrypted or otherwise transformed bytes that must never
    /// reach the code model.
    pub opaque: bool,
    /// Architecture named for this child by the container.
    pub target: Option<Target>,
    /// CPU variant the platform fixes for `target` (`ARMv4T (ARM7TDMI)`),
    /// reported as the child's variant while its ISA is the target's.
    pub variant: Option<&'static str>,
    /// Classification policy.
    pub classify: Classify,
}

impl<'a> Child<'a> {
    /// A component stored as-is at `offset`.
    pub fn stored(label: impl Into<String>, offset: usize, data: &'a [u8]) -> Self {
        Self {
            label: label.into(),
            offset,
            stored_size: data.len(),
            data: Cow::Borrowed(data),
            transform: None,
            opaque: false,
            target: None,
            variant: None,
            classify: Classify::Always,
        }
    }

    /// A component whose stored bytes at `offset..offset + stored_size`
    /// decode to `data` through `transform`.
    pub fn decoded(
        label: impl Into<String>,
        offset: usize,
        stored_size: usize,
        data: Cow<'a, [u8]>,
        transform: &'static str,
    ) -> Self {
        Self {
            label: label.into(),
            offset,
            stored_size,
            data,
            transform: Some(transform),
            opaque: false,
            target: None,
            variant: None,
            classify: Classify::Always,
        }
    }

    /// A component that is listed but never analyzed as code.
    pub fn opaque(label: impl Into<String>, offset: usize, data: &'a [u8]) -> Self {
        Self {
            opaque: true,
            ..Self::stored(label, offset, data)
        }
    }

    /// Set the architecture the container names for this child.
    #[must_use]
    pub fn with_target(mut self, target: Target) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the CPU variant the platform fixes for this child's target.
    #[must_use]
    pub fn with_variant(mut self, variant: &'static str) -> Self {
        self.variant = Some(variant);
        self
    }

    /// Classify only when the bytes are a recognized format.
    #[must_use]
    pub fn if_recognized(mut self) -> Self {
        self.classify = Classify::IfRecognized;
        self
    }

    /// Classify as raw code, never as a nested container.
    #[must_use]
    pub fn as_code(mut self) -> Self {
        self.classify = Classify::Code;
        self
    }
}

/// A parsed container.
#[derive(Debug)]
pub struct Container<'a> {
    /// Reported file format.
    pub format: FileFormat,
    /// Layout name, reported as the classification variant.
    pub variant: String,
    /// Architecture named by the container itself.
    pub target: Option<Target>,
    /// Entry point, in the units stated in the notes (bytes unless stated).
    pub entry: Option<u64>,
    /// Load sections in stream order.
    pub sections: Vec<Section<'a>>,
    /// Embedded images in stream order.
    pub children: Vec<Child<'a>>,
    /// Format notes, most important first.
    pub notes: Vec<String>,
    /// Format-specific metadata, in addition to the generated entries.
    pub metadata: Vec<MetadataEntry>,
    /// Bytes of the input that belong to the container.
    pub consumed: usize,
    /// Encrypted or metadata-only content that must not be analyzed.
    pub opaque: bool,
    /// A codec wrapper: the single child is the content and its
    /// classification is reported as the container's own.
    pub transparent: bool,
    /// Load sections hold code for the code model and are never a nested
    /// container (kernel images whose section is the file itself).
    pub code_sections: bool,
    /// Prefix of generated metadata keys (`<prefix>_section_0`).
    pub key_prefix: &'static str,
}

impl<'a> Container<'a> {
    /// An empty container of `format`.
    pub fn new(format: FileFormat, variant: impl Into<String>, key_prefix: &'static str) -> Self {
        Self {
            format,
            variant: variant.into(),
            target: None,
            entry: None,
            sections: Vec::new(),
            children: Vec::new(),
            notes: Vec::new(),
            metadata: Vec::new(),
            consumed: 0,
            opaque: false,
            transparent: false,
            code_sections: false,
            key_prefix,
        }
    }

    /// Append a load section of stored bytes.
    pub fn push_section(&mut self, address: u64, offset: usize, data: Cow<'a, [u8]>) {
        let stored_size = data.len();
        self.sections.push(Section {
            label: format!("Load section {}", self.sections.len() + 1),
            address,
            offset,
            stored_size,
            data,
            transform: None,
        });
    }

    /// Append a custom metadata entry `<key>` with a display label.
    pub fn push_metadata(
        &mut self,
        key: impl Into<String>,
        label: impl Into<String>,
        value: impl Into<MetadataValue>,
    ) {
        self.metadata.push(MetadataEntry::new(
            MetadataKey::Custom(key.into()),
            value.into(),
            label,
        ));
    }

    /// The container-level result. The ISA is unknown, with confidence 0,
    /// unless the format names one.
    pub fn classification(&self) -> ClassificationResult {
        let (isa, bits, endianness) = match self.target {
            Some(t) => (t.isa, t.bits, t.endianness.unwrap_or(Endianness::BiEndian)),
            None => (Isa::Unknown(0), 0, Endianness::Little),
        };
        let mut r = ClassificationResult::from_format(isa, bits, endianness, self.format);
        if matches!(isa, Isa::Unknown(_)) {
            r.confidence = 0.0;
        }
        r.variant = Variant::new(self.variant.clone());
        r.metadata.entry_point = self.entry;
        if self.sections.is_empty() && !self.children.is_empty() {
            r.metadata.section_count = Some(self.children.len());
        } else if !self.sections.is_empty() {
            r.metadata.section_count = Some(self.sections.len());
            r.metadata.code_size = Some(self.sections.iter().map(|s| s.data.len() as u64).sum());
        }
        r.metadata.notes.clone_from(&self.notes);
        if self.opaque {
            r.metadata
                .notes
                .push("Payload is encrypted or metadata-only; ISA analysis was not applied".into());
        }
        r
    }

    /// Container size, the format's own entries, then one entry per
    /// section and child.
    pub fn metadata(&self) -> Vec<MetadataEntry> {
        let prefix = self.key_prefix;
        let custom = |key: String, label: String, value: MetadataValue| {
            MetadataEntry::new(MetadataKey::Custom(key), value, label)
        };
        let mut entries = vec![custom(
            format!("{prefix}_image_size"),
            "Container size (B)".into(),
            MetadataValue::Integer(self.consumed as u64),
        )];
        entries.extend(self.metadata.iter().cloned());
        for (i, s) in self.sections.iter().enumerate() {
            entries.push(custom(
                format!("{prefix}_section_{i}"),
                s.label.clone(),
                MetadataValue::String(format!(
                    "file 0x{:X}; destination 0x{:X}; {}",
                    s.offset,
                    s.address,
                    stored_and_decoded(s.stored_size, s.data.len(), s.transform)
                )),
            ));
        }
        for (i, child) in self.children.iter().enumerate() {
            let opaque = if child.opaque || self.opaque {
                "; opaque"
            } else {
                ""
            };
            entries.push(custom(
                format!("{prefix}_component_{i}"),
                child.label.clone(),
                MetadataValue::String(format!(
                    "file 0x{:X}; {}{opaque}",
                    child.offset,
                    stored_and_decoded(child.stored_size, child.data.len(), child.transform)
                )),
            ));
        }
        entries
    }

    /// Sections concatenated in stream order, without materializing address
    /// gaps. Opaque containers yield nothing.
    ///
    /// # Errors
    ///
    /// [`ClassifierError::PayloadLimit`] when the sections exceed
    /// [`MAX_PAYLOAD`].
    pub fn payload(&self) -> Result<Vec<u8>> {
        if self.opaque {
            return Ok(Vec::new());
        }
        let size = self.sections.iter().try_fold(0usize, |size, s| {
            size.checked_add(s.data.len())
                .filter(|size| *size <= MAX_PAYLOAD)
                .ok_or(ClassifierError::PayloadLimit { limit: MAX_PAYLOAD })
        })?;
        let mut payload = Vec::with_capacity(size);
        for s in &self.sections {
            payload.extend_from_slice(&s.data);
        }
        Ok(payload)
    }
}

/// `"{stored} B"`, or `"{stored} B stored; {decoded} B decoded ({codec})"`.
fn stored_and_decoded(stored: usize, decoded: usize, transform: Option<&str>) -> String {
    match transform {
        Some(name) => format!("{stored} B stored; {decoded} B decoded ({name})"),
        None => format!("{stored} B"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_prefixes_are_magic_bearing_formats() {
        assert!(is_recognized(b"\x7fELF\x02\x01\x01\0"));
        assert!(!is_recognized(&[0x5a; 64]));
    }

    #[test]
    fn metadata_reports_stored_and_decoded_sizes() {
        let mut c = Container::new(FileFormat::Gzip, "test", "test");
        c.children.push(Child::decoded(
            "Payload",
            4,
            10,
            Cow::Owned(vec![0; 20]),
            "gzip",
        ));
        let entries = c.metadata();
        let component = entries
            .iter()
            .find(|e| e.label == "Payload")
            .expect("component entry");
        assert_eq!(
            component.value.to_string(),
            "file 0x4; 10 B stored; 20 B decoded (gzip)"
        );
    }
}
