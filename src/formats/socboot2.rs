//! System-on-chip boot ROM images: Allwinner `eGON.BT0` boot0/SPL and TOC0
//! images, Rockchip RKFW update images, RKAF firmware packages, RKBOOT
//! loaders and idbloaders, `MediaTek` preloaders (device header, BRLYT and
//! GFH records) and legacy Qualcomm MBN headers (40-byte version 3 and
//! 80-byte SBL).
//!
//! Primary sources, at pinned revisions
//! (`https://github.com/<repo>/blob/<revision>/<path>`):
//! - `u-boot/u-boot` `5e3b01c8466dbe45cd6a06299f8f4c7e8c1c2363`:
//!   `include/sunxi_image.h` (`struct boot_file_head`, `struct
//!   toc0_main_info`, `struct toc0_item_info`), `tools/sunxi_egon.c` (jump
//!   instruction and checksum), `tools/sunxi_toc0.c` (`toc0_verify`),
//!   `tools/rkcommon.c` (idbloader headers v1 and v2, RC4 key) and
//!   `tools/mtk_image.[ch]` (`MediaTek` device header, BRLYT and GFH records).
//! - `linux-sunxi/sunxi-tools` `bc96c0ae5d97b15e482404665b4218fcbcf11db7`:
//!   `fel.c` (eGON checksum verification), `bootinfo.c`.
//! - `neo-technologies/rockchip-mkbootimg`
//!   `2348690523faee6ce3cea9eb9ff47e8b8d5e1df6`: `rkrom.h` (RKFW),
//!   `rkafp.h` (RKAF), `rkcrc.h`, `afptool.c` and `img_maker.c`;
//!   `linux-rockchip/rkflashtool` `fc2181c577ef3fb1e821818dfd07e0dac0575b74`:
//!   `rkunpack.c`, `rkcrc.c`.
//! - `rockchip-linux/u-boot` `1c535d65b8509f388d09e49fb6961f49fda35a1d`:
//!   `tools/rockchip/boot_merger.[ch]` (RKBOOT header and entries,
//!   `writeFile`, `unpackEntry`, `P_RC4`).
//! - `mtk09422/chromiumos-third_party-mediatek-datool`
//!   `c0779f00ba25d2e568d5cefea868c6385864ad04`: `fbtool.c` (the vendor's
//!   own header structures and preloader payload extraction);
//!   `bkerler/mtkclient` `7cb40e727727dfe3faa065eefb29b16ed29bbdf1`.
//! - `coreboot/coreboot` `99a3e1e820598b1eae76eb5b24664dfe5b7b1966`:
//!   `util/qualcomm/mbn_tools.py`, `mbncat.py` and `ipqheader.py`.
//!
//! Every header here is little-endian. Only three fields name an
//! instruction set: the eGON jump instruction (the boot ROM's entry
//! instruction), the `MediaTek` `GFH_BROM_CFG` `AArch64` hand-off and the
//! Qualcomm SBL `booting_image_config`. Rockchip chip codes and chip tags
//! name a chip family and Qualcomm image IDs name a boot role; neither is
//! used as ISA evidence, so the code model classifies the extracted code.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Section, Target};
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;

mod egon;
mod mediatek;
mod qualcomm;
mod rockchip;

pub(crate) use egon::{decode_jump, sign_extend, Jump, JumpKind};

/// Storage sector size: the unit of Rockchip sizes and of the search for an
/// image after the one parsed.
const SECTOR: usize = 512;

/// A layout of this family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Allwinner `eGON.BT0` boot0 or U-Boot SPL image.
    Egon,
    /// Allwinner TOC0 secure boot image (`TOC0.GLH`).
    Toc0,
    /// Rockchip RKFW update image (`update.img`).
    Rkfw,
    /// Rockchip RKAF firmware package.
    Rkaf,
    /// Rockchip RKBOOT loader (`BOOT` tag).
    RkBoot,
    /// Rockchip idbloader with the RC4-scrambled version 1 header.
    IdbloaderV1,
    /// Rockchip idbloader with the version 2 `RKNS` header.
    IdbloaderV2,
    /// `MediaTek` preloader with an `EMMC_BOOT` device header.
    MediatekEmmc,
    /// `MediaTek` preloader with an `SF_BOOT` (serial NOR) device header.
    MediatekSf,
    /// `MediaTek` preloader with an `SDMMC_BOOT` device header.
    MediatekSdmmc,
    /// `MediaTek` preloader with a `UFS_BOOT` device header.
    MediatekUfs,
    /// `MediaTek` preloader that starts with its `GFH_FILE_INFO` record.
    MediatekGfh,
    /// Qualcomm MBN with the 80-byte SBL header.
    QualcommSbl,
    /// Qualcomm MBN with the 40-byte version 3 header (no magic).
    QualcommMbn,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Egon | Self::Toc0 => FileFormat::AllwinnerEgon,
            Self::Rkfw | Self::Rkaf | Self::RkBoot | Self::IdbloaderV1 | Self::IdbloaderV2 => {
                FileFormat::RockchipImage
            }
            Self::MediatekEmmc
            | Self::MediatekSf
            | Self::MediatekSdmmc
            | Self::MediatekUfs
            | Self::MediatekGfh => FileFormat::MediatekPreloader,
            Self::QualcommSbl | Self::QualcommMbn => FileFormat::QualcommMbn,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Egon => "eGON.BT0 boot image",
            Self::Toc0 => "TOC0 secure boot image",
            Self::Rkfw => "RKFW update image",
            Self::Rkaf => "RKAF firmware package",
            Self::RkBoot => "RKBOOT loader",
            Self::IdbloaderV1 => "idbloader (header v1)",
            Self::IdbloaderV2 => "idbloader (header v2)",
            Self::MediatekEmmc => "EMMC_BOOT preloader",
            Self::MediatekSf => "SF_BOOT preloader",
            Self::MediatekSdmmc => "SDMMC_BOOT preloader",
            Self::MediatekUfs => "UFS_BOOT preloader",
            Self::MediatekGfh => "GFH preloader",
            Self::QualcommSbl => "SBL MBN (80-byte header)",
            Self::QualcommMbn => "MBN (40-byte header)",
        }
    }

    /// Recognized from complete structure rather than a magic value.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::QualcommMbn)
    }
}

/// Detect a magic-bearing layout of this family. A valid magic is enough,
/// so a corrupt image becomes a parse error rather than raw data.
pub fn detect(data: &[u8]) -> Option<Layout> {
    egon::detect(data)
        .or_else(|| rockchip::detect(data))
        .or_else(|| mediatek::detect(data))
        .or_else(|| qualcomm::detect(data))
}

/// Detect a layout without a magic value from its complete structure. Only
/// the 40-byte Qualcomm MBN header is recognized this way.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    qualcomm::detect_weak(data)
}

/// Parse `data` as `layout` into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::SocBoot2ParseError`] for a missing magic, a checksum
/// or CRC mismatch, a truncated header, table or payload, or an
/// inconsistent field.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Egon => egon::parse_egon(data),
        Layout::Toc0 => egon::parse_toc0(data),
        Layout::Rkfw => rockchip::parse_rkfw(data),
        Layout::Rkaf => rockchip::parse_rkaf(data),
        Layout::RkBoot => rockchip::parse_rkboot(data),
        Layout::IdbloaderV1 => rockchip::parse_idbloader_v1(data),
        Layout::IdbloaderV2 => rockchip::parse_idbloader_v2(data),
        Layout::MediatekEmmc | Layout::MediatekSf | Layout::MediatekSdmmc | Layout::MediatekUfs => {
            mediatek::parse_device(data, layout)
        }
        Layout::MediatekGfh => mediatek::parse_gfh_image(data),
        Layout::QualcommSbl => qualcomm::parse_sbl(data),
        Layout::QualcommMbn => qualcomm::parse_mbn(data),
    }
}

/// What one of the three ISA-naming header fields (the eGON jump
/// instruction, `GFH_BROM_CFG`, `booting_image_config`) establishes.
struct IsaEvidence {
    /// The target the field names; `None` when it names none, so the code
    /// model classifies the extracted code.
    target: Option<Target>,
    /// The note that states the field's value and what it establishes.
    note: String,
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::SocBoot2ParseError {
        message: message.into(),
    }
}

/// The `len` bytes of `what` at `offset`.
fn range<'a>(data: &'a [u8], offset: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range 0x{offset:X} + {len} B")))?;
    data.get(offset..end).ok_or_else(|| {
        error(format!(
            "Truncated {what} at 0x{offset:X}: {len} B declared, {} B present",
            data.len().saturating_sub(offset)
        ))
    })
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = range(data, at, 2, "field")?
        .try_into()
        .expect("range has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = range(data, at, 4, "field")?
        .try_into()
        .expect("range has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

/// A little-endian 32-bit size or offset field as a byte count.
fn le_size(data: &[u8], at: usize) -> Result<usize> {
    usize::try_from(le_u32(data, at)?).map_err(|_| error(format!("Invalid size at 0x{at:X}")))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A fixed-size, NUL-padded text field, up to its first NUL.
fn text_field(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).trim().to_string()
}

/// `size` as `"{n} B"`, or in KiB or MiB when it is a whole multiple.
fn size_text(size: usize) -> String {
    const KIB: usize = 1 << 10;
    const MIB: usize = 1 << 20;
    if size >= MIB && size % MIB == 0 {
        format!("{} MiB", size / MIB)
    } else if size >= KIB && size % KIB == 0 {
        format!("{} KiB", size / KIB)
    } else {
        format!("{size} B")
    }
}

/// Data after an image that is not erased flash, as a member listed only
/// when it is a recognized format. Padding up to the sector that holds the
/// first non-padding byte is skipped, so a second image on a sector
/// boundary (U-Boot proper after an SPL) starts the member. Records a note
/// when such data exists.
fn trailing_member<'a>(data: &'a [u8], end: usize, notes: &mut Vec<String>) -> Option<Child<'a>> {
    let rest = data.get(end..)?;
    let first = rest.iter().position(|b| !matches!(b, 0x00 | 0xff))?;
    let content = end + first;
    let start = (content - content % SECTOR).max(end);
    notes.push(format!(
        "{} after the image at 0x{end:X}; listed only if it is a recognized format",
        size_text(rest.len())
    ));
    Some(Child::stored("Trailing data", start, &data[start..]).if_recognized())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_member_starts_at_the_sector_of_the_first_data_byte() {
        let mut data = vec![0u8; 3 * SECTOR];
        data[2 * SECTOR + 7] = 0x5a;
        let mut notes = Vec::new();
        let member = trailing_member(&data, 100, &mut notes).expect("data after the image");
        assert_eq!(member.offset, 2 * SECTOR);
        assert_eq!(member.data.len(), SECTOR);
        assert_eq!(notes.len(), 1);
        assert!(trailing_member(&[0xff; 64], 0, &mut notes).is_none());
    }

    #[test]
    fn sizes_use_binary_units_only_when_exact() {
        assert_eq!(size_text(8192), "8 KiB");
        assert_eq!(size_text(1 << 20), "1 MiB");
        assert_eq!(size_text(1000), "1000 B");
    }
}
