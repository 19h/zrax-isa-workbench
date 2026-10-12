//! `SoC` boot images: Xilinx Zynq-7000 and `Zynq UltraScale+ MPSoC` (`ZynqMP`)
//! `BOOT.BIN`, NXP i.MX HAB images (IVT, boot data, DCD, CSF) and i.MX 8/9
//! AHAB containers, and NXP Secure Binary SB2.0/SB2.1 and SB3.1 files.
//!
//! Primary sources, by layout (pinned revisions):
//! - `BOOT.BIN`: Xilinx Bootgen `d93c3fa6e6ef8aa1d4fb4532c58ed4a5efa8804e`
//!   (`common/include/bootheader.h`, `zynq/include/bootheader-zynq.h`,
//!   `zynqmp/include/bootheader-zynqmp.h`, `zynqmp/src/bootheader-zynqmp.cpp`,
//!   the partition header table sources in `zynq/` and `zynqmp/`), AMD
//!   UG1283 (Bootgen User Guide, the "Zynq-7000 `SoC`" and "Zynq `UltraScale+`
//!   `MPSoC`" boot header, image header table, partition header and attribute
//!   tables) and U-Boot `5e3b01c8466dbe45cd6a06299f8f4c7e8c1c2363`
//!   `tools/zynqimage.c`, `tools/zynqmpimage.[ch]`. See [`zynq`].
//! - i.MX: U-Boot `5e3b01c8` `include/imximage.h`, `tools/imximage.c`,
//!   `arch/arm/include/asm/mach-imx/hab.h`, `arch/arm/mach-imx/hab.c`,
//!   `include/imx8image.h`, and NXP SPSDK
//!   `fb0f666d2c4c0260face05d5ccc8238154465eea`
//!   `spsdk/image/hab/segments/seg_ivt.py`, `spsdk/image/ahab/ahab_container.py`,
//!   `ahab_iae.py`. See [`imx`].
//! - SB2/SB3: SPSDK `fb0f666d` `spsdk/sbfile/sb2/headers.py`, `sb2/images.py`,
//!   `sbfile/sb31/images.py`, `image/cert_block/cert_block_v1.py`,
//!   `rkht.py`, `cert_block_v21.py`. See [`nxp_sb`].
//!
//! All three header families are little-endian, except the HAB header word
//! (tag, big-endian length, version) of i.MX structures. Only `ZynqMP` boot
//! header and partition attributes name a CPU; Zynq-7000 partitions name a
//! destination device, and the i.MX and Secure Binary layouts name none, so
//! their classification comes from the code model on the extracted image.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target};
use crate::types::{Endianness, FileFormat, Isa};

mod imx;
mod nxp_sb;
mod zynq;

/// A recognized `SoC` boot image layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Xilinx `BOOT.BIN`: width detection word at 0x20 and `XNLX` at 0x24.
    /// Whether it is a Zynq-7000 or a `ZynqMP` image is decided by parsing.
    XilinxBootBin,
    /// i.MX HAB image: an image vector table at file offset 0, 0x400 or
    /// 0x1000 whose pointers and boot data are consistent.
    ImxIvt,
    /// i.MX 8/9 AHAB container header (tag `0x87`) at file offset 0.
    ImxAhab,
    /// NXP SB2.0 or SB2.1 secure binary (`STMP`, `sgtl`, major version 2).
    Sb2,
    /// NXP SB3.1 secure binary (`sbv3`, major version 3).
    Sb31,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::XilinxBootBin => FileFormat::XilinxBootBin,
            Self::ImxIvt | Self::ImxAhab => FileFormat::ImxImage,
            Self::Sb2 | Self::Sb31 => FileFormat::NxpSb,
        }
    }

    /// Human-readable layout name, used as the detection variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::XilinxBootBin => "Zynq-7000/ZynqMP boot image",
            Self::ImxIvt => "i.MX HAB image",
            Self::ImxAhab => "i.MX AHAB container",
            Self::Sb2 => "SB2 secure binary",
            Self::Sb31 => "SB3.1 secure binary",
        }
    }

    /// Recognized from complete structure rather than a magic value.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::ImxAhab)
    }
}

/// Strong recognition: the `BOOT.BIN` and Secure Binary magics, and an i.MX
/// IVT at a documented offset. The IVT key is only four bytes, so an IVT is
/// recognized only when its self pointer, boot data and entry point agree.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if zynq::has_signature(data) {
        return Some(Layout::XilinxBootBin);
    }
    if nxp_sb::has_sb31_magic(data) {
        return Some(Layout::Sb31);
    }
    if nxp_sb::has_sb2_magic(data) {
        return Some(Layout::Sb2);
    }
    if imx::has_ivt(data) {
        return Some(Layout::ImxIvt);
    }
    None
}

/// Weak recognition: an i.MX AHAB container, whose header key is a version
/// byte and a tag byte, recognized only when the header, image array and
/// signature block header validate.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    imx::is_ahab(data).then_some(Layout::ImxAhab)
}

/// Parse `data` as `layout` into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::SocBootParseError`] for a truncated or inconsistent
/// header, table or image range, or a failed checksum or hash.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::XilinxBootBin => zynq::parse(data),
        Layout::ImxIvt => imx::parse_ivt_image(data),
        Layout::ImxAhab => imx::parse_ahab(data),
        Layout::Sb2 => nxp_sb::parse_sb2(data),
        Layout::Sb31 => nxp_sb::parse_sb31(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::SocBootParseError {
        message: message.into(),
    }
}

/// The message of an error built by [`error`], for combining the failures
/// of two interpretations into one error.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::SocBootParseError { message } => message,
        other => other.to_string(),
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

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn byte(data: &[u8], at: usize) -> Result<u8> {
    array::<1>(data, at).map(|[value]| value)
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    array(data, at).map(u16::from_le_bytes)
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    array(data, at).map(u16::from_be_bytes)
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    array(data, at).map(u32::from_le_bytes)
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    array(data, at).map(u64::from_le_bytes)
}

/// A file position or size from a 64-bit value; fails where `usize` is
/// narrower (WebAssembly).
fn to_usize(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Invalid {what} 0x{value:X}")))
}

/// `start + len` as a file position.
fn end_of(start: usize, len: usize) -> Result<usize> {
    start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Child for stored bytes `offset..offset + len` of `data`.
fn stored_child(
    data: &[u8],
    label: impl Into<String>,
    offset: usize,
    len: usize,
) -> Result<Child<'_>> {
    Ok(Child::stored(label, offset, slice(data, offset, len)?))
}

/// Opaque child for stored bytes `offset..offset + len` of `data`.
fn opaque_child(
    data: &[u8],
    label: impl Into<String>,
    offset: usize,
    len: usize,
) -> Result<Child<'_>> {
    Ok(Child::opaque(label, offset, slice(data, offset, len)?))
}

/// Bytes after `c.consumed`: erased flash or zero fill is ignored; anything
/// else is noted, and listed when it starts a recognized format.
fn push_trailing<'a>(data: &'a [u8], c: &mut Container<'a>) {
    let rest = data.get(c.consumed..).unwrap_or_default();
    if is_padding(rest) {
        return;
    }
    c.notes.push(format!(
        "{} B after the image at 0x{:X} are not described by its headers",
        rest.len(),
        c.consumed
    ));
    c.children
        .push(Child::stored("Trailing data", c.consumed, rest).if_recognized());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_report_truncation_offsets() {
        let data = [1u8, 2, 3];
        assert_eq!(le_u16(&data, 1).unwrap(), 0x0302);
        assert_eq!(be_u16(&data, 1).unwrap(), 0x0203);
        assert_eq!(byte(&data, 2).unwrap(), 3);
        let e = le_u32(&data, 1).unwrap_err();
        assert_eq!(message(e), "Truncated file range 0x1 + 4 B");
        assert!(slice(&data, usize::MAX, 2).is_err());
    }

    #[test]
    fn wide_values_do_not_wrap_into_file_positions() {
        assert!(end_of(usize::MAX, 1).is_err());
        assert_eq!(to_usize(0x40, "offset").unwrap(), 0x40);
    }

    #[test]
    fn layouts_report_their_formats() {
        assert_eq!(Layout::XilinxBootBin.format(), FileFormat::XilinxBootBin);
        assert_eq!(Layout::ImxAhab.format(), FileFormat::ImxImage);
        assert_eq!(Layout::Sb31.format(), FileFormat::NxpSb);
        assert!(Layout::ImxAhab.is_weak());
        assert!(!Layout::ImxIvt.is_weak());
    }

    #[test]
    fn trailing_padding_is_ignored_and_other_bytes_are_noted() {
        let data = [0xffu8, 0xff, 0x00, 0x5a];
        let mut c = Container::new(FileFormat::XilinxBootBin, "test", "test");
        c.consumed = 2;
        push_trailing(&data, &mut c);
        assert_eq!(c.children.len(), 1);
        assert_eq!(
            c.notes,
            ["2 B after the image at 0x2 are not described by its headers"]
        );
        c.children.clear();
        c.notes.clear();
        c.consumed = 4;
        push_trailing(&data, &mut c);
        assert!(c.children.is_empty() && c.notes.is_empty());
    }
}
