//! Miscellaneous boot images: OP-TEE OS images with an `OPTE` header,
//! Amlogic USB burning images (`aml_upgrade_package.img`), Allwinner
//! PhoenixSuit/LiveSuit `IMAGEWTY` images and barebox ARM images.
//!
//! Sources, at pinned revisions:
//! - OP-TEE: `OP-TEE/optee_os` tag `4.3.0` `scripts/gen_tee_bin.py`;
//!   `ARM-software/arm-trusted-firmware` tag `v2.11.0`
//!   `include/lib/optee_utils.h` and `lib/optee/optee_utils.c`
//!   (`parse_optee_header`); `u-boot/u-boot`
//!   `5e3b01c8466dbe45cd6a06299f8f4c7e8c1c2363` `include/tee/optee.h` and
//!   `lib/optee/optee.c`. See [`optee`].
//! - Amlogic: the vendor U-Boot at
//!   `third-party-mirror.googlesource.com/u-boot`
//!   `422c66357c3eb319ef307e4f80dd3bb8f85741cc`
//!   (`drivers/usb/gadget/v2_burning/v2_common/amlImage_if.h`,
//!   `optimus_img_decoder.c`, `v2_sdc_burn/optimus_sdc_burn.c`); Amlogic's
//!   packer source in `yyftxws/aml_image_packer`
//!   `6c954162a22b449ef4e5ffb7e038e593564541d8` (`src/amlImage.cpp`,
//!   `src/crc32.cpp`, `src/sha1.c`); `7Ji/ampack`
//!   `46066067b2b06c387df14243e301742644aa77a1` (`src/image.rs`). See
//!   [`amlogic`].
//! - Allwinner: Allwinner's `imagefile_new.h` and `imgdecode.c` as copied in
//!   `YuzukiTsuru/OpenixCard` `b5a6ffccb2492a3f238d628089d9acd1f44ec7a0`
//!   (`docs/img_decode/firmware/`); `Ithamar/awutils`
//!   `3f1cbb2c67752b392a88b252c51158d13d8809b5` (`imagewty.h`, `awimage.c`,
//!   `rc6.c`) for the version 1 layout and the RC6 keys. See [`imagewty`].
//! - barebox: `barebox/barebox` tag `v2024.10.0`
//!   `arch/arm/include/asm/barebox-arm-head.h`, `arch/arm/cpu/head_64.S`,
//!   `arch/arm/include/asm/barebox-arm64.h`, `arch/arm/lib/pbl.lds.S`. See
//!   [`barebox`].
//!
//! Every header here is little-endian. Two fields name an instruction set:
//! the OP-TEE `arch` byte and the instruction at the start of a barebox
//! head. Amlogic and Allwinner images name no ISA; their components are
//! classified on their own bytes.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{self, Child, Container, Target};
use crate::types::{Endianness, FileFormat, Isa};

mod amlogic;
mod barebox;
mod imagewty;
mod optee;
mod rc6;

/// A layout of this family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// OP-TEE header version 1 (`tee.bin`): the header, the init part and
    /// the paged part in one file.
    OpteeV1,
    /// OP-TEE header version 2 (`tee-header_v2.bin`): the image table only;
    /// the pager and pageable images are separate files.
    OpteeV2,
    /// Amlogic USB burning image, item table version 1 or 2.
    Amlogic,
    /// Allwinner `IMAGEWTY` image with a plaintext header.
    ImageWty,
    /// Allwinner `IMAGEWTY` image whose header and item table are
    /// RC6-encrypted with the published fixed keys.
    ImageWtyEncrypted,
    /// barebox image with the ARM or `AArch64` barebox head at offset 0.
    Barebox,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::OpteeV1 | Self::OpteeV2 => FileFormat::OpteeImage,
            Self::Amlogic => FileFormat::AmlogicUpgrade,
            Self::ImageWty | Self::ImageWtyEncrypted => FileFormat::AllwinnerImage,
            Self::Barebox => FileFormat::BareboxImage,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::OpteeV1 => "OP-TEE header v1 image (tee.bin)",
            Self::OpteeV2 => "OP-TEE header v2 (tee-header_v2.bin)",
            Self::Amlogic => "Amlogic USB burning image",
            Self::ImageWty => "IMAGEWTY image",
            Self::ImageWtyEncrypted => "IMAGEWTY image (RC6-encrypted header)",
            Self::Barebox => "barebox image",
        }
    }

    /// Every layout here carries a magic, so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::OpteeV1
            | Self::OpteeV2
            | Self::Amlogic
            | Self::ImageWty
            | Self::ImageWtyEncrypted
            | Self::Barebox => false,
        }
    }
}

/// Strong recognition from a magic: `OPTE` with header version 1 or 2, the
/// Amlogic image magic at offset 8, `IMAGEWTY` in plaintext or after
/// decrypting the first block, or the barebox magic at 0x20. The rest of
/// the file is not checked, so a damaged image becomes a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    optee::detect(data)
        .or_else(|| amlogic::detect(data))
        .or_else(|| imagewty::detect(data))
        .or_else(|| barebox::detect(data))
}

/// Parse `data` as `layout` into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::BootImageParseError`] for a missing magic, an
/// unsupported version, a CRC mismatch, or a header, table or component
/// that does not fit the file.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::OpteeV1 => optee::parse_v1(data),
        Layout::OpteeV2 => optee::parse_v2(data),
        Layout::Amlogic => amlogic::parse(data),
        Layout::ImageWty => imagewty::parse(data, false),
        Layout::ImageWtyEncrypted => imagewty::parse(data, true),
        Layout::Barebox => barebox::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::BootImageParseError {
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

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(range(data, at, N, "field")?
        .try_into()
        .expect("range has exactly N bytes"))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at)?))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, at)?))
}

/// A file offset or size read from the image, as `usize`.
fn to_usize(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Invalid {what} 0x{value:X}")))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Bytes after `end`, which may only be erased flash or zero fill.
fn expect_padding(data: &[u8], end: usize, what: &str) -> Result<()> {
    let trailing = data.get(end..).unwrap_or_default();
    if is_padding(trailing) {
        return Ok(());
    }
    Err(error(format!(
        "Unexpected {} after the {what} at 0x{end:X}",
        size_text(trailing.len())
    )))
}

/// Longest name read from a fixed-size text field (our bound).
const MAX_NAME: usize = 64;

/// A fixed-size, NUL-terminated text field: up to its first NUL, at most
/// [`MAX_NAME`] bytes, trimmed, with bytes outside printable ASCII shown as
/// `.`.
fn text_field(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let text: String = bytes[..len]
        .iter()
        .take(MAX_NAME)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    text.trim().to_string()
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

/// `count` followed by the singular or plural noun.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{count} {noun}")
}

/// Up to `limit` names, comma-separated, with a count of the rest.
fn name_list(names: &[String], limit: usize) -> String {
    let listed = names
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > limit {
        format!("{listed} and {} more", names.len() - limit)
    } else {
        listed
    }
}

/// Bytes of a component that recognition looks at (our bound). Partition
/// and file formats carry their magic in the first kilobytes; a weak
/// format that needs its whole input is not recognized from a prefix.
const RECOGNITION_PREFIX: usize = 64 << 10;

/// A component that is analyzed only when its first bytes start a format
/// the classifier recognizes; anything else is listed as opaque data,
/// because no field of these images says that it is code.
fn recognized_or_opaque(label: String, offset: usize, bytes: &[u8]) -> (Child<'_>, bool) {
    let prefix = &bytes[..bytes.len().min(RECOGNITION_PREFIX)];
    if container::is_recognized(prefix) {
        (Child::stored(label, offset, bytes), true)
    } else {
        (Child::opaque(label, offset, bytes), false)
    }
}

/// Data after an image that is not erased flash, as a member listed only
/// when it is a recognized format. Records a note when such data exists.
fn trailing_member<'a>(data: &'a [u8], end: usize, notes: &mut Vec<String>) -> Option<Child<'a>> {
    let rest = data.get(end..)?;
    if is_padding(rest) {
        return None;
    }
    notes.push(format!(
        "{} after the image at 0x{end:X}; listed only if it is a recognized format",
        size_text(rest.len())
    ));
    Some(Child::stored("Trailing data", end, rest).if_recognized())
}

/// A32 or `AArch64` with little-endian instructions, as a barebox head
/// instruction names it.
fn arm_target(aarch64: bool) -> Target {
    if aarch64 {
        Target::new(Isa::AArch64, 64, Endianness::Little)
    } else {
        Target::new(Isa::Arm, 32, Endianness::Little)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_fields_stop_at_nul_and_hide_control_bytes() {
        assert_eq!(text_field(b"PARTITION\0junk"), "PARTITION");
        assert_eq!(text_field(b"COMMON  "), "COMMON");
        assert_eq!(text_field(b"a\x01b"), "a.b");
        assert_eq!(text_field(&[b'x'; 300]).len(), MAX_NAME);
    }

    #[test]
    fn trailing_bytes_must_be_padding() {
        assert!(expect_padding(&[1, 2, 0, 0xff], 2, "image").is_ok());
        assert!(expect_padding(&[1, 2], 5, "image").is_ok());
        let message = expect_padding(&[1, 2, 3], 1, "image")
            .unwrap_err()
            .to_string();
        assert_eq!(
            message,
            "Boot image parse error: Unexpected 2 B after the image at 0x1"
        );
    }

    #[test]
    fn name_lists_are_bounded() {
        let names: Vec<String> = (0..5).map(|i| format!("n{i}")).collect();
        assert_eq!(name_list(&names, 2), "n0, n1 and 3 more");
        assert_eq!(name_list(&names[..2], 2), "n0, n1");
    }

    #[test]
    fn detect_needs_a_magic() {
        assert_eq!(detect(&[0; 128]), None);
        assert_eq!(detect(b"OPTE\x02\x01\0\0"), Some(Layout::OpteeV2));
        assert_eq!(detect(b"OPTERON processor"), None);
    }
}
