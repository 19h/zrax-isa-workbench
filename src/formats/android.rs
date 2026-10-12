//! Android images: boot and `vendor_boot` images, sparse images, A/B OTA
//! update payloads and Pixel/Nexus bootloader packs.
//!
//! Primary sources, by layout (pinned revisions; see `docs/android.md`):
//! - Boot images (`ANDROID!`, header versions 0 to 4) and `vendor_boot` images
//!   (`VNDRBOOT`, versions 3 and 4): AOSP `platform/system/tools/mkbootimg`
//!   at `d2bb0af5ba6d3198a3e99529c97eda1be0b5a093`, files
//!   `include/bootimg/bootimg.h`, `mkbootimg.py` and `unpack_bootimg.py`.
//!   The Qualcomm reading of `header_version` as `dt_size` is from `LineageOS`
//!   `android_system_tools_mkbootimg` `mkbootimg.py` at `90054adc`; the
//!   `MediaTek` payload header and the Samsung and LG partition-tail markers
//!   are from Magisk v30.7 `native/src/boot/bootimg.hpp` at `e8a58776`.
//! - AVB footer: AOSP `platform/external/avb` at `76117860`,
//!   `libavb/avb_footer.h`.
//! - Sparse images: AOSP `platform/system/core` at `a3b721a3`,
//!   `libsparse/sparse_format.h` and `libsparse/sparse_read.cpp`.
//! - OTA payloads (`CrAU`): AOSP `platform/system/update_engine` at
//!   `dc84c255`, `update_metadata.proto` and
//!   `payload_consumer/payload_metadata.cc`; major version 1 from tag
//!   `android-10.0.0_r1`; protobuf wire format from the protobuf.dev
//!   encoding guide.
//! - `BOOTLDR!` packs: AOSP `device/lge/hammerhead` `releasetools.py` at
//!   `e2e99344` (Qualcomm layout) and `device/asus/fugu` `releasetools.py`
//!   at `25a29d70` (ASUS layout). Qualcomm meta image: CAF
//!   `device/qcom/common/meta_image/meta_format.h` (`OnePlusOSS` mirror at
//!   `018b5519`) and AOSP `device/huawei/angler` `releasetools.py` at
//!   `cf92cd8e`.
//! - FBPK version 2: Google `fbpack.py` and `fbpacktool.py`, published on
//!   source.android.com with the Pixel `fw_unpack` tools (2021). FBPK
//!   version 1 has no Google source: `anestisb/qc_image_unpacker`
//!   `src/packed_image.h` at `28a783a9` and BANG `android_fbpk.ksy` at
//!   `96370e4f` agree on it.
//!
//! No header in this family names a CPU. Load addresses, board, product
//! and partition names are not ISA evidence, so the container target stays
//! empty and every kernel, ramdisk, partition and pack member is classified
//! from its own bytes. Device trees, DTBO tables, bootconfig text, AVB
//! metadata, signatures and partition tables are data and stay opaque.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::{FileFormat, MetadataValue};
use std::borrow::Cow;

mod boot;
mod bootloader;
mod ota;
mod sparse;

/// Boot image magic (`BOOT_MAGIC`).
const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";

/// `vendor_boot` image magic (`VENDOR_BOOT_MAGIC`).
const VENDOR_BOOT_MAGIC: &[u8; 8] = b"VNDRBOOT";

/// Sparse image magic `0xED26FF3A`, stored little-endian (`SPARSE_HEADER_MAGIC`).
const SPARSE_MAGIC: u32 = 0xed26_ff3a;

/// `update_engine` payload magic (`kDeltaMagic`).
const OTA_MAGIC: &[u8; 4] = b"CrAU";

/// `BOOTLDR!` pack magic, shared by the Qualcomm and ASUS layouts.
const BOOTLDR_MAGIC: &[u8; 8] = b"BOOTLDR!";

/// Qualcomm meta image magic `0xCE1AD63C`, stored little-endian
/// (`META_HEADER_MAGIC`).
const META_IMAGE_MAGIC: u32 = 0xce1a_d63c;

/// FBPK pack magic (`FBPACK_MAGIC` `0x4B504246`, stored little-endian).
const FBPK_MAGIC: &[u8; 4] = b"FBPK";

/// AVB footer (`AvbFooter`, big-endian): magic, major and minor version,
/// original image size, vbmeta offset and size, 28 reserved bytes. It
/// occupies the last 64 bytes of a partition image.
const AVB_FOOTER_MAGIC: &[u8; 4] = b"AVBf";
const AVB_FOOTER_SIZE: usize = 64;
const AVB_FOOTER_MAJOR: u32 = 1;

/// vbmeta image magic (`AVB_MAGIC`).
const AVB_VBMETA_MAGIC: &[u8; 4] = b"AVB0";

/// Samsung marker after the last boot image section (Magisk
/// `SEANDROID_MAGIC`).
const SEANDROID_MAGIC: &[u8; 16] = b"SEANDROIDENFORCE";

/// LG "bump" trailer after the last boot image section (Magisk
/// `LG_BUMP_MAGIC`).
const LG_BUMP_MAGIC: [u8; 16] = [
    0x41, 0xa9, 0xe4, 0x67, 0x74, 0x4d, 0x1d, 0x1b, 0xa4, 0x29, 0xf2, 0xec, 0xea, 0x65, 0x52, 0x79,
];

/// Flattened device tree magic, stored big-endian (an appended DTB after a
/// compressed kernel).
const FDT_MAGIC: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];

/// Prefix of generated and custom metadata keys.
const KEY_PREFIX: &str = "android";

/// An Android image layout, recognized by its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Boot image (`ANDROID!`), header versions 0 to 4.
    Boot,
    /// `vendor_boot` image (`VNDRBOOT`), header versions 3 and 4.
    VendorBoot,
    /// libsparse image.
    Sparse,
    /// `update_engine` payload (`CrAU`).
    Ota,
    /// `BOOTLDR!` pack: the Qualcomm layout or the ASUS fugu layout.
    Bootldr,
    /// Qualcomm meta image (`0xCE1AD63C`).
    MetaImage,
    /// FBPK pack, versions 1 and 2.
    Fbpk,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Boot => FileFormat::AndroidBoot,
            Self::VendorBoot => FileFormat::AndroidVendorBoot,
            Self::Sparse => FileFormat::AndroidSparse,
            Self::Ota => FileFormat::AndroidOta,
            Self::Bootldr | Self::MetaImage | Self::Fbpk => FileFormat::AndroidBootloader,
        }
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Boot => "Android boot image",
            Self::VendorBoot => "Android vendor_boot image",
            Self::Sparse => "Android sparse image",
            Self::Ota => "Android OTA payload",
            Self::Bootldr => "BOOTLDR! bootloader pack",
            Self::MetaImage => "Qualcomm meta image",
            Self::Fbpk => "FBPK bootloader pack",
        }
    }

    /// Every layout carries a magic value.
    pub fn is_weak(self) -> bool {
        false
    }
}

/// Strong recognition by magic. A file with one of these magics is an
/// Android image even when the rest is damaged, so damage is a parse error
/// rather than a raw-code guess.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let magic = data.get(..4)?;
    if data.starts_with(BOOT_MAGIC) {
        Some(Layout::Boot)
    } else if data.starts_with(VENDOR_BOOT_MAGIC) {
        Some(Layout::VendorBoot)
    } else if data.starts_with(BOOTLDR_MAGIC) {
        Some(Layout::Bootldr)
    } else if magic == SPARSE_MAGIC.to_le_bytes() {
        Some(Layout::Sparse)
    } else if magic == OTA_MAGIC {
        Some(Layout::Ota)
    } else if magic == META_IMAGE_MAGIC.to_le_bytes() {
        Some(Layout::MetaImage)
    } else if magic == FBPK_MAGIC {
        Some(Layout::Fbpk)
    } else {
        None
    }
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::AndroidParseError`] for a truncated or inconsistent
/// header, section, chunk, manifest or pack table.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Boot => boot::parse(data),
        Layout::VendorBoot => boot::parse_vendor(data),
        Layout::Sparse => sparse::parse(data),
        Layout::Ota => ota::parse(data),
        Layout::Bootldr => bootloader::parse_bootldr(data),
        Layout::MetaImage => bootloader::parse_meta_image(data),
        Layout::Fbpk => bootloader::parse_fbpk(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::AndroidParseError {
        message: message.into(),
    }
}

/// The `len` bytes of `what` at `start`.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

/// [`slice`] with an offset and size read from the input as 64-bit values.
fn slice64<'a>(data: &'a [u8], start: u64, len: u64, what: &str) -> Result<&'a [u8]> {
    match (usize::try_from(start), usize::try_from(len)) {
        (Ok(start), Ok(len)) => slice(data, start, len, what),
        _ => Err(error(format!("Truncated {what} at 0x{start:X} + {len} B"))),
    }
}

/// The `N` bytes of a fixed-size field at `at`.
fn field<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    let bytes = slice(data, at, N, "header field")?;
    Ok(bytes.try_into().expect("slice has exactly N bytes"))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(field(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(field(data, at)?))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(field(data, at)?))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(field(data, at)?))
}

fn be_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(field(data, at)?))
}

/// An ASCIIZ field: the bytes before the first NUL, decoded lossily.
fn asciiz(field: &[u8]) -> String {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..len]).into_owned()
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A size with the largest exact binary unit (`4 KiB`, `64 MiB`, `100 B`).
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

/// Decoded bytes left for one container's components, so that the
/// components of one file never extract more than [`MAX_EXTRACTED`] in
/// total.
struct Budget {
    remaining: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            remaining: MAX_EXTRACTED,
        }
    }

    /// The most bytes one component may still extract.
    fn limit(&self) -> usize {
        self.remaining.min(MAX_PAYLOAD)
    }

    /// Account for `size` extracted bytes.
    fn spend(&mut self, size: usize) {
        self.remaining = self.remaining.saturating_sub(size);
    }
}

/// Codec of a compressed kernel or ramdisk, identified by its leading magic
/// with the header checks of [`compressed::sniff`], so a two-byte match is
/// not enough. LZMA-alone has no magic; the Linux default properties with a
/// power-of-two dictionary are accepted, as for kernel payloads.
fn payload_codec(stored: &[u8]) -> Option<Codec> {
    compressed::sniff(stored)
        .or_else(|| compressed::is_plausible_lzma(stored).then_some(Codec::Lzma))
}

/// A kernel or ramdisk component: decoded when it starts with a codec
/// magic, stored as-is otherwise. A payload that does not decode is kept as
/// an opaque component and the failure is noted.
fn payload_child<'a>(
    label: String,
    offset: usize,
    stored: &'a [u8],
    budget: &mut Budget,
    notes: &mut Vec<String>,
) -> Child<'a> {
    let Some(codec) = payload_codec(stored) else {
        return Child::stored(label, offset, stored);
    };
    if budget.limit() == 0 {
        notes.push(format!(
            "{label}: {} payload not decoded; the extraction limit of {} was reached",
            codec.name(),
            size_text(MAX_EXTRACTED)
        ));
        return Child::opaque(label, offset, stored);
    }
    let decoded = match compressed::decode_limited(codec, stored, budget.limit()) {
        Ok(decoded) => decoded,
        Err(e) => {
            notes.push(format!(
                "{label}: payload does not decode as {} ({e})",
                codec.name()
            ));
            return Child::opaque(label, offset, stored);
        }
    };
    budget.spend(decoded.data.len());
    notes.push(decoded_note(&label, codec, stored, &decoded));
    Child::decoded(
        label,
        offset,
        stored.len(),
        Cow::Owned(decoded.data),
        codec.name(),
    )
}

/// What a payload decode established: sizes, the verified check, and what
/// follows the stream inside the section (Linux `Image.gz-dtb` kernels
/// append device trees after the compressed stream).
fn decoded_note(label: &str, codec: Codec, stored: &[u8], decoded: &compressed::Decoded) -> String {
    let check = match decoded.check {
        Some(check) => format!("{check} verified"),
        None => "no integrity check verified".to_string(),
    };
    let mut parts = vec![
        format!(
            "{label}: {} stream decoded to {} B",
            codec.name(),
            decoded.data.len()
        ),
        check,
    ];
    let trailing = decoded
        .consumed
        .and_then(|used| stored.get(used..))
        .unwrap_or_default();
    if trailing.starts_with(&FDT_MAGIC) {
        parts.push(format!(
            "{} B after the stream start with a device tree",
            trailing.len()
        ));
    } else if !is_padding(trailing) {
        parts.push(format!("{} B after the stream", trailing.len()));
    }
    parts.join("; ")
}

/// Stop adding components at [`MAX_COMPONENTS`]; returns whether `children`
/// is full and notes, once, how many of `total` were left out.
fn is_component_limit(children: usize, total: usize, notes: &mut Vec<String>) -> bool {
    if children < MAX_COMPONENTS {
        return false;
    }
    if children == MAX_COMPONENTS && total > children {
        notes.push(format!(
            "{} further components were not listed (limit {MAX_COMPONENTS})",
            total - children
        ));
    }
    true
}

/// The fields of an AVB footer that locate the vbmeta image.
struct AvbFooter {
    original_image_size: u64,
    vbmeta_offset: u64,
    vbmeta_size: u64,
}

/// The AVB footer in the last 64 bytes of `data`, if they start with its
/// magic. Footer fields: magic (4), major (4), minor (4), original image
/// size (8), vbmeta offset (8), vbmeta size (8), reserved (28).
fn avb_footer(data: &[u8], notes: &mut Vec<String>) -> Option<AvbFooter> {
    let start = data.len().checked_sub(AVB_FOOTER_SIZE)?;
    let footer = &data[start..];
    if !footer.starts_with(AVB_FOOTER_MAGIC) {
        return None;
    }
    let major = be_u32(footer, 4).ok()?;
    let minor = be_u32(footer, 8).ok()?;
    if major != AVB_FOOTER_MAJOR {
        notes.push(format!(
            "AVB footer version {major}.{minor} is not supported; footer not parsed"
        ));
        return None;
    }
    Some(AvbFooter {
        original_image_size: be_u64(footer, 12).ok()?,
        vbmeta_offset: be_u64(footer, 20).ok()?,
        vbmeta_size: be_u64(footer, 28).ok()?,
    })
}

/// What [`push_partition_tail`] found after the last section.
struct Tail {
    /// An AVB footer was parsed.
    has_footer: bool,
    /// File offset of the footer's vbmeta image, when it is in the file.
    vbmeta_offset: Option<usize>,
    /// A Samsung or LG marker was noted.
    has_marker: bool,
}

/// Notes, metadata and an opaque component for the partition tail after
/// the last section at `end`: Samsung and LG markers and the AVB footer.
fn push_partition_tail<'a>(c: &mut Container<'a>, data: &'a [u8], end: usize) -> Tail {
    let rest = data.get(end..).unwrap_or_default();
    let mut tail = Tail {
        has_footer: false,
        vbmeta_offset: None,
        has_marker: false,
    };
    if rest.starts_with(SEANDROID_MAGIC) {
        c.notes
            .push("Samsung SEANDROIDENFORCE marker after the last section".into());
        tail.has_marker = true;
    } else if rest.starts_with(&LG_BUMP_MAGIC) {
        c.notes
            .push("LG bump trailer after the last section".into());
        tail.has_marker = true;
    }
    let Some(footer) = avb_footer(data, &mut c.notes) else {
        return tail;
    };
    tail.has_footer = true;
    c.push_metadata(
        format!("{KEY_PREFIX}_avb_original_image_size"),
        "AVB original image size (B)",
        footer.original_image_size,
    );
    let vbmeta = slice64(
        data,
        footer.vbmeta_offset,
        footer.vbmeta_size,
        "AVB vbmeta image",
    );
    match vbmeta {
        Ok(bytes) if bytes.starts_with(AVB_VBMETA_MAGIC) => {
            c.notes.push(format!(
                "AVB footer: original image {} B; vbmeta at 0x{:X} ({} B); signature not verified",
                footer.original_image_size, footer.vbmeta_offset, footer.vbmeta_size
            ));
            let offset = usize::try_from(footer.vbmeta_offset).expect("vbmeta lies in the file");
            c.children.push(Child::opaque("AVB vbmeta", offset, bytes));
            tail.vbmeta_offset = Some(offset);
        }
        _ => c.notes.push(format!(
            "AVB footer names a vbmeta image at 0x{:X} ({} B) that is not in the file",
            footer.vbmeta_offset, footer.vbmeta_size
        )),
    }
    tail
}

/// The partition tail, or a note when bytes other than padding follow the
/// last section and nothing explains them.
fn push_unexplained_tail<'a>(c: &mut Container<'a>, data: &'a [u8], end: usize) {
    let tail = push_partition_tail(c, data, end);
    let rest = data.get(end..).unwrap_or_default();
    if !tail.has_footer && !tail.has_marker && !is_padding(rest) {
        c.notes.push(format!(
            "{} after the last section are not described by the header",
            size_text(rest.len())
        ));
    }
}

/// A target physical address from a header, as metadata.
fn push_address(c: &mut Container<'_>, key: &str, label: &str, address: u64) {
    c.push_metadata(key, label, MetadataValue::Address(address));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_magic_selects_its_layout() {
        let mut sparse = SPARSE_MAGIC.to_le_bytes().to_vec();
        sparse.extend_from_slice(&[0; 4]);
        let cases: [(&[u8], Layout); 7] = [
            (b"ANDROID!\0\0\0\0", Layout::Boot),
            (b"VNDRBOOT\0\0\0\0", Layout::VendorBoot),
            (&sparse, Layout::Sparse),
            (b"CrAU\0\0\0\0", Layout::Ota),
            (b"BOOTLDR!\0\0\0\0", Layout::Bootldr),
            (&[0x3c, 0xd6, 0x1a, 0xce, 1, 0], Layout::MetaImage),
            (b"FBPK\x02\0\0\0", Layout::Fbpk),
        ];
        for (data, layout) in cases {
            assert_eq!(detect(data), Some(layout), "{layout:?}");
            assert!(!layout.is_weak());
        }
        assert_eq!(detect(b"ANDROID"), None);
        assert_eq!(detect(b"\x7fELF\x02\x01\x01\0"), None);
    }

    #[test]
    fn slices_name_the_region_that_is_truncated() {
        let data = [0u8; 16];
        let e = slice(&data, 8, 16, "boot image kernel").unwrap_err();
        assert_eq!(
            e.to_string(),
            "Android image parse error: Truncated boot image kernel at 0x8 + 16 B"
        );
        assert!(slice(&data, usize::MAX, 2, "kernel").is_err());
        assert!(slice64(&data, u64::MAX, 1, "kernel").is_err());
        assert_eq!(asciiz(b"name\0junk"), "name");
        assert_eq!(asciiz(b"full"), "full");
        assert_eq!(size_text(MAX_EXTRACTED), "256 MiB");
        assert_eq!(size_text(16 << 10), "16 KiB");
        assert_eq!(size_text(100), "100 B");
    }

    #[test]
    fn avb_footer_locates_the_vbmeta_image() {
        let mut image = vec![0u8; 256];
        image[64..68].copy_from_slice(AVB_VBMETA_MAGIC);
        let footer = &mut image[192..];
        footer[..4].copy_from_slice(AVB_FOOTER_MAGIC);
        footer[4..8].copy_from_slice(&1u32.to_be_bytes());
        footer[12..20].copy_from_slice(&64u64.to_be_bytes());
        footer[20..28].copy_from_slice(&64u64.to_be_bytes());
        footer[28..36].copy_from_slice(&32u64.to_be_bytes());
        let mut c = Container::new(FileFormat::AndroidBoot, "test", KEY_PREFIX);
        let tail = push_partition_tail(&mut c, &image, 64);
        assert!(tail.has_footer);
        assert_eq!(tail.vbmeta_offset, Some(64));
        assert_eq!(c.children.len(), 1);
        assert!(c.children[0].opaque);
        assert_eq!((c.children[0].offset, c.children[0].stored_size), (64, 32));
        assert!(c.notes[0].ends_with("signature not verified"));
    }

    #[test]
    fn decoded_note_names_an_appended_device_tree() {
        let decoded = compressed::Decoded {
            data: vec![0; 8],
            consumed: Some(4),
            check: Some("CRC-32"),
        };
        let mut stored = vec![0x1f, 0x8b, 8, 0];
        stored.extend_from_slice(&FDT_MAGIC);
        let note = decoded_note("Kernel", Codec::Gzip, &stored, &decoded);
        assert_eq!(
            note,
            "Kernel: gzip stream decoded to 8 B; CRC-32 verified; 4 B after the stream start with a device tree"
        );
    }
}
