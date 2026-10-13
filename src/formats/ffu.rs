//! Microsoft Full Flash Update (FFU) images: the sector-based disk images
//! that Windows phone and device manufacturing tools and DISM write and
//! flash. An FFU holds a security header with a signed catalog and a hash
//! table, an image header with an INI manifest, one store (FFU V1) or
//! several (V2) with their validation entries and write descriptors, and
//! the payload blocks that the write descriptors place on the target disk.
//!
//! Sources (pins and hashes in `docs/ffu.md`):
//! - Microsoft "FFU image format" (Windows hardware manufacturing
//!   documentation for Windows 10 Mobile, ms.date 2017-05-02; Wayback
//!   Machine capture `20190918215141` of the docs.microsoft.com page, which
//!   learn.microsoft.com no longer serves): `SECURITY_HEADER`,
//!   `IMAGE_HEADER`, `STORE_HEADER` with its V2 fields, `VALIDATION_ENTRY`,
//!   `BLOCK_DATA_ENTRY`, `DISK_LOCATION`, the order and padding of the
//!   regions, and the V1 and V2 version values.
//! - Microsoft Learn "`ALG_ID`": `CALG_SHA_256` and `CALG_SHA1`.
//! - `WPinternals` `WPinternals/Models/FFU.cs` at commit `d270cace`: the
//!   header offsets, validation entries right after the 248-byte store
//!   header, `dwBlockCount` payload blocks per write descriptor, and a file
//!   that ends with the last payload block.
//! - img2ffu at commit `d0dda2b2` (`Img2Ffu.Library/Reader`, `Writer`): the
//!   V2 store header fields without alignment padding, the image header's
//!   device targeting count, the manifest keys, `DISK_END` block indices
//!   counted back from the last block, one SHA-256 per chunk from the image
//!   header to the end of the payload, and later writes replacing earlier
//!   ones.
//!
//! An FFU names no ISA: its platform ID names a device, not an instruction
//! set. Each store's disk is assembled from its write descriptors (the first
//! `min(disk size, MAX_PAYLOAD)` bytes, with blocks that are not written as
//! zeros) and is one child, classified on its own, so the partition table,
//! its partitions and the files in them report themselves. The catalog
//! signature is not verified; the chunk hashes of the hash table are, up to
//! a hashing budget.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::{FileFormat, MetadataValue};
use std::borrow::Cow;

mod disk;
mod hash;
mod header;
mod manifest;
mod store;

use disk::Plan;
use header::{ImageHeader, SecurityHeader};
use manifest::{DiskSize, Manifest};
use store::{Store, Stores};

/// Prefix of generated metadata keys.
const KEY_PREFIX: &str = "ffu";

/// `SECURITY_SIGNATURE`, at offset 4 of the security header.
const SECURITY_SIGNATURE: &[u8; 12] = b"SignedImage ";

/// `FFU_SIGNATURE`, at offset 4 of the image header (two trailing spaces).
const IMAGE_SIGNATURE: &[u8; 12] = b"ImageFlash  ";

/// `sizeof(SECURITY_HEADER)`: six fields in 32 bytes.
const SECURITY_HEADER_SIZE: usize = 32;

/// Bytes per KiB: chunk sizes are stored in KiB.
const KIB: u64 = 1024;

/// Transform named for an assembled disk.
const TRANSFORM: &str = "FFU blocks";

/// Longest text field shown in notes and metadata, in characters.
const MAX_TEXT: usize = 256;

/// Why an FFU reports no ISA of its own.
const ISA_NOTE: &str = "FFU images name no ISA; each store's disk is classified on its own";

/// An FFU layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A Full Flash Update image: the `SignedImage ` security header, the
    /// `ImageFlash  ` image header and manifest, one store (V1) or several
    /// (V2), and the payload blocks.
    Ffu,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Ffu => FileFormat::Ffu,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ffu => "FFU image",
        }
    }

    /// Recognized from complete structure rather than a magic value. The
    /// security header carries a 12-byte signature with its size field and
    /// chunk size, so the layout is not weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Ffu => false,
        }
    }
}

/// Strong recognition: `SignedImage ` at offset 4, a `cbSize` of at least
/// the 32-byte header, and a non-zero chunk size that holds the header.
/// Everything else is checked by the parser, so a damaged image becomes a
/// parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    header::is_security_header(data).then_some(Layout::Ffu)
}

/// Parse an FFU image into the shared container model: one child per store
/// with the disk its write descriptors assemble, and the headers, manifest,
/// stores and chunk hashes in notes and metadata.
///
/// # Errors
///
/// [`ClassifierError::FfuParseError`] for a bad signature, size or chunk
/// size in the security or image header; a catalog, hash table, manifest,
/// device targeting entry, store header, descriptor region or payload that
/// the file does not hold; an unsupported store header version or disk
/// access method; descriptors that do not fill their regions exactly;
/// inconsistent V2 store counts or indices; write descriptors that place
/// blocks outside the disk the manifest describes; or data after the payload
/// that is not erased-flash padding.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Ffu => parse(data),
    }
}

fn parse(data: &[u8]) -> Result<Container<'_>> {
    let security = SecurityHeader::read(data)?;
    let image = ImageHeader::read(data, &security)?;
    let manifest = Manifest::parse(image.manifest(data));
    let stores = store::read_all(data, image.stores_offset)?;
    let padding = trailing_padding(data, stores.payload_end)?;
    let mut c = Container::new(FileFormat::Ffu, stores.variant(), KEY_PREFIX);
    c.consumed = data.len();
    push_summary(&mut c, &security, &stores);
    for store in &stores.list {
        store.push_notes(&mut c);
    }
    push_disks(&mut c, data, &stores, &manifest)?;
    image.push_notes(&mut c, &security);
    manifest.push_notes(&mut c);
    security.push_notes(&mut c);
    let hashes = hash::check(data, &security, stores.payload_end);
    c.notes.push(hashes.note);
    c.push_metadata("ffu_chunk_hashes", "Chunk hashes", hashes.status);
    if padding > 0 {
        c.notes.push(format!(
            "{padding} B of erased-flash padding follow the payload at 0x{:X}",
            stores.payload_end
        ));
    }
    c.notes.push(ISA_NOTE.into());
    Ok(c)
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::FfuParseError {
        message: message.into(),
    }
}

/// The overview note and metadata: FFU version, store count, chunk size and
/// where the payload lies.
fn push_summary(c: &mut Container<'_>, security: &SecurityHeader, stores: &Stores<'_>) {
    c.notes.push(format!(
        "{}: {}; {} chunks; payload of {} at 0x{:X}",
        stores.variant(),
        counted(stores.list.len() as u64, "store", "stores"),
        size_text(security.chunk_size),
        size_text((stores.payload_end - stores.payload_offset) as u64),
        stores.payload_offset
    ));
    c.push_metadata("ffu_store_count", "Stores", stores.list.len() as u64);
    c.push_metadata("ffu_chunk_size", "Chunk size (B)", security.chunk_size);
    c.push_metadata(
        "ffu_payload_offset",
        "Payload file offset",
        stores.payload_offset as u64,
    );
    c.push_metadata(
        "ffu_payload_size",
        "Payload size (B)",
        (stores.payload_end - stores.payload_offset) as u64,
    );
}

/// Assemble each store's disk and push it as a child: the main OS stores
/// the manifest marks first (they describe the image best), then the others
/// in store order. Assembly stops at [`MAX_EXTRACTED`] bytes or
/// [`MAX_COMPONENTS`] disks, with a note.
fn push_disks<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    stores: &Stores<'a>,
    manifest: &Manifest,
) -> Result<()> {
    let order = disk_order(stores, manifest);
    if let Some(&first) = order.first().filter(|&&first| first != 0) {
        c.notes.push(format!(
            "Store {} is the main OS store (manifest `IsMainOSStore`), so its disk is listed first",
            first + 1
        ));
    }
    let mut extracted = 0usize;
    for (listed, &i) in order.iter().enumerate() {
        let store = &stores.list[i];
        if listed == MAX_COMPONENTS {
            c.notes.push(format!(
                "{} further store disks were not assembled (limit {MAX_COMPONENTS})",
                order.len() - listed
            ));
            break;
        }
        let disk_size = match manifest.store(i).map(manifest::StoreSection::disk_size) {
            Some(DiskSize::Known(size)) => {
                c.push_metadata(
                    format!("ffu_store_{}_disk_size", store.number),
                    format!("Store {} disk size (B)", store.number),
                    size.bytes,
                );
                Some(size)
            }
            Some(DiskSize::Invalid(reason)) => {
                c.notes.push(format!(
                    "Store {} disk size is unknown: {reason}",
                    store.number
                ));
                None
            }
            Some(DiskSize::Missing) | None => None,
        };
        let plan = Plan::new(store, disk_size)?;
        if store.payload_blocks == 0 {
            c.notes.push(format!(
                "Store {} writes no blocks, so it has no disk to classify",
                store.number
            ));
            continue;
        }
        if plan.limit == 0 {
            c.notes.push(format!(
                "Store {} writes no blocks from the start of the disk and the manifest gives no \
                 disk size, so it has no disk to classify",
                store.number
            ));
            continue;
        }
        if extracted.saturating_add(plan.limit) > MAX_EXTRACTED {
            c.notes.push(format!(
                "Store {} disk was not assembled: the stores before it reached the {} \
                 extraction limit",
                store.number,
                size_text(MAX_EXTRACTED as u64)
            ));
            continue;
        }
        extracted += plan.limit;
        let disk = plan.assemble(data, store)?;
        plan.push_notes(c, store, &disk);
        let label = format!("Store {} disk", store.number);
        if !container::is_recognized(&disk.image) {
            c.notes.push(format!(
                "{label} does not start with a recognized format (such as a partition table or \
                 filesystem), so it is not classified"
            ));
        }
        c.children.push(
            Child::decoded(
                label,
                store.payload_offset,
                store.payload_size,
                Cow::Owned(disk.image),
                TRANSFORM,
            )
            .if_recognized(),
        );
    }
    Ok(())
}

/// Store positions in the order their disks are listed: the stores whose
/// manifest section says `IsMainOSStore = True`, then the rest, each group
/// in store order.
fn disk_order(stores: &Stores<'_>, manifest: &Manifest) -> Vec<usize> {
    let is_main = |i: &usize| {
        manifest
            .store(*i)
            .is_some_and(manifest::StoreSection::is_main_os)
    };
    let (mut order, rest): (Vec<usize>, Vec<usize>) = (0..stores.list.len()).partition(is_main);
    order.extend(rest);
    order
}

/// Bytes after the last payload block, which must be erased flash (all
/// `0x00` or all `0xFF`): FFU defines no trailer.
fn trailing_padding(data: &[u8], payload_end: usize) -> Result<usize> {
    let rest = data.get(payload_end..).unwrap_or_default();
    let erased = rest.iter().all(|&b| b == 0) || rest.iter().all(|&b| b == 0xFF);
    if erased {
        Ok(rest.len())
    } else {
        Err(error(format!(
            "Invalid data after the payload at 0x{payload_end:X}: {} B that are not erased-flash \
             padding",
            rest.len()
        )))
    }
}

/// The `len` bytes at `start`; `what` names them in the error.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

/// A 64-bit file offset or size as `usize`; values beyond the address space
/// lie beyond any file, so they are truncation errors.
fn to_usize(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Truncated {what} at 0x{value:X}")))
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(bytes, at, N, "header field")?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn le_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(bytes, at)?))
}

fn le_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(bytes, at)?))
}

fn le_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(bytes, at)?))
}

/// `value` rounded up to a multiple of `unit` (not zero), or `None` on
/// overflow.
fn round_up(value: u64, unit: u64) -> Option<u64> {
    match value % unit {
        0 => Some(value),
        remainder => value.checked_add(unit - remainder),
    }
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: u64) -> String {
    if n >= 1 << 30 && n % (1 << 30) == 0 {
        format!("{} GiB", n >> 30)
    } else if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// `n` and the noun in the number it takes: "1 store", "2 stores".
fn counted(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Display form of untrusted text: up to the first NUL, control
/// characters as `?`, cut after [`MAX_TEXT`] characters.
fn display_text(chars: impl IntoIterator<Item = char>) -> String {
    let mut text = String::new();
    for (i, ch) in chars.into_iter().take_while(|&ch| ch != '\0').enumerate() {
        if i == MAX_TEXT {
            text.push_str("...");
            break;
        }
        text.push(if ch.is_control() { '?' } else { ch });
    }
    text
}

/// An 8-bit text field (ASCII; UTF-8 where valid) for display.
fn byte_text(bytes: &[u8]) -> String {
    display_text(String::from_utf8_lossy(bytes).chars())
}

/// A UTF-16LE text field for display.
fn utf16le_text(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]));
    display_text(char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_up_reaches_the_next_multiple_or_overflows() {
        assert_eq!(round_up(0, 4096), Some(0));
        assert_eq!(round_up(1, 4096), Some(4096));
        assert_eq!(round_up(4096, 4096), Some(4096));
        assert_eq!(round_up(u64::MAX, 4096), None);
    }

    #[test]
    fn sizes_use_the_largest_exact_binary_unit() {
        assert_eq!(size_text(128 << 10), "128 KiB");
        assert_eq!(size_text(3 << 30), "3 GiB");
        assert_eq!(size_text(1536), "1536 B");
        assert_eq!(counted(1, "store", "stores"), "1 store");
        assert_eq!(counted(3, "store", "stores"), "3 stores");
    }

    #[test]
    fn text_fields_stop_at_nul_and_hide_control_characters() {
        assert_eq!(byte_text(b"Zrax\x01.Test\0junk"), "Zrax?.Test");
        assert_eq!(utf16le_text(&[b'V', 0, b'e', 0, 0, 0, b'n', 0]), "Ve");
        assert_eq!(byte_text(&[b'x'; 300]).len(), MAX_TEXT + 3);
    }

    #[test]
    fn trailing_bytes_must_be_erased_flash() {
        assert_eq!(trailing_padding(&[1, 2, 0, 0], 2).unwrap(), 2);
        assert_eq!(trailing_padding(&[1, 2, 0xFF], 2).unwrap(), 1);
        assert_eq!(trailing_padding(&[1, 2], 2).unwrap(), 0);
        let message = trailing_padding(&[1, 2, 0, 7], 2).unwrap_err().to_string();
        assert_eq!(
            message,
            "FFU image parse error: Invalid data after the payload at 0x2: 2 B that are not \
             erased-flash padding"
        );
    }
}
