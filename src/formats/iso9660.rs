//! ISO 9660 optical disc filesystem images: the ECMA-119 volume descriptor
//! set and directory hierarchy, with names from Rock Ridge or Joliet, El
//! Torito boot images as children and regular files in a recognized format
//! as members.
//!
//! Sources:
//! - ECMA-119 4th edition (June 2019): 6.1.2 and 6.2 (logical sectors and
//!   blocks, the system area), 6.7.1 (volume descriptor set from sector 16),
//!   6.8 (directories), 6.9 (path tables), 7.2.3 and 7.3.3 (both-byte
//!   orders), 7.5 (file identifiers), 8.1-8.6 (volume descriptors, Tables
//!   1-7), 9.1 (directory records, Tables 8 and 10), 9.4 (path table
//!   records, Table 11), 10 (levels of interchange), Annex C (the Joliet
//!   Specification of 1995-05-22: SVD escape sequences, UCS-2 big-endian
//!   names).
//! - IEEE P1281 System Use Sharing Protocol, draft 1.12 (1994-07-08): 4,
//!   4.1, 5.1 (`CE`), 5.3 (`SP`), 5.4 (`ST`), 5.5 (`ER`).
//! - IEEE P1282 Rock Ridge Interchange Protocol, draft 1.12 (1994-07-08):
//!   4.1.1 (`PX`), 4.1.4 (`NM`), 4.1.5 (`CL`, `PL`, `RE`), 4.1.7 (`SF`), 4.3
//!   (ER identifier `IEEE_P1282`); libarchive v3.7.4
//!   `archive_write_set_format_iso9660.c` (`rrip_identifier`,
//!   `RRIP_1991A`).
//! - "El Torito" Bootable CD-ROM Format Specification 1.0 (Phoenix
//!   Technologies and IBM, 1995-01-25): 1.5, 2.0-2.5, figures 2-7, 4.1, 4.3.
//! - libisofs `release-1.5.6` `doc/boot_sectors.txt` (platform ID 0xEF, as
//!   UEFI 2.4 12.3.2.1 defines it; the MBR and GPT layouts) and tianocore
//!   edk2 `edk2-stable202408`
//!   `MdeModulePkg/Universal/Disk/PartitionDxe/ElTorito.c` (the extent of
//!   an EFI system partition image).
//! - ECMA-167 3rd edition (June 1997): 2/8.3, 2/9.1-9.3 and 3/9.1 (the UDF
//!   volume recognition sequence).
//! - Linux v6.11 `fs/isofs/inode.c` (`isofs_fill_super`: Rock Ridge before
//!   Joliet, logical block sizes) and `fs/isofs/rock.c` (`SP` check bytes,
//!   at most 32 continuation areas).
//!
//! All descriptor numbers are recorded in both byte orders or in a stated
//! one; El Torito fields are little-endian. Sectors are 2048 bytes; extents
//! count logical blocks of 512, 1024 or 2048 bytes; El Torito load addresses
//! count 2048-byte sectors and its sector counts 512-byte virtual sectors.
//! The format names no processor. Only the El Torito platform ID names one
//! for a boot image; members are classified from their own bytes.

use crate::error::{ClassifierError, Result};
use crate::formats::container::Container;
use crate::types::FileFormat;

mod descriptors;
mod directory;
mod eltorito;
mod susp;
mod walk;

use descriptors::DescriptorSet;

/// Logical sector size of a CD-ROM volume (ECMA-119 6.1.2).
const SECTOR_SIZE: usize = 2048;

/// First sector of the volume descriptor set (6.7.1); sectors 0-15 are the
/// system area (6.2.1).
const FIRST_DESCRIPTOR_SECTOR: usize = 16;

/// File offset of the first volume descriptor.
const DESCRIPTOR_SET_OFFSET: usize = FIRST_DESCRIPTOR_SECTOR * SECTOR_SIZE;

/// Standard identifier of every ECMA-119 volume descriptor (8.1.2).
const STANDARD_ID: &[u8; 5] = b"CD001";

/// Offset of the standard identifier within a descriptor.
const STANDARD_ID_OFFSET: usize = 1;

/// Bytes of a regular file read to decide whether it is a recognized
/// format.
const PROBE_SIZE: usize = 4096;

/// Deepest directory level below the root that the walk enters. ECMA-119
/// allows 8 levels (6.8.2.1); Joliet and Rock Ridge relocation allow more.
const MAX_DEPTH: usize = 64;

/// Longest member path that is walked (Linux `PATH_MAX`).
const MAX_PATH: usize = 4096;

/// An ISO 9660 layout recognized by its descriptor set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// An ECMA-119 volume: `CD001` at 0x8001 and a consistent primary
    /// volume descriptor. Rock Ridge, Joliet, El Torito and UDF bridge
    /// descriptors are reported in the notes.
    Iso9660,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Iso9660 => FileFormat::Iso9660,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Iso9660 => "ISO 9660",
        }
    }

    /// Recognized from complete structure rather than a magic value. The
    /// layout carries `CD001`, so it is not weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Iso9660 => false,
        }
    }
}

/// Strong recognition: `CD001` at 0x8001 and, in the volume descriptor set,
/// a primary volume descriptor whose both-byte-order fields agree, whose
/// logical block size is 512, 1024 or 2048 and whose root directory record
/// is well formed. The volume size, the directory tree and the El Torito
/// catalog are checked by [`parse_container`], so a damaged image is a
/// parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let magic_at = DESCRIPTOR_SET_OFFSET + STANDARD_ID_OFFSET;
    if data.get(magic_at..magic_at + STANDARD_ID.len()) != Some(STANDARD_ID.as_slice()) {
        return None;
    }
    descriptors::find_primary(data)
        .is_ok()
        .then_some(Layout::Iso9660)
}

/// Parse an ISO 9660 image into the shared container model. Regular files
/// that start with a recognized format are the first children, labeled by
/// their path; El Torito boot images follow.
///
/// # Errors
///
/// [`ClassifierError::Iso9660ParseError`] for a volume descriptor set
/// without a valid primary volume descriptor or terminator, a volume larger
/// than the file or followed by data other than padding (unless the system
/// area holds a partition table that may describe it), or an unreadable
/// root directory. Damage below the root directory and an invalid El Torito
/// catalog are reported in notes.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let set = descriptors::read_set(data)?;
    let volume = &set.primary;
    let volume_size = volume.size()?;
    let Some(image) = data.get(..volume_size) else {
        return Err(error(format!(
            "Truncated ISO 9660 volume: {} blocks of {} B need {volume_size} B, {} B present",
            volume.space_blocks,
            volume.block_size,
            data.len()
        )));
    };
    let system_area = descriptors::SystemArea::read(data);
    let trailing = &data[volume_size..];
    if !is_padding(trailing) && !system_area.has_partition_table() {
        return Err(error(format!(
            "Invalid trailing data: {} B after the volume at 0x{volume_size:X} are not padding",
            trailing.len()
        )));
    }

    let mut c = Container::new(layout.format(), layout.label(), "iso9660");
    c.consumed = volume_size;
    let tree = walk::Tree::choose(image, &set)?;
    describe(&set, &tree, &mut c);
    let catalog = set
        .el_torito
        .as_ref()
        .map(|record| eltorito::Catalog::read(image, record));
    let boot_offsets = catalog
        .as_ref()
        .and_then(|catalog| catalog.as_ref().ok())
        .map(eltorito::Catalog::image_offsets)
        .unwrap_or_default();
    let mut walked = walk::walk(&tree, &boot_offsets);
    let boot_files = std::mem::take(&mut walked.boot_files);
    system_area.describe(volume_size, trailing, &mut c);
    set.describe_extras(&mut c);
    descriptors::check_path_tables(image, volume, &mut c);
    walked.finish(&mut c);
    // Boot images follow the files: the files describe the disc better than
    // its boot code, which supplies the primary ISA only when no file is
    // recognized.
    if let Some(catalog) = catalog {
        eltorito::describe(image, catalog, &boot_files, &mut c);
    }
    Ok(c)
}

/// Summary notes and metadata from the primary volume descriptor and the
/// chosen name source.
fn describe(set: &DescriptorSet, tree: &walk::Tree<'_>, c: &mut Container<'_>) {
    let volume = &set.primary;
    c.notes.push(format!(
        "ISO 9660 volume \"{}\": {} logical blocks of {} B ({}); names from {}",
        volume.identifier.escape_debug(),
        volume.space_blocks,
        volume.block_size,
        size_text(u64::from(volume.space_blocks) * volume.block_size as u64),
        tree.names.description()
    ));
    if let Some(joliet) = &set.joliet {
        let use_text = match (&tree.names, &tree.joliet_unusable) {
            (walk::Names::Joliet, _) => "its hierarchy supplies the names".to_string(),
            (_, Some(reason)) => format!("not used: {reason}"),
            (_, None) => "not used for names: Rock Ridge takes precedence".to_string(),
        };
        c.notes.push(format!(
            "Joliet supplementary volume descriptor at 0x{:X}, UCS-2 level {}; {use_text}",
            joliet.volume.offset, joliet.level
        ));
    }
    if volume.set_size > 1 {
        c.notes.push(format!(
            "Volume {} of a set of {}; file sections recorded on other volumes are not read",
            volume.sequence_number, volume.set_size
        ));
    }
    c.notes.push(
        "No processor field: ISO 9660 names no ISA; members are classified from their own bytes"
            .to_string(),
    );
    c.push_metadata(
        "iso9660_volume_id",
        "Volume identifier",
        volume.identifier.clone(),
    );
    if !volume.system_id.is_empty() {
        c.push_metadata(
            "iso9660_system_id",
            "System identifier",
            volume.system_id.clone(),
        );
    }
    for (key, label, value) in [
        (
            "iso9660_volume_set_id",
            "Volume set identifier",
            &volume.set_id,
        ),
        ("iso9660_publisher", "Publisher", &volume.publisher),
        ("iso9660_preparer", "Data preparer", &volume.preparer),
        ("iso9660_application", "Application", &volume.application),
    ] {
        if !value.is_empty() {
            c.push_metadata(key, label, value.clone());
        }
    }
    if let Some(created) = &volume.created {
        c.push_metadata("iso9660_created", "Volume creation time", created.clone());
    }
    c.push_metadata(
        "iso9660_block_size",
        "Logical block size (B)",
        volume.block_size as u64,
    );
    c.push_metadata(
        "iso9660_volume_blocks",
        "Volume space (logical blocks)",
        u64::from(volume.space_blocks),
    );
    c.push_metadata("iso9660_names", "Name source", tree.names.label());
    if let Some(joliet) = &set.joliet {
        c.push_metadata(
            "iso9660_joliet_level",
            "Joliet UCS-2 level",
            u64::from(joliet.level),
        );
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::Iso9660ParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid file range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated image at 0x{start:X} + {len} B")))
}

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn byte(data: &[u8], at: usize) -> Result<u8> {
    Ok(slice(data, at, 1)?[0])
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at)?))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(data, at)?))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(data, at)?))
}

/// A 16-bit number in both byte orders (ECMA-119 7.2.3): little-endian,
/// then big-endian. Returns both halves.
fn both_u16_halves(data: &[u8], at: usize) -> Result<(u16, u16)> {
    Ok((le_u16(data, at)?, be_u16(data, at + 2)?))
}

/// A 32-bit number in both byte orders (ECMA-119 7.3.3): little-endian,
/// then big-endian. Returns both halves.
fn both_u32_halves(data: &[u8], at: usize) -> Result<(u32, u32)> {
    Ok((le_u32(data, at)?, be_u32(data, at + 4)?))
}

/// A 16-bit both-byte-order field whose halves must agree; `field` names it
/// in the error.
fn both_u16(data: &[u8], at: usize, field: &str) -> Result<u16> {
    let (little, big) = both_u16_halves(data, at)?;
    if little != big {
        return Err(error(format!(
            "Invalid {field} at 0x{at:X}: little-endian 0x{little:04X} and big-endian \
             0x{big:04X} differ"
        )));
    }
    Ok(little)
}

/// A 32-bit both-byte-order field whose halves must agree; `field` names it
/// in the error.
fn both_u32(data: &[u8], at: usize, field: &str) -> Result<u32> {
    let (little, big) = both_u32_halves(data, at)?;
    if little != big {
        return Err(error(format!(
            "Invalid {field} at 0x{at:X}: little-endian 0x{little:08X} and big-endian \
             0x{big:08X} differ"
        )));
    }
    Ok(little)
}

/// The file offset of logical block `block`, if it fits in `usize`.
fn block_offset(block: u32, block_size: usize) -> Option<usize> {
    usize::try_from(u64::from(block) * block_size as u64).ok()
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A fixed-length character field (ECMA-119 7.4.5): left-justified, padded
/// with spaces (FILLER) or, as many writers do, NUL bytes.
fn text_field(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|b| !matches!(b, b' ' | 0))
        .map_or(0, |last| last + 1);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// UCS-2 big-endian text (Joliet, ECMA-119 C.3.4), with unpaired
/// surrogates replaced.
fn ucs2_text(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: u64) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_byte_order_fields_must_agree() {
        let agreeing = [0x34, 0x12, 0x12, 0x34];
        assert_eq!(both_u16(&agreeing, 0, "test").unwrap(), 0x1234);
        let differing = [0x34, 0x12, 0x12, 0x35];
        let message = both_u16(&differing, 0, "test").unwrap_err().to_string();
        assert!(message.contains("big-endian 0x1235"), "{message}");
        let wide = [0x78, 0x56, 0x34, 0x12, 0x12, 0x34, 0x56, 0x78];
        assert_eq!(both_u32(&wide, 0, "test").unwrap(), 0x1234_5678);
        assert!(both_u32(&wide, 1, "test").is_err());
    }

    #[test]
    fn character_fields_drop_filler_and_nul_padding() {
        assert_eq!(text_field(b"CDROM   \0\0"), "CDROM");
        assert_eq!(text_field(b"    "), "");
        assert_eq!(ucs2_text(&[0, b'a', 0x00, 0xE9]), "a\u{e9}");
        assert_eq!(ucs2_text(&[0xD8, 0x00]), "\u{fffd}");
    }

    #[test]
    fn block_offsets_and_sizes() {
        assert_eq!(block_offset(16, 2048), Some(0x8000));
        assert_eq!(size_text(80 << 10), "80 KiB");
        assert_eq!(size_text(3 << 20), "3 MiB");
        assert_eq!(size_text(1500), "1500 B");
    }

    #[test]
    fn detection_needs_the_standard_identifier_at_0x8001() {
        assert_eq!(detect(&vec![0; DESCRIPTOR_SET_OFFSET + 8]), None);
        assert_eq!(detect(b"CD001"), None);
    }
}
