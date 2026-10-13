//! El Torito boot catalogs (El Torito 1.0, figures 2-6): a validation entry
//! with a checksum, the initial/default entry, then sections of entries per
//! platform. Bootable entries become children: platform 0 no-emulation
//! images are x86 real-mode code (4.3, 5.3), EFI images are EFI system
//! partitions (FAT, per UEFI as libisofs quotes it), and emulated floppy and
//! hard disk images are disk images classified from their own bytes.

use super::descriptors::BootRecord;
use super::walk::BootFile;
use super::*;
use crate::formats::container::{Child, Target};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, Isa};
use std::collections::HashMap;

/// Size of every catalog entry (2.0, "20" hex).
const ENTRY_SIZE: usize = 32;

/// Validation entry (figure 2): header ID, platform ID (1), ID string (4,
/// 24 B), checksum word (0x1C), key bytes (0x1E).
const VALIDATION_HEADER_ID: u8 = 0x01;
const VALIDATION_ID_STRING: std::ops::Range<usize> = 4..0x1C;
const KEY_BYTES_OFFSET: usize = 0x1E;
const KEY_BYTES: [u8; 2] = [0x55, 0xAA];

/// Boot indicators of the default and section entries (figures 3 and 5).
const BOOTABLE: u8 = 0x88;
const NOT_BOOTABLE: u8 = 0x00;

/// Section header indicators (figure 4): more headers follow, or final.
const SECTION_HEADER: u8 = 0x90;
const FINAL_SECTION_HEADER: u8 = 0x91;

/// Section entry extension indicator (figure 6).
const EXTENSION_INDICATOR: u8 = 0x44;

/// Media type byte: bits 0-3 the emulation, bit 5 "continuation entry
/// follows" (an extension, figures 5 and 6).
const MEDIA_TYPE_MASK: u8 = 0x0F;
const EXTENSION_FOLLOWS: u8 = 0x20;

/// Emulation types (figure 3).
const MEDIA_NO_EMULATION: u8 = 0;
const MEDIA_FLOPPY_1200: u8 = 1;
const MEDIA_FLOPPY_1440: u8 = 2;
const MEDIA_FLOPPY_2880: u8 = 3;
const MEDIA_HARD_DISK: u8 = 4;

/// Platform IDs (figures 2 and 4; 0xEF from UEFI 2.4 12.3.2.1 as libisofs
/// `boot_sectors.txt` quotes it).
const PLATFORM_X86: u8 = 0x00;
const PLATFORM_POWERPC: u8 = 0x01;
const PLATFORM_MAC: u8 = 0x02;
const PLATFORM_EFI: u8 = 0xEF;

/// Virtual sector of an emulated device and unit of the sector count
/// (1.5, "200" hex).
const VIRTUAL_SECTOR_SIZE: usize = 512;

/// Load segment used when the entry records 0 (figure 3).
const DEFAULT_LOAD_SEGMENT: u16 = 0x07C0;

/// Most catalog bytes read: 32 sectors of 64 entries. The specification
/// sets no limit (2.0); EDK2 reads one sector.
const MAX_CATALOG_SIZE: usize = 32 * SECTOR_SIZE;

/// Emulated floppy geometry (4.1): 0x50 tracks, 2 heads, and 0x0F, 0x12 or
/// 0x24 sectors per track.
const FLOPPY_TRACKS: usize = 0x50;
const FLOPPY_HEADS: usize = 2;

/// The MBR of an emulated hard disk holds one partition, in the first entry
/// (4.1): start LBA at 454 and sector count at 458, signature at 510.
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];
const FIRST_PARTITION_START: usize = 454;
const FIRST_PARTITION_SECTORS: usize = 458;

/// Platform 0 no-emulation images are loaded at the load segment and run
/// in real mode (4.3, 5.3).
const X86_REAL_MODE: Target = Target::new(Isa::X86, 16, Endianness::Little);

/// Platform 1 names PowerPC; the byte order is left to the code.
const POWERPC: Target = Target::without_byte_order(Isa::Ppc, 32);

/// A bootable catalog entry (figures 3 and 5).
#[derive(Debug)]
struct Entry {
    /// "default entry" or "section N entry M".
    name: String,
    platform: u8,
    /// Emulation type (bits 0-3 of the media type).
    media: u8,
    load_segment: u16,
    /// Virtual sectors loaded (512 B each).
    sector_count: u16,
    /// Load RBA, in 2048-byte sectors.
    load_rba: u32,
}

impl Entry {
    /// File offset of the image.
    fn image_offset(&self) -> Option<usize> {
        block_offset(self.load_rba, SECTOR_SIZE)
    }
}

/// A boot catalog whose validation entry checked.
#[derive(Debug)]
pub(super) struct Catalog {
    /// Catalog sector and file offset.
    sector: u32,
    offset: usize,
    /// Platform ID of the validation entry, which the default entry uses.
    platform: u8,
    /// Manufacturer or developer ID string.
    id: String,
    /// Bootable entries in catalog order.
    entries: Vec<Entry>,
    not_bootable: usize,
    /// Entries that could not be read, with the reason.
    problems: Vec<String>,
}

fn platform_name(platform: u8) -> String {
    match platform {
        PLATFORM_X86 => "80x86".to_string(),
        PLATFORM_POWERPC => "PowerPC".to_string(),
        PLATFORM_MAC => "Mac".to_string(),
        PLATFORM_EFI => "EFI".to_string(),
        other => format!("platform 0x{other:02X}"),
    }
}

fn media_name(media: u8) -> &'static str {
    match media {
        MEDIA_NO_EMULATION => "no emulation",
        MEDIA_FLOPPY_1200 => "1.2 MB floppy emulation",
        MEDIA_FLOPPY_1440 => "1.44 MB floppy emulation",
        MEDIA_FLOPPY_2880 => "2.88 MB floppy emulation",
        MEDIA_HARD_DISK => "hard disk emulation",
        _ => "reserved media type",
    }
}

/// Sum of the little-endian words of the validation entry; a valid entry
/// sums to 0 (figure 2).
fn word_sum(entry: &[u8]) -> u16 {
    entry.chunks_exact(2).fold(0u16, |sum, word| {
        sum.wrapping_add(u16::from_le_bytes([word[0], word[1]]))
    })
}

/// The entry at `at`, if it is bootable; the caller checked that its 32
/// bytes lie in `catalog`. Layout (figures 3 and 5): boot indicator (0),
/// media type (1), load segment (2), system type (4), sector count (6), load
/// RBA (8).
fn boot_entry(
    catalog: &[u8],
    at: usize,
    name: String,
    platform: u8,
) -> std::result::Result<Option<Entry>, String> {
    let entry = &catalog[at..at + ENTRY_SIZE];
    match entry[0] {
        BOOTABLE => {}
        NOT_BOOTABLE => return Ok(None),
        other => return Err(format!("{name}: invalid boot indicator 0x{other:02X}")),
    }
    let media = entry[1] & MEDIA_TYPE_MASK;
    if media > MEDIA_HARD_DISK {
        return Err(format!("{name}: reserved media type {media}"));
    }
    Ok(Some(Entry {
        name,
        platform,
        media,
        load_segment: u16::from_le_bytes([entry[2], entry[3]]),
        sector_count: u16::from_le_bytes([entry[6], entry[7]]),
        load_rba: u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]),
    }))
}

impl Catalog {
    /// Read the catalog that `record` points to. The error is a note: an
    /// invalid catalog leaves the filesystem readable.
    pub(super) fn read(image: Image<'_>, record: &BootRecord) -> std::result::Result<Self, String> {
        let sector = record.catalog_sector;
        let Some(offset) = block_offset(sector, SECTOR_SIZE).filter(|offset| *offset < image.size)
        else {
            return Err(format!(
                "El Torito boot record at 0x{:X}: the boot catalog sector 0x{sector:X} lies \
                 outside the volume",
                record.offset
            ));
        };
        // The catalog's first sector must be present; a truncated volume's
        // input may end in the sectors after it.
        let first_sector = SECTOR_SIZE.min(image.size - offset);
        if image.present(offset, first_sector).is_none() {
            return Err(format!(
                "El Torito boot record at 0x{:X}: the boot catalog sector 0x{sector:X} lies past \
                 the {} present",
                record.offset,
                image.present_text()
            ));
        }
        let end = image
            .bytes
            .len()
            .min(offset.saturating_add(MAX_CATALOG_SIZE));
        let catalog = &image.bytes[offset..end];
        let location = format!("El Torito boot catalog at sector 0x{sector:X} (file 0x{offset:X})");
        if catalog.len() < 2 * ENTRY_SIZE {
            return Err(format!("{location}: truncated"));
        }
        let validation = &catalog[..ENTRY_SIZE];
        if validation[0] != VALIDATION_HEADER_ID {
            return Err(format!(
                "{location}: invalid validation entry header ID 0x{:02X}",
                validation[0]
            ));
        }
        if validation[KEY_BYTES_OFFSET..ENTRY_SIZE] != KEY_BYTES {
            return Err(format!(
                "{location}: invalid validation entry key bytes {:02X?}",
                &validation[KEY_BYTES_OFFSET..ENTRY_SIZE]
            ));
        }
        let sum = word_sum(validation);
        if sum != 0 {
            return Err(format!(
                "{location}: invalid validation entry checksum: the words sum to 0x{sum:04X}"
            ));
        }
        let platform = validation[1];
        let mut found = Self {
            sector,
            offset,
            platform,
            id: text_field(&validation[VALIDATION_ID_STRING]),
            entries: Vec::new(),
            not_bootable: 0,
            problems: Vec::new(),
        };
        found.add(boot_entry(
            catalog,
            ENTRY_SIZE,
            "default entry".to_string(),
            platform,
        ));
        found.sections(catalog);
        Ok(found)
    }

    fn add(&mut self, entry: std::result::Result<Option<Entry>, String>) {
        match entry {
            Ok(Some(entry)) => self.entries.push(entry),
            Ok(None) => self.not_bootable += 1,
            Err(problem) => self.problems.push(problem),
        }
    }

    /// The section headers and entries after the default entry (figures
    /// 4-6). A byte other than a header indicator ends the catalog.
    fn sections(&mut self, catalog: &[u8]) {
        let mut pos = 2 * ENTRY_SIZE;
        let mut section = 0;
        while pos + ENTRY_SIZE <= catalog.len() {
            let indicator = catalog[pos];
            if !matches!(indicator, SECTION_HEADER | FINAL_SECTION_HEADER) {
                return;
            }
            section += 1;
            let platform = catalog[pos + 1];
            let count = usize::from(u16::from_le_bytes([catalog[pos + 2], catalog[pos + 3]]));
            pos += ENTRY_SIZE;
            for number in 1..=count {
                if pos + ENTRY_SIZE > catalog.len() {
                    self.problems.push(format!(
                        "section {section}: {count} entries announced, the catalog ends after {}",
                        number - 1
                    ));
                    return;
                }
                let name = format!("section {section} entry {number}");
                let extended = catalog[pos + 1] & EXTENSION_FOLLOWS != 0;
                self.add(boot_entry(catalog, pos, name, platform));
                pos += ENTRY_SIZE;
                if extended {
                    pos = skip_extensions(catalog, pos);
                }
            }
            if indicator == FINAL_SECTION_HEADER {
                return;
            }
        }
    }

    /// File offsets of the bootable images, for matching them to files.
    pub(super) fn image_offsets(&self) -> Vec<usize> {
        self.entries
            .iter()
            .filter_map(Entry::image_offset)
            .collect()
    }
}

/// The position after the section entry extensions at `pos` (figure 6):
/// each one with bit 5 set is followed by another.
fn skip_extensions(catalog: &[u8], mut pos: usize) -> usize {
    while pos + ENTRY_SIZE <= catalog.len() && catalog[pos] == EXTENSION_INDICATOR {
        let more = catalog[pos + 1] & EXTENSION_FOLLOWS != 0;
        pos += ENTRY_SIZE;
        if !more {
            break;
        }
    }
    pos
}

/// The size of an entry's image and where it comes from. A file whose data
/// starts at the image gives its size; otherwise the media type (floppy),
/// the MBR (hard disk) or the sector count (no emulation) does. An EFI
/// image with a sector count of 0 or 1 extends to the end of the volume
/// (EDK2 `PartitionInstallElToritoChildHandles`).
fn image_size(
    image: Image<'_>,
    entry: &Entry,
    offset: usize,
    file: Option<&BootFile>,
) -> std::result::Result<(usize, String), String> {
    let floppy = |sectors_per_track: usize| {
        let size = FLOPPY_TRACKS * FLOPPY_HEADS * sectors_per_track * VIRTUAL_SECTOR_SIZE;
        Ok((size, "the emulated floppy geometry".to_string()))
    };
    match (entry.media, file) {
        (MEDIA_FLOPPY_1200, _) => floppy(0x0F),
        (MEDIA_FLOPPY_1440, _) => floppy(0x12),
        (MEDIA_FLOPPY_2880, _) => floppy(0x24),
        (_, Some(file)) => Ok((file.size, format!("file {}", file.path))),
        (MEDIA_HARD_DISK, None) => hard_disk_size(image, offset),
        (_, None) if entry.platform == PLATFORM_EFI && entry.sector_count < 2 => Ok((
            image.size - offset,
            "the rest of the volume (sector count below 2)".to_string(),
        )),
        (_, None) if entry.sector_count == 0 => Err("the sector count is 0".to_string()),
        (_, None) => Ok((
            usize::from(entry.sector_count) * VIRTUAL_SECTOR_SIZE,
            "the sector count".to_string(),
        )),
    }
}

/// An emulated hard disk ends where its first partition ends (4.1).
fn hard_disk_size(image: Image<'_>, offset: usize) -> std::result::Result<(usize, String), String> {
    if image.holds(offset, VIRTUAL_SECTOR_SIZE)
        && image.present(offset, VIRTUAL_SECTOR_SIZE).is_none()
    {
        return Err(format!(
            "the hard disk image's MBR lies past the {} present",
            image.present_text()
        ));
    }
    let mbr = image
        .bytes
        .get(offset..offset + VIRTUAL_SECTOR_SIZE)
        .filter(|mbr| mbr[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2] == MBR_SIGNATURE)
        .ok_or_else(|| "the hard disk image has no MBR".to_string())?;
    let start = le_u32(mbr, FIRST_PARTITION_START).map_err(descriptors::message)?;
    let sectors = le_u32(mbr, FIRST_PARTITION_SECTORS).map_err(descriptors::message)?;
    let end = u64::from(start) + u64::from(sectors);
    let size = usize::try_from(end * VIRTUAL_SECTOR_SIZE as u64)
        .ok()
        .filter(|size| *size > 0)
        .ok_or_else(|| format!("the MBR's first partition ends at sector {end}"))?;
    Ok((size, "the MBR's first partition".to_string()))
}

/// The child for one bootable entry, or why there is none.
fn boot_child<'a>(
    image: Image<'a>,
    entry: &Entry,
    files: &HashMap<usize, BootFile>,
    notes: &mut Vec<String>,
) -> std::result::Result<Child<'a>, String> {
    let offset = entry
        .image_offset()
        .filter(|offset| *offset < image.size)
        .ok_or_else(|| format!("load RBA 0x{:X} lies outside the volume", entry.load_rba))?;
    let (size, source) = image_size(image, entry, offset, files.get(&offset))?;
    if !image.holds(offset, size) {
        return Err(format!(
            "the {size} B image at 0x{offset:X} (size from {source}) extends past the volume"
        ));
    }
    let bytes = image.present(offset, size).ok_or_else(|| {
        format!(
            "the {size} B image at 0x{offset:X} (size from {source}) lies partly or wholly past \
             the {} present",
            image.present_text()
        )
    })?;
    if size > MAX_PAYLOAD {
        return Err(format!(
            "the {} image (size from {source}) exceeds the {} member limit",
            size_text(size as u64),
            size_text(MAX_PAYLOAD as u64)
        ));
    }
    let label = format!(
        "El Torito {} ({}, {})",
        entry.name,
        platform_name(entry.platform),
        media_name(entry.media)
    );
    let load = if entry.platform == PLATFORM_X86 {
        let segment = match entry.load_segment {
            0 => DEFAULT_LOAD_SEGMENT,
            segment => segment,
        };
        format!(
            "; {} virtual sectors loaded at segment 0x{segment:04X}",
            entry.sector_count
        )
    } else {
        String::new()
    };
    let content = match (entry.platform, entry.media) {
        (PLATFORM_X86, MEDIA_NO_EMULATION) => "x86 real-mode boot code (platform ID 0)",
        (PLATFORM_POWERPC, MEDIA_NO_EMULATION) => "PowerPC boot image (platform ID 1)",
        (PLATFORM_EFI, MEDIA_NO_EMULATION) => {
            "EFI system partition image, usually FAT; classified from its own bytes"
        }
        (_, MEDIA_NO_EMULATION) => "boot image; the platform names no ISA",
        _ => "emulated disk image; classified from its own bytes",
    };
    notes.push(format!(
        "{label}: {content}; sector 0x{:X} (file 0x{offset:X}), {} from {source}{load}",
        entry.load_rba,
        size_text(size as u64)
    ));
    let child = Child::stored(label, offset, bytes);
    Ok(match (entry.platform, entry.media) {
        (PLATFORM_X86, MEDIA_NO_EMULATION) => child.as_code().with_target(X86_REAL_MODE),
        (PLATFORM_POWERPC, MEDIA_NO_EMULATION) => child.with_target(POWERPC),
        _ => child,
    })
}

/// Notes, metadata and children for the boot catalog, or the note for an
/// invalid one.
pub(super) fn describe<'a>(
    image: Image<'a>,
    catalog: std::result::Result<Catalog, String>,
    files: &HashMap<usize, BootFile>,
    c: &mut Container<'a>,
) {
    let catalog = match catalog {
        Ok(catalog) => catalog,
        Err(reason) => {
            c.notes
                .push(format!("{reason}; boot images are not listed"));
            return;
        }
    };
    let id = if catalog.id.is_empty() {
        String::new()
    } else {
        format!(", ID \"{}\"", catalog.id.escape_debug())
    };
    c.notes.push(format!(
        "El Torito boot catalog at sector 0x{:X} (file 0x{:X}): validation entry checksum \
         verified; platform {}{id}; {} bootable entries, {} not bootable",
        catalog.sector,
        catalog.offset,
        platform_name(catalog.platform),
        catalog.entries.len(),
        catalog.not_bootable
    ));
    c.push_metadata(
        "iso9660_boot_catalog",
        "El Torito boot catalog",
        format!(
            "sector 0x{:X} (file 0x{:X})",
            catalog.sector, catalog.offset
        ),
    );
    c.push_metadata(
        "iso9660_boot_entries",
        "El Torito bootable entries",
        catalog.entries.len() as u64,
    );
    for problem in &catalog.problems {
        c.notes
            .push(format!("El Torito {problem}; the entry is not listed"));
    }
    for entry in &catalog.entries {
        match boot_child(image, entry, files, &mut c.notes) {
            Ok(child) => c.children.push(child),
            Err(reason) => c
                .notes
                .push(format!("El Torito {} is not listed: {reason}", entry.name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A validation entry for `platform` with its checksum.
    fn validation(platform: u8) -> [u8; ENTRY_SIZE] {
        let mut entry = [0u8; ENTRY_SIZE];
        entry[0] = VALIDATION_HEADER_ID;
        entry[1] = platform;
        entry[KEY_BYTES_OFFSET..].copy_from_slice(&KEY_BYTES);
        let checksum = 0u16.wrapping_sub(word_sum(&entry));
        entry[0x1C..0x1E].copy_from_slice(&checksum.to_le_bytes());
        entry
    }

    #[test]
    fn validation_checksums_sum_the_words_to_zero() {
        let entry = validation(PLATFORM_X86);
        assert_eq!(word_sum(&entry), 0);
        assert_eq!(&entry[0x1C..0x1E], &[0xAA, 0x55]);
        assert_eq!(word_sum(&validation(PLATFORM_EFI)), 0);
    }

    #[test]
    fn extensions_chain_while_bit_5_is_set() {
        let mut catalog = vec![0u8; 4 * ENTRY_SIZE];
        catalog[0] = EXTENSION_INDICATOR;
        catalog[1] = EXTENSION_FOLLOWS;
        catalog[ENTRY_SIZE] = EXTENSION_INDICATOR;
        catalog[2 * ENTRY_SIZE] = EXTENSION_INDICATOR;
        assert_eq!(skip_extensions(&catalog, 0), 2 * ENTRY_SIZE);
        assert_eq!(skip_extensions(&catalog, 3 * ENTRY_SIZE), 3 * ENTRY_SIZE);
    }

    #[test]
    fn floppy_images_take_the_emulated_geometry() {
        let entry = Entry {
            name: "default entry".to_string(),
            platform: PLATFORM_X86,
            media: MEDIA_FLOPPY_1440,
            load_segment: 0,
            sector_count: 1,
            load_rba: 20,
        };
        let empty = Image {
            bytes: &[],
            size: 0,
        };
        let (size, _) = image_size(empty, &entry, 0, None).unwrap();
        assert_eq!(size, 1_474_560);
    }
}
