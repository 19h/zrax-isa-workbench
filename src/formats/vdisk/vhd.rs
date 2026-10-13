//! Microsoft VHD images: fixed, dynamic and differencing (Microsoft
//! "Virtual Hard Disk Image Format Specification" 1.0, 2006-10-11: "Hard
//! Disk Footer Format", "Dynamic Disk Header Format", "Block Allocation
//! Table and Data Blocks", "Implementing a Differencing Hard Disk"; QEMU
//! `v11.1.1` `block/vpc.c`; `VirtualBox` `v7.2.20` `src/VBox/Storage/VHD.cpp`
//! for the parent name and sector bitmap encodings).
//!
//! Every field is big-endian. A fixed disk is the guest's bytes followed by
//! a 512-byte footer (511 bytes before Virtual PC 2004). A dynamic or
//! differencing disk starts with a copy of the footer, then the dynamic
//! disk header, the block allocation table (BAT) of 32-bit sector offsets
//! and the blocks, each a sector bitmap and the block's data, and ends with
//! the footer. Footer and header carry a one's-complement byte-sum
//! checksum.

use super::*;

/// The footer cookie.
const COOKIE: &[u8; 8] = b"conectix";

/// Footer sizes: 512 bytes, or 511 before Virtual PC 2004.
const FOOTER_SIZE: usize = 512;
const OLD_FOOTER_SIZE: usize = 511;

/// The footer's checksum field.
const FOOTER_CHECKSUM_OFFSET: usize = 64;

/// The dynamic disk header cookie, size and checksum field.
const DYNAMIC_COOKIE: &[u8; 8] = b"cxsparse";
const DYNAMIC_HEADER_SIZE: u64 = 1024;
const DYNAMIC_CHECKSUM_OFFSET: usize = 36;

/// `Disk Type` values.
const DISK_FIXED: u32 = 2;
const DISK_DYNAMIC: u32 = 3;
const DISK_DIFFERENCING: u32 = 4;

/// File format and dynamic header versions: major version 1
/// (`0x00010000`).
const VERSION_MAJOR: u32 = 1;

/// An unused BAT entry.
const BAT_UNUSED: u32 = 0xffff_ffff;

/// BAT entries are 32-bit sector offsets.
const BAT_ENTRY_SIZE: u64 = 4;

/// The dynamic header's parent fields: unique ID (16) at 40 and the
/// Unicode name (512, UTF-16 big-endian as `VirtualBox` writes it) at 64.
const PARENT_ID_OFFSET: usize = 40;
const PARENT_NAME_OFFSET: usize = 64;
const PARENT_NAME_SIZE: usize = 512;

/// The footer's saved-state flag.
const SAVED_STATE_OFFSET: usize = 84;

const TRANSFORM: &str = "VHD blocks";

/// One's complement of the byte sum, with the 4-byte checksum field at
/// `checksum_at` counted as zero.
fn checksum(bytes: &[u8], checksum_at: usize) -> u32 {
    let sum = bytes
        .iter()
        .enumerate()
        .filter(|&(i, _)| !(checksum_at..checksum_at + 4).contains(&i))
        .fold(0u32, |sum, (_, &b)| sum.wrapping_add(u32::from(b)));
    !sum
}

/// Is this a VHD: the footer copy's cookie at offset 0, or a footer with
/// a valid checksum at the end that describes this file? A file that only
/// ends with a VHD footer may hold a VHD as its last member, so the footer
/// must also say where the disk is: a fixed disk's current size is every
/// byte before the footer ("the size of the entire file is the size of the
/// hard disk ... plus the size of the footer"), and a dynamic disk's data
/// offset locates its `cxsparse` header.
pub(super) fn is_present(data: &[u8]) -> bool {
    if data.starts_with(COOKIE) {
        return true;
    }
    end_footer(data).is_some_and(|f| match f.disk_type {
        DISK_FIXED => f.current_size == f.offset as u64,
        _ => range(
            data,
            f.data_offset,
            DYNAMIC_COOKIE.len() as u64,
            "VHD dynamic disk header",
        )
        .is_ok_and(|cookie| cookie == DYNAMIC_COOKIE),
    })
}

/// The hard disk footer fields this parser uses.
#[derive(Debug, Clone)]
struct Footer {
    /// File offset of the footer.
    offset: usize,
    /// Footer size: 512, or 511 for an old footer.
    size: usize,
    data_offset: u64,
    creator_app: [u8; 4],
    creator_version: u32,
    creator_os: [u8; 4],
    /// Guest-visible size in bytes.
    current_size: u64,
    disk_type: u32,
    saved_state: bool,
}

/// Footer at `offset`: cookie (8), features, version, data offset (8),
/// time stamp, creator application, version and host OS, original and
/// current size (8 each), geometry, disk type, checksum, unique ID (16)
/// and the saved-state flag.
fn footer(bytes: &[u8], offset: usize) -> Result<Footer> {
    if bytes.get(..COOKIE.len()) != Some(COOKIE.as_slice()) {
        return Err(error(format!("Missing VHD footer cookie at 0x{offset:X}")));
    }
    let stored = be_u32(bytes, FOOTER_CHECKSUM_OFFSET)?;
    if checksum(bytes, FOOTER_CHECKSUM_OFFSET) != stored {
        return Err(error(format!(
            "Invalid VHD footer checksum at 0x{offset:X}"
        )));
    }
    let version = be_u32(bytes, 12)?;
    if version >> 16 != VERSION_MAJOR {
        return Err(error(format!(
            "Unsupported VHD file format version 0x{version:08X}"
        )));
    }
    let disk_type = be_u32(bytes, 60)?;
    if !matches!(disk_type, DISK_FIXED | DISK_DYNAMIC | DISK_DIFFERENCING) {
        return Err(error(format!("Unsupported VHD disk type {disk_type}")));
    }
    Ok(Footer {
        offset,
        size: bytes.len(),
        data_offset: be_u64(bytes, 16)?,
        creator_app: array(bytes, 28)?,
        creator_version: be_u32(bytes, 32)?,
        creator_os: array(bytes, 36)?,
        current_size: be_u64(bytes, 48)?,
        disk_type,
        saved_state: slice(bytes, SAVED_STATE_OFFSET, 1, "VHD footer")?[0] != 0,
    })
}

/// The footer at the end of the file: the last 512 bytes, or the last 511
/// of an old image, with the cookie and a valid checksum.
fn end_footer(data: &[u8]) -> Option<Footer> {
    [FOOTER_SIZE, OLD_FOOTER_SIZE].into_iter().find_map(|size| {
        let offset = data.len().checked_sub(size)?;
        footer(&data[offset..], offset).ok()
    })
}

/// The footer copy at offset 0 of a dynamic or differencing disk.
fn copy_footer(data: &[u8]) -> Result<Footer> {
    footer(slice(data, 0, FOOTER_SIZE, "VHD footer copy")?, 0)
}

/// Pick the footer to use: the one at the end of the file, else the copy
/// at offset 0 (the specification's fallback when the footer's checksum
/// fails). Notes say which was used when they differ.
fn choose_footer(data: &[u8], notes: &mut Vec<String>) -> Result<Footer> {
    match (end_footer(data), copy_footer(data)) {
        (Some(end), Ok(copy)) if end.disk_type == DISK_FIXED || same_footer(data, &end, &copy) => {
            Ok(end)
        }
        (Some(end), Ok(_)) => {
            notes.push(
                "The footer copy at 0x0 differs from the footer at the end; the footer is used"
                    .into(),
            );
            Ok(end)
        }
        (Some(end), Err(_)) if end.disk_type == DISK_FIXED => Ok(end),
        (Some(end), Err(_)) => {
            notes.push(
                "The footer copy at 0x0 is missing or damaged; the footer at the end is used"
                    .into(),
            );
            Ok(end)
        }
        (None, Ok(copy)) if copy.disk_type == DISK_FIXED => Err(error(
            "Invalid VHD: a fixed disk footer at 0x0 and no footer at the end of the file",
        )),
        (None, Ok(copy)) => {
            notes.push(
                "The footer at the end of the file is missing or damaged; the copy at 0x0 is used"
                    .into(),
            );
            Ok(copy)
        }
        (None, Err(e)) => Err(e),
    }
}

/// Whether the footer copy holds the same bytes as the footer.
fn same_footer(data: &[u8], end: &Footer, copy: &Footer) -> bool {
    data.get(end.offset..end.offset + end.size) == data.get(copy.offset..copy.offset + end.size)
}

/// Parse a VHD image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let mut notes = Vec::new();
    let f = choose_footer(data, &mut notes)?;
    let kind = match f.disk_type {
        DISK_FIXED => "fixed",
        DISK_DYNAMIC => "dynamic",
        _ => "differencing",
    };
    let mut c = container_for(data, Layout::Vhd, format!("VHD {kind}"));
    c.notes.push(format!(
        "VHD {kind} disk; {} current size; created by {} {}.{} on {}{}",
        size_text(f.current_size),
        byte_text(&f.creator_app).trim_end(),
        f.creator_version >> 16,
        f.creator_version & 0xffff,
        byte_text(&f.creator_os).trim_end(),
        if f.size == OLD_FOOTER_SIZE {
            "; 511-byte footer (before Virtual PC 2004)"
        } else {
            ""
        }
    ));
    c.notes.append(&mut notes);
    if f.saved_state {
        c.notes
            .push("The disk is marked as in a saved state".into());
    }
    c.push_metadata("vdisk_vhd_disk_type", "Disk type", kind);
    c.push_metadata(
        "vdisk_vhd_creator",
        "Creator application",
        byte_text(&f.creator_app),
    );
    if f.disk_type == DISK_FIXED {
        if f.current_size != f.offset as u64 {
            c.notes.push(format!(
                "The footer's current size is {} B, but {} B are stored before the footer; the \
                 stored bytes are the guest disk",
                f.current_size, f.offset
            ));
        }
        let guest = Guest::flat(data, 0, f.offset, f.current_size);
        guest.finish(&mut c, TRANSFORM, None)?;
        return Ok(c);
    }
    let header = dynamic_header(data, &f)?;
    c.notes.push(format!(
        "Dynamic disk header at 0x{:X}: {} blocks, {} at 0x{:X}",
        f.data_offset,
        size_text(u64::from(header.block_size)),
        counted(
            u64::from(header.max_table_entries),
            "BAT entry",
            "BAT entries"
        ),
        header.table_offset
    ));
    c.push_metadata(
        "vdisk_vhd_block_size",
        "Block size (B)",
        u64::from(header.block_size),
    );
    let parent = (f.disk_type == DISK_DIFFERENCING).then(|| {
        let reference = format!("{} (unique ID {})", header.parent_name, header.parent_id);
        c.notes
            .push(format!("Differencing disk of the parent {reference}"));
        Parent {
            role: "parent disk",
            reference,
        }
    });
    let mut guest = Guest::new(data, f.current_size);
    map_blocks(data, &header, parent.is_some(), &mut guest)?;
    guest.finish(&mut c, TRANSFORM, parent.as_ref())?;
    Ok(c)
}

/// The dynamic disk header fields this parser uses.
struct DynamicHeader {
    table_offset: u64,
    max_table_entries: u32,
    /// Data bytes per block, without the sector bitmap.
    block_size: u32,
    parent_id: String,
    parent_name: String,
}

impl DynamicHeader {
    /// The sector bitmap: one bit per sector, padded to a sector.
    fn bitmap_size(&self) -> u64 {
        let sectors = u64::from(self.block_size) / SECTOR_SIZE;
        div_ceil(div_ceil(sectors, 8), SECTOR_SIZE) * SECTOR_SIZE
    }
}

/// Dynamic disk header at the footer's data offset: cookie (8), data
/// offset (8), table offset (8), header version, max table entries, block
/// size, checksum, parent unique ID (16), parent time stamp, reserved,
/// parent Unicode name (512), eight parent locators (24 each), reserved.
/// The BAT must fit in the file and cover the disk.
fn dynamic_header(data: &[u8], f: &Footer) -> Result<DynamicHeader> {
    let bytes = range(
        data,
        f.data_offset,
        DYNAMIC_HEADER_SIZE,
        "VHD dynamic disk header",
    )?;
    if &bytes[..DYNAMIC_COOKIE.len()] != DYNAMIC_COOKIE {
        return Err(error(format!(
            "Missing VHD dynamic disk header cookie at 0x{:X}",
            f.data_offset
        )));
    }
    if checksum(bytes, DYNAMIC_CHECKSUM_OFFSET) != be_u32(bytes, DYNAMIC_CHECKSUM_OFFSET)? {
        return Err(error(format!(
            "Invalid VHD dynamic disk header checksum at 0x{:X}",
            f.data_offset
        )));
    }
    let version = be_u32(bytes, 24)?;
    if version >> 16 != VERSION_MAJOR {
        return Err(error(format!(
            "Unsupported VHD dynamic disk header version 0x{version:08X}"
        )));
    }
    let block_size = be_u32(bytes, 32)?;
    if !block_size.is_power_of_two() || u64::from(block_size) < SECTOR_SIZE {
        return Err(error(format!("Invalid VHD block size {block_size} B")));
    }
    let header = DynamicHeader {
        table_offset: be_u64(bytes, 16)?,
        max_table_entries: be_u32(bytes, 28)?,
        block_size,
        parent_id: uuid_text(array(bytes, PARENT_ID_OFFSET)?),
        parent_name: utf16_text(
            slice(
                bytes,
                PARENT_NAME_OFFSET,
                PARENT_NAME_SIZE,
                "VHD parent name",
            )?,
            false,
        ),
    };
    range(
        data,
        header.table_offset,
        u64::from(header.max_table_entries) * BAT_ENTRY_SIZE,
        "VHD block allocation table",
    )?;
    if u64::from(header.max_table_entries) * u64::from(block_size) < f.current_size {
        return Err(error(format!(
            "Invalid VHD block allocation table: {} entries of {} cover less than the {} disk",
            header.max_table_entries,
            size_text(u64::from(block_size)),
            size_text(f.current_size)
        )));
    }
    Ok(header)
}

/// Map every block in the analyzed range. A dynamic disk's block is its
/// data area: sectors whose bitmap bit is clear are stored as zeros. In a
/// differencing disk (`has_parent`) a clear bit means the parent holds the
/// sector; the bitmap is read most significant bit first, as `VirtualBox`'s
/// `vhdBlockBitmapSectorContainsData` reads it.
fn map_blocks<'a>(
    data: &'a [u8],
    header: &DynamicHeader,
    has_parent: bool,
    guest: &mut Guest<'a>,
) -> Result<()> {
    let block_size = u64::from(header.block_size);
    let bitmap_size = header.bitmap_size();
    for block in 0..guest.block_count(block_size) {
        let at = header.table_offset + block * BAT_ENTRY_SIZE;
        let entry = be_u32(
            range(data, at, BAT_ENTRY_SIZE, "VHD block allocation table")?,
            0,
        )?;
        if entry == BAT_UNUSED {
            if has_parent {
                guest.parent(block_size);
            } else {
                guest.zero(block_size);
            }
            continue;
        }
        let start = u64::from(entry) * SECTOR_SIZE;
        let block_data = start + bitmap_size;
        if !has_parent {
            guest.stored(block_data, block_size, "VHD data block")?;
            continue;
        }
        let bitmap = range(data, start, bitmap_size, "VHD sector bitmap")?;
        let sectors = guest.block_count(SECTOR_SIZE) - block * (block_size / SECTOR_SIZE);
        for sector in 0..sectors.min(block_size / SECTOR_SIZE) {
            let byte = bitmap[usize::try_from(sector / 8).expect("inside the bitmap")];
            let present = byte & (0x80 >> (sector % 8)) != 0;
            if present {
                let offset = block_data + sector * SECTOR_SIZE;
                guest.stored(offset, SECTOR_SIZE, "VHD data sector")?;
            } else {
                guest.parent(SECTOR_SIZE);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_skips_its_own_field() {
        let mut bytes = [0u8; 16];
        bytes[0] = 1;
        bytes[1] = 2;
        bytes[8..12].copy_from_slice(&[0xff; 4]);
        assert_eq!(checksum(&bytes, 8), !3);
    }

    #[test]
    fn bitmaps_round_up_to_a_sector() {
        let header = |block_size| DynamicHeader {
            table_offset: 0,
            max_table_entries: 1,
            block_size,
            parent_id: String::new(),
            parent_name: String::new(),
        };
        assert_eq!(header(2 << 20).bitmap_size(), 512);
        assert_eq!(header(512).bitmap_size(), 512);
        assert_eq!(header(4 << 20).bitmap_size(), 1024);
    }
}
