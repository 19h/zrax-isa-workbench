//! WBFS images: a Wii Backup File System partition in a file (Wiimms ISO
//! Tools `libwbfs/file-formats.h`, `libwbfs/libwbfs.h`,
//! `libwbfs/libwbfs.c`, `wbfs-interface.c`; Dolphin `WbfsBlob.h`,
//! `WbfsBlob.cpp`).
//!
//! Hd sector 0 holds `wbfs_head_t`: the magic `WBFS`, the partition size
//! in hd sectors (big-endian), log2 of the hd sector size and of the WBFS
//! sector size, an informative version, and from 0x0C to the end of the hd
//! sector the disc table, one byte per slot (0 free). WBFS sector 0 holds
//! the head, one disc info per slot and the free-block table (the layout
//! comment in `libwbfs.h`). The disc info of slot `i` starts at hd sector
//! `1 + i * disc_info_sz / hd_sec_sz` (`wbfs_open_disc_by_slot`): a copy of
//! the first 0x100 bytes of the disc header, then one big-endian WBFS
//! sector number per disc block (`wlba_table`), 0 for a block that is not
//! allocated (`wbfs_add_disc`). Block `j` holds the disc bytes from `j *
//! wbfs_sec_sz`. Nothing is compressed or checksummed.

use super::*;
use crate::formats::container::{MAX_COMPONENTS, MAX_EXTRACTED};

/// The magic at 0 (`WBFS_MAGIC`).
const MAGIC: &[u8; 4] = b"WBFS";

/// `wbfs_head_t` field offsets.
const HD_SECTORS: usize = 0x04;
const HD_SECTOR_SHIFT: usize = 0x08;
const WBFS_SECTOR_SHIFT: usize = 0x09;
const VERSION: usize = 0x0A;
const DISC_TABLE: usize = 0x0C;

/// Hd sector sizes accepted, as shifts: from 512 B (wit `HD_SECTOR_SIZE`,
/// the size libwbfs reads the head with by default) to 32 KiB, because the
/// geometry divides the Wii sector size by the hd sector size
/// (`wbfs_calc_geometry`).
const MIN_HD_SECTOR_SHIFT: u8 = 9;
const MAX_HD_SECTOR_SHIFT: u8 = WII_SECTOR_SHIFT;

/// WBFS sector sizes accepted, as shifts: at least a Wii sector (Dolphin
/// `ReadHeader` rejects smaller ones) and at most 2 GiB (libwbfs keeps the
/// size in a `u32`).
const MIN_WBFS_SECTOR_SHIFT: u8 = WII_SECTOR_SHIFT;
const MAX_WBFS_SECTOR_SHIFT: u8 = 31;

/// `WII_SECTOR_SIZE_SHIFT`: Wii sectors are 0x8000 B.
const WII_SECTOR_SHIFT: u8 = 15;

/// `WII_MAX_SECTORS`: the Wii sectors of a dual-layer disc.
const WII_MAX_SECTORS: u64 = 143_432 * 2;

/// `WII_MAX_DISC_SIZE`: the largest disc a slot can address.
const WII_MAX_DISC_SIZE: u64 = WII_MAX_SECTORS << WII_SECTOR_SHIFT;

/// `n_wbfs_sec` is 16 bits in libwbfs (`WBFS_MAX_SECTORS - 1`).
const MAX_WBFS_SECTORS: u64 = 0xFFFF;

/// The disc header copy at the start of a disc info (`dhead`), and the game
/// ID (game code and maker code) at its start.
const DISC_HEADER_COPY_SIZE: usize = 0x100;
const GAME_ID_SIZE: usize = 6;

/// One `wlba_table` entry.
const WLBA_SIZE: usize = 2;

/// Transform name of a decoded disc.
const TRANSFORM: &str = "WBFS";

/// The partition geometry, as `wbfs_calc_geometry` derives it from the
/// head.
struct Geometry {
    /// Partition size in hd sectors.
    hd_sectors: u32,
    /// log2 of the hd sector size.
    hd_shift: u8,
    /// log2 of the WBFS sector size.
    wbfs_shift: u8,
    /// Hd sector size in bytes.
    hd_sector_size: u64,
    /// WBFS sector size in bytes.
    wbfs_sector_size: u64,
    /// WBFS sectors in the partition (`n_wbfs_sec`, with the correct Wii
    /// sector count); allocated sectors are below it.
    wbfs_sectors: u64,
    /// Blocks per disc (`n_wbfs_sec_per_disc`): `WII_MAX_SECTORS` shifted
    /// down, rounded down as libwbfs does (Dolphin rounds up).
    blocks_per_disc: usize,
    /// Size of one disc info (`disc_info_sz`), hd-sector aligned.
    disc_info_size: u64,
    /// Informative version byte.
    version: u8,
}

/// Whether the two shifts are in the accepted ranges. Hd sectors are at
/// most a Wii sector and WBFS sectors at least one, so a WBFS sector holds
/// whole hd sectors.
fn is_valid_shifts(hd_shift: u8, wbfs_shift: u8) -> bool {
    (MIN_HD_SECTOR_SHIFT..=MAX_HD_SECTOR_SHIFT).contains(&hd_shift)
        && (MIN_WBFS_SECTOR_SHIFT..=MAX_WBFS_SECTOR_SHIFT).contains(&wbfs_shift)
}

/// Strong recognition: `WBFS`, a nonzero partition size and sector shifts
/// in the accepted ranges, so the 32-bit magic alone is not enough.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if !data.starts_with(MAGIC) {
        return None;
    }
    let hd_sectors = be_u32(data, HD_SECTORS, "WBFS header").ok()?;
    let hd_shift = *data.get(HD_SECTOR_SHIFT)?;
    let wbfs_shift = *data.get(WBFS_SECTOR_SHIFT)?;
    (hd_sectors != 0 && is_valid_shifts(hd_shift, wbfs_shift)).then_some(Layout::Wbfs)
}

/// The geometry from the head; the shifts must be valid.
fn geometry(data: &[u8]) -> Result<Geometry> {
    let head = slice(data, 0, DISC_TABLE, "WBFS header")?;
    if !head.starts_with(MAGIC) {
        return Err(error("Missing WBFS magic at 0x0"));
    }
    let hd_sectors = be_u32(head, HD_SECTORS, "WBFS header")?;
    let hd_shift = head[HD_SECTOR_SHIFT];
    let wbfs_shift = head[WBFS_SECTOR_SHIFT];
    if !is_valid_shifts(hd_shift, wbfs_shift) {
        return Err(error(format!(
            "Invalid WBFS sector shifts at 0x{HD_SECTOR_SHIFT:X}: hd sector 2^{hd_shift} B, WBFS sector 2^{wbfs_shift} B (accepted: hd 2^{MIN_HD_SECTOR_SHIFT} to 2^{MAX_HD_SECTOR_SHIFT} B, WBFS 2^{MIN_WBFS_SECTOR_SHIFT} to 2^{MAX_WBFS_SECTOR_SHIFT} B)"
        )));
    }
    if hd_sectors == 0 {
        return Err(error(format!(
            "Invalid WBFS partition size at 0x{HD_SECTORS:X}: 0 hd sectors"
        )));
    }
    let hd_sector_size = 1u64 << hd_shift;
    let wii_sector_shift = wbfs_shift - WII_SECTOR_SHIFT;
    let wii_sectors = u64::from(hd_sectors) >> (WII_SECTOR_SHIFT - hd_shift);
    let blocks_per_disc = usize::try_from(WII_MAX_SECTORS >> wii_sector_shift)
        .expect("at most 286864 blocks per disc");
    let disc_info_size = align_up(
        (DISC_HEADER_COPY_SIZE + blocks_per_disc * WLBA_SIZE) as u64,
        hd_sector_size,
    )
    .expect("a disc info is at most 574 KiB");
    Ok(Geometry {
        hd_sectors,
        hd_shift,
        wbfs_shift,
        hd_sector_size,
        wbfs_sector_size: 1u64 << wbfs_shift,
        wbfs_sectors: (wii_sectors >> wii_sector_shift).min(MAX_WBFS_SECTORS),
        blocks_per_disc,
        disc_info_size,
        version: head[VERSION],
    })
}

/// What happened to the used slots that were not decoded.
#[derive(Default)]
struct Skipped {
    /// Slots whose disc info would lie outside WBFS sector 0.
    outside_sector_0: Vec<usize>,
    /// Slots with no allocated block.
    empty: Vec<usize>,
    /// Discs not decoded once [`MAX_COMPONENTS`] were listed.
    over_component_limit: u64,
    /// Discs not decoded because of [`MAX_EXTRACTED`].
    over_extraction_limit: u64,
}

/// Parse a WBFS image: the head, every used slot's disc info, and one
/// decoded disc per slot.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let geometry = geometry(data)?;
    let head = slice(
        data,
        0,
        usize::try_from(geometry.hd_sector_size).expect("at most 32 KiB"),
        "WBFS header sector",
    )?;
    let disc_table = &head[DISC_TABLE..];
    let used: Vec<usize> = disc_table
        .iter()
        .enumerate()
        .filter(|(_, slot)| **slot != 0)
        .map(|(i, _)| i)
        .collect();
    let mut c = Container::new(FileFormat::Wbfs, Layout::Wbfs.label(), "wbfs");
    let partition_size = u64::from(geometry.hd_sectors) * geometry.hd_sector_size;
    c.notes.push(format!(
        "WBFS version {}: {} hd sectors of {} ({partition_size} B); WBFS sector size {}; {} WBFS sectors; {} of {} disc slots used",
        geometry.version,
        geometry.hd_sectors,
        size_text(1 << geometry.hd_shift),
        size_text(1 << geometry.wbfs_shift),
        geometry.wbfs_sectors,
        used.len(),
        disc_table.len()
    ));
    check_extent(&mut c, data, partition_size, "the WBFS partition")?;
    push_metadata(&mut c, &geometry, used.len());
    let mut skipped = Skipped::default();
    let mut extracted = 0usize;
    for slot in used {
        if c.children.len() >= MAX_COMPONENTS {
            skipped.over_component_limit += 1;
            continue;
        }
        let info_offset = geometry.hd_sector_size + slot as u64 * geometry.disc_info_size;
        if info_offset + geometry.disc_info_size > geometry.wbfs_sector_size {
            skipped.outside_sector_0.push(slot);
            continue;
        }
        let info = disc_info(data, &geometry, slot, info_offset)?;
        let Some(last) = info.wlba.iter().rposition(|sector| *sector != 0) else {
            skipped.empty.push(slot);
            continue;
        };
        let disc_size = ((last as u64 + 1) * geometry.wbfs_sector_size).min(WII_MAX_DISC_SIZE);
        let prefix = usize::try_from(disc_size).map_or(MAX_PAYLOAD, |size| size.min(MAX_PAYLOAD));
        match extracted.checked_add(prefix) {
            Some(total) if total <= MAX_EXTRACTED => extracted = total,
            _ => {
                skipped.over_extraction_limit += 1;
                continue;
            }
        }
        let label = format!("Disc slot {slot} ({})", info.game_id);
        let allocated = info.wlba.iter().filter(|sector| **sector != 0).count();
        c.notes.push(format!(
            "{label}: {allocated} of {} blocks allocated; disc size {disc_size} B, to the end of the last allocated block; unallocated blocks read as zeros",
            geometry.blocks_per_disc
        ));
        let disc = decode(data, &geometry, slot, &info.wlba, disc_size)?;
        let stored = first_run(&geometry, &info.wlba, data.len());
        push_disc(&mut c, label, disc, stored, TRANSFORM);
    }
    push_skipped_notes(&mut c, &skipped);
    push_no_isa_note(&mut c, "WBFS");
    Ok(c)
}

/// A slot's disc info: the game ID from the header copy and the block
/// table.
struct DiscInfo {
    game_id: String,
    /// WBFS sector of each disc block; 0 when not allocated.
    wlba: Vec<u16>,
}

/// Read and validate the disc info of `slot` at `offset`: every allocated
/// block must name a WBFS sector of the partition, past the head sector
/// (wit's check reports others as "invalid WBFS block").
fn disc_info(data: &[u8], geometry: &Geometry, slot: usize, offset: u64) -> Result<DiscInfo> {
    let offset = usize::try_from(offset).expect("inside WBFS sector 0, at most 2 GiB");
    let size = DISC_HEADER_COPY_SIZE + geometry.blocks_per_disc * WLBA_SIZE;
    let what = format!("WBFS disc info of slot {slot}");
    let info = slice(data, offset, size, &what)?;
    let table = &info[DISC_HEADER_COPY_SIZE..];
    let mut wlba = Vec::with_capacity(geometry.blocks_per_disc);
    for (block, entry) in table.chunks_exact(WLBA_SIZE).enumerate() {
        let sector = be_u16(entry, 0, &what)?;
        if sector != 0 && u64::from(sector) >= geometry.wbfs_sectors {
            return Err(error(format!(
                "Invalid WBFS disc slot {slot} block {block} at 0x{:X}: WBFS sector {sector} is past the {} sectors of the partition",
                offset + DISC_HEADER_COPY_SIZE + block * WLBA_SIZE,
                geometry.wbfs_sectors
            )));
        }
        wlba.push(sector);
    }
    Ok(DiscInfo {
        game_id: ascii_text(&info[..GAME_ID_SIZE]),
        wlba,
    })
}

/// Copy the allocated blocks the disc prefix covers; each must lie in the
/// file.
fn decode(
    data: &[u8],
    geometry: &Geometry,
    slot: usize,
    wlba: &[u16],
    disc_size: u64,
) -> Result<Disc> {
    let sector_size = geometry.wbfs_sector_size;
    let mut disc = Disc::new(disc_size);
    let needed = usize::try_from(disc.blocks(sector_size)).expect("at most one block per byte");
    for (block, sector) in wlba.iter().enumerate().take(needed) {
        if *sector == 0 {
            continue;
        }
        let at = u64::from(*sector) * sector_size;
        let out = disc.block_mut(block as u64, sector_size);
        let stored = range(data, at, out.len() as u64).ok_or_else(|| {
            error(format!(
                "Truncated WBFS disc slot {slot} block {block} (WBFS sector {sector}) at 0x{at:X} + {} B: it lies outside the file",
                out.len()
            ))
        })?;
        out.copy_from_slice(stored);
    }
    Ok(disc)
}

/// The stored span of a disc: its first allocated block and the blocks
/// that follow it in consecutive WBFS sectors, clamped to the file.
fn first_run(geometry: &Geometry, wlba: &[u16], file_size: usize) -> StoredSpan {
    let allocated: Vec<u16> = wlba.iter().copied().filter(|s| *s != 0).collect();
    let run = allocated
        .windows(2)
        .take_while(|w| u32::from(w[1]) == u32::from(w[0]) + 1)
        .count()
        + 1;
    let first = allocated.first().map_or(0, |s| u64::from(*s));
    let offset = usize::try_from(first * geometry.wbfs_sector_size)
        .unwrap_or(usize::MAX)
        .min(file_size);
    let size = usize::try_from(run as u64 * geometry.wbfs_sector_size)
        .unwrap_or(usize::MAX)
        .min(file_size - offset);
    StoredSpan { offset, size }
}

fn push_metadata(c: &mut Container<'_>, geometry: &Geometry, used: usize) {
    c.push_metadata(
        "wbfs_hd_sector_size",
        "Hd sector size (B)",
        geometry.hd_sector_size,
    );
    c.push_metadata(
        "wbfs_hd_sectors",
        "Partition size (hd sectors)",
        u64::from(geometry.hd_sectors),
    );
    c.push_metadata(
        "wbfs_sector_size",
        "WBFS sector size (B)",
        geometry.wbfs_sector_size,
    );
    c.push_metadata("wbfs_used_slots", "Used disc slots", used as u64);
    c.push_metadata("wbfs_version", "Version", u64::from(geometry.version));
}

/// Notes on the used slots that were not decoded.
fn push_skipped_notes(c: &mut Container<'_>, skipped: &Skipped) {
    if let Some(first) = skipped.outside_sector_0.first() {
        c.notes.push(format!(
            "Not read: {} whose disc info would lie outside WBFS sector 0; first: slot {first}",
            counted(
                skipped.outside_sector_0.len() as u64,
                "used slot",
                "used slots"
            )
        ));
    }
    if let Some(first) = skipped.empty.first() {
        c.notes.push(format!(
            "No disc: {} with no allocated block; first: slot {first}",
            counted(skipped.empty.len() as u64, "used slot", "used slots")
        ));
    }
    if skipped.over_component_limit > 0 {
        c.notes.push(format!(
            "Member limit reached ({MAX_COMPONENTS} discs); not decoded: {}",
            counted(
                skipped.over_component_limit,
                "further disc",
                "further discs"
            )
        ));
    }
    if skipped.over_extraction_limit > 0 {
        c.notes.push(format!(
            "Extraction limit reached ({}); not decoded: {}",
            size_text(MAX_EXTRACTED),
            counted(skipped.over_extraction_limit, "disc", "discs")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(hd_shift: u8, wbfs_shift: u8, hd_sectors: u32) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&hd_sectors.to_be_bytes());
        bytes.extend_from_slice(&[hd_shift, wbfs_shift, 1, 0]);
        bytes
    }

    #[test]
    fn geometry_matches_libwbfs_for_a_two_mib_sector() {
        // 500 GB drive layout: 512 B hd sectors, 2 MiB WBFS sectors.
        let mut data = head(9, 21, 976_773_168);
        data.resize(512, 0);
        let g = geometry(&data).unwrap();
        assert_eq!(g.blocks_per_disc, 4482);
        assert_eq!(g.disc_info_size, 9728);
        assert_eq!(g.wbfs_sectors, MAX_WBFS_SECTORS);
        let mut small = head(9, 18, 4096);
        small.resize(512, 0);
        let g = geometry(&small).unwrap();
        assert_eq!(g.blocks_per_disc, 35_858);
        assert_eq!(g.wbfs_sectors, 8);
    }

    #[test]
    fn detection_needs_plausible_shifts() {
        assert_eq!(detect(&head(9, 21, 1)), Some(Layout::Wbfs));
        assert_eq!(detect(&head(15, 15, 1)), Some(Layout::Wbfs));
        assert_eq!(detect(&head(16, 21, 1)), None);
        assert_eq!(detect(&head(8, 21, 1)), None);
        assert_eq!(detect(&head(9, 14, 1)), None);
        assert_eq!(detect(&head(9, 32, 1)), None);
        assert_eq!(detect(&head(9, 21, 0)), None);
        assert_eq!(detect(&head(9, 21, 1)[..9]), None);
    }

    #[test]
    fn first_run_follows_consecutive_sectors() {
        let mut data = head(9, 15, 64);
        data.resize(512, 0);
        let g = geometry(&data).unwrap();
        let span = first_run(&g, &[0, 3, 4, 0, 5, 9], 1 << 20);
        assert_eq!(span.offset, 3 * 0x8000);
        assert_eq!(span.size, 3 * 0x8000);
        let clamped = first_run(&g, &[3, 4], 4 * 0x8000);
        assert_eq!(clamped.size, 0x8000);
    }
}
