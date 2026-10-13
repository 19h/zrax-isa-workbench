//! `GameCube` and Wii CISO images (Dolphin `CISOBlob.h`, `CISOBlob.cpp`;
//! Wiimms ISO Tools `lib-ciso.h`, `lib-ciso.c`).
//!
//! A 0x8000-byte header: the magic `CISO`, the block size (little-endian,
//! "not network byte order") and a map of 0x7FF8 bytes, one per disc
//! block: 0 unused, 1 used, anything else invalid (`SetupCISO`). The used
//! blocks follow the header in map order, so the k-th used block is stored
//! at `0x8000 + k * block_size`. Unused blocks read as zeros
//! (`CISOFileReader::Read`). Nothing is compressed or checksummed.

use super::*;

/// The magic at 0 (`CISO_MAGIC`).
const MAGIC: &[u8; 4] = b"CISO";

/// Block size field and the start of the map.
const BLOCK_SIZE: usize = 0x04;
const MAP_OFFSET: usize = 0x08;

/// `CISO_HEADER_SIZE`: the header, and where the first used block starts.
const HEADER_SIZE: usize = 0x8000;

/// Map bytes (`CISO_MAP_SIZE`).
const MAP_SIZE: usize = HEADER_SIZE - MAP_OFFSET;

/// Map values (`CISOHeader::map`: "0=unused, 1=used, others=invalid").
const BLOCK_UNUSED: u8 = 0;
const BLOCK_USED: u8 = 1;

/// wit `CISO_MIN_BLOCK_SIZE` (`WII_SECTOR_SIZE`): `SetupCISO` accepts
/// block sizes that are nonzero multiples of it.
const BLOCK_ALIGNMENT: u32 = 0x8000;

/// The shortest prefix detection reads: the magic, the block size and the
/// first 16 map bytes, which cover a whole PSP CSO header.
const DETECT_SIZE: usize = 0x18;

/// Transform name of the decoded disc.
const TRANSFORM: &str = "CISO";

/// Whether `block_size` is one `SetupCISO` accepts.
fn is_valid_block_size(block_size: u32) -> bool {
    block_size != 0 && block_size % BLOCK_ALIGNMENT == 0
}

/// The index of the first map byte that is neither 0 nor 1.
fn first_invalid_entry(map: &[u8]) -> Option<usize> {
    map.iter()
        .position(|b| !matches!(*b, BLOCK_UNUSED | BLOCK_USED))
}

/// Strong recognition: `CISO`, a block size that is a nonzero multiple of
/// 32 KiB, and 0 or 1 in every map byte the input holds (up to 0x8000).
/// A PSP CSO also starts with `CISO`, but it has its header size (0 or
/// 0x18) where the block size would be, and its index at 0x18 holds file
/// offsets past 0x18, which are not all 0 and 1 bytes.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if data.len() < DETECT_SIZE || !data.starts_with(MAGIC) {
        return None;
    }
    let block_size = le_u32(data, BLOCK_SIZE, "CISO header").ok()?;
    let map = &data[MAP_OFFSET..data.len().min(HEADER_SIZE)];
    (is_valid_block_size(block_size) && first_invalid_entry(map).is_none()).then_some(Layout::Ciso)
}

/// Parse a CISO image: the header and map, and the disc as one child.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(MAGIC) {
        return Err(error("Missing CISO magic at 0x0"));
    }
    let block_size = le_u32(data, BLOCK_SIZE, "CISO header")?;
    if !is_valid_block_size(block_size) {
        return Err(error(format!(
            "Invalid CISO block size {block_size} B at 0x{BLOCK_SIZE:X}: not a nonzero multiple of 32 KiB"
        )));
    }
    if data.len() < HEADER_SIZE {
        return Err(error(format!(
            "Truncated CISO header: {} B of 0x{HEADER_SIZE:X} B",
            data.len()
        )));
    }
    let map = &data[MAP_OFFSET..HEADER_SIZE];
    if let Some(index) = first_invalid_entry(map) {
        return Err(error(format!(
            "Invalid CISO map entry 0x{index:X} at 0x{:X}: 0x{:02X} (0 unused, 1 used)",
            MAP_OFFSET + index,
            map[index]
        )));
    }
    // Every entry is 0 or 1, so their sum counts the used blocks.
    let used: u64 = map.iter().map(|b| u64::from(*b)).sum();
    let block_text = size_text(block_size as usize);
    let block_size = u64::from(block_size);
    let mut c = Container::new(FileFormat::Ciso, Layout::Ciso.label(), "ciso");
    let stored_end = HEADER_SIZE as u64 + used * block_size;
    check_extent(&mut c, data, stored_end, "the used CISO blocks")?;
    push_metadata(&mut c, block_size, used);
    // wit's `max_virt_off`: the disc ends with its last used block. Dolphin
    // reports the whole map (0x7FF8 blocks) as an upper bound.
    let Some(last) = map.iter().rposition(|b| *b == BLOCK_USED) else {
        c.notes.push(format!(
            "CISO: block size {block_text}; no used blocks, so there is no disc to decode"
        ));
        push_no_isa_note(&mut c, "CISO");
        return Ok(c);
    };
    let disc_size = (last as u64 + 1) * block_size;
    c.notes.push(format!(
        "CISO: block size {block_text}; {used} of {MAP_SIZE} map entries used; disc size {disc_size} B, to the end of the last used block; unused blocks read as zeros"
    ));
    c.push_metadata("ciso_disc_size", "Disc size (B)", disc_size);
    let disc = decode(data, map, block_size, disc_size)?;
    let stored = StoredSpan {
        offset: HEADER_SIZE,
        size: usize::try_from(used * block_size)
            .unwrap_or(usize::MAX)
            .min(data.len() - HEADER_SIZE),
    };
    push_disc(&mut c, "Disc image".into(), disc, stored, TRANSFORM);
    push_no_isa_note(&mut c, "CISO");
    Ok(c)
}

fn push_metadata(c: &mut Container<'_>, block_size: u64, used: u64) {
    c.push_metadata("ciso_block_size", "Block size (B)", block_size);
    c.push_metadata("ciso_used_blocks", "Used blocks", used);
}

/// Copy the used blocks the disc prefix covers; each must lie in the file.
fn decode(data: &[u8], map: &[u8], block_size: u64, disc_size: u64) -> Result<Disc> {
    let mut disc = Disc::new(disc_size);
    let mut stored_index = 0u64;
    let needed = usize::try_from(disc.blocks(block_size)).expect("the map has 0x7FF8 entries");
    for (i, entry) in map.iter().enumerate().take(needed) {
        if *entry != BLOCK_USED {
            continue;
        }
        let at = HEADER_SIZE as u64 + stored_index * block_size;
        stored_index += 1;
        let out = disc.block_mut(i as u64, block_size);
        let stored = range(data, at, out.len() as u64).ok_or_else(|| {
            error(format!(
                "Truncated CISO block 0x{i:X} (stored block {}) at 0x{at:X} + {} B: it lies outside the file",
                stored_index - 1,
                out.len()
            ))
        })?;
        out.copy_from_slice(stored);
    }
    Ok(disc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(block_size: u32, map: &[u8]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&block_size.to_le_bytes());
        bytes.extend_from_slice(map);
        bytes
    }

    #[test]
    fn detection_needs_an_aligned_block_size_and_a_zero_one_map() {
        assert_eq!(detect(&header(0x20_0000, &[1; 16])), Some(Layout::Ciso));
        assert_eq!(
            detect(&header(
                0x8000,
                &[0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
            )),
            Some(Layout::Ciso)
        );
        assert_eq!(detect(&header(0x4000, &[1; 16])), None);
        assert_eq!(detect(&header(0, &[1; 16])), None);
        assert_eq!(detect(&header(0x8000, &[2; 16])), None);
        assert_eq!(detect(&header(0x8000, &[1; 15])), None);
        // A PSP CSO header: header size 0x18, then the uncompressed size.
        assert_eq!(
            detect(&header(
                0x18,
                &[0, 0, 0x10, 0, 0, 0, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0]
            )),
            None
        );
    }
}
