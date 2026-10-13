//! Block group descriptors: their location (`descriptor_loc`, with
//! `meta_bg`), the fields the reader uses, the range checks of
//! `ext4_check_descriptors` and the descriptor checksum
//! (`ext4_group_desc_csum`).

use super::*;
use crate::formats::checksum::{crc16_modbus_update, crc32c_update};

/// Offset of `bg_checksum`; the 32-byte descriptor ends after it.
const BG_CHECKSUM: usize = 0x1e;

/// Offset of the fields after `bg_checksum`, present in descriptors of at
/// least [`EXT4_MIN_DESC_SIZE_64BIT`] bytes.
const BG_HIGH_FIELDS: usize = 0x20;

/// Read the group descriptors, verify their checksums and check that their
/// bitmaps and inode tables lie in the filesystem. `data` holds the
/// filesystem, or its first bytes when the input ends inside it. Descriptor
/// blocks lie in the order of the groups they describe, so the descriptors
/// stop at the first one past the end of the input, whose block is added
/// to `absent_blocks`; the later groups are absent.
pub(super) fn parse(
    data: &[u8],
    sb: &Superblock,
    csum_seed: Option<u32>,
    absent_blocks: &RefCell<BTreeSet<u64>>,
) -> Result<Vec<GroupDesc>> {
    let group_count = u64::from(sb.group_count);
    // Each descriptor occupies its own bytes of the filesystem.
    if group_count.saturating_mul(sb.desc_size as u64) > sb.size() {
        return Err(error(format!(
            "Invalid group count {group_count}: {} B of group descriptors exceed the {} B \
             filesystem",
            group_count.saturating_mul(sb.desc_size as u64),
            sb.size()
        )));
    }
    let descriptors_per_block = (sb.block_size / sb.desc_size) as u64;
    let inode_table_blocks = inode_table_blocks(sb);
    // The descriptors present occupy bytes present.
    let present = group_count.min(data.len() as u64 / sb.desc_size as u64);
    let capacity = usize::try_from(present).expect("bounded by the input size");
    let mut groups = Vec::with_capacity(capacity);
    for group in 0..group_count {
        let block = sb.descriptor_block(group / descriptors_per_block);
        let index = usize::try_from(group % descriptors_per_block).expect("below 2^16");
        let Some(raw) = descriptor(data, sb, block, index, group)? else {
            absent_blocks.borrow_mut().insert(block);
            break;
        };
        verify_checksum(raw, sb, csum_seed, group)?;
        let desc = decode(raw, sb)?;
        check_ranges(raw, sb, &desc, inode_table_blocks, group)?;
        groups.push(desc);
    }
    Ok(groups)
}

/// Blocks of one group's inode table, as the kernel computes
/// `s_itb_per_group`.
fn inode_table_blocks(sb: &Superblock) -> u64 {
    let inodes_per_block = (sb.block_size / sb.inode_size) as u64;
    u64::from(sb.inodes_per_group) / inodes_per_block
}

/// The raw descriptor of `group`, entry `index` of descriptor block
/// `block`; `None` when it lies inside the filesystem but past the end of
/// `data`.
fn descriptor<'a>(
    data: &'a [u8],
    sb: &Superblock,
    block: u64,
    index: usize,
    group: u64,
) -> Result<Option<&'a [u8]>> {
    let range = block
        .checked_mul(sb.block_size as u64)
        .and_then(|start| start.checked_add((index * sb.desc_size) as u64))
        .and_then(|offset| Some(offset..offset.checked_add(sb.desc_size as u64)?))
        .filter(|range| range.end <= sb.size())
        .ok_or_else(|| {
            error(format!(
                "Invalid group descriptor {group} location: block 0x{block:X} is beyond the \
                 filesystem"
            ))
        })?;
    if range.end > data.len() as u64 {
        return Ok(None);
    }
    // The range lies in `data`, so it fits in usize.
    let start = usize::try_from(range.start).expect("offset is in the image");
    Ok(Some(&data[start..start + sb.desc_size]))
}

/// Descriptor fields: 0x00 `bg_block_bitmap_lo`, 0x04 `bg_inode_bitmap_lo`,
/// 0x08 `bg_inode_table_lo`, 0x12 `bg_flags`, 0x1C `bg_itable_unused_lo`;
/// with 64-byte descriptors also 0x20 `bg_block_bitmap_hi`, 0x24
/// `bg_inode_bitmap_hi`, 0x28 `bg_inode_table_hi` and 0x32
/// `bg_itable_unused_hi`.
fn decode(raw: &[u8], sb: &Superblock) -> Result<GroupDesc> {
    let wide = sb.desc_size >= EXT4_MIN_DESC_SIZE_64BIT;
    let itable_unused_high = if wide { le_u16(raw, 0x32)? } else { 0 };
    Ok(GroupDesc {
        inode_table: split_u64(raw, 0x08, wide.then_some(0x28))?,
        flags: le_u16(raw, 0x12)?,
        itable_unused: u32::from(le_u16(raw, 0x1c)?) | (u32::from(itable_unused_high) << 16),
    })
}

/// The kernel's location checks: without `flex_bg`, the block bitmap,
/// inode bitmap and inode table lie in their own group; with it, or for
/// the last group, anywhere in the filesystem after `s_first_data_block`.
fn check_ranges(
    raw: &[u8],
    sb: &Superblock,
    desc: &GroupDesc,
    inode_table_blocks: u64,
    group: u64,
) -> Result<()> {
    let wide = sb.desc_size >= EXT4_MIN_DESC_SIZE_64BIT;
    let flex_bg = sb.has_incompat(INCOMPAT_FLEX_BG);
    let first_block = if flex_bg {
        u64::from(sb.first_data_block)
    } else {
        sb.group_first_block(group)
    };
    let last_block = if flex_bg || group + 1 == u64::from(sb.group_count) {
        sb.blocks_count - 1
    } else {
        first_block + u64::from(sb.blocks_per_group) - 1
    };
    let block_bitmap = split_u64(raw, 0x00, wide.then_some(0x20))?;
    if block_bitmap < first_block || block_bitmap > last_block {
        return Err(error(format!(
            "Invalid group {group} block bitmap 0x{block_bitmap:X} outside blocks \
             0x{first_block:X}-0x{last_block:X}"
        )));
    }
    let inode_bitmap = split_u64(raw, 0x04, wide.then_some(0x24))?;
    if inode_bitmap < first_block || inode_bitmap > last_block {
        return Err(error(format!(
            "Invalid group {group} inode bitmap 0x{inode_bitmap:X} outside blocks \
             0x{first_block:X}-0x{last_block:X}"
        )));
    }
    let table_end = desc.inode_table.checked_add(inode_table_blocks);
    if desc.inode_table < first_block || table_end.map_or(true, |end| end - 1 > last_block) {
        return Err(error(format!(
            "Invalid group {group} inode table 0x{:X} + {inode_table_blocks} blocks outside \
             blocks 0x{first_block:X}-0x{last_block:X}",
            desc.inode_table
        )));
    }
    Ok(())
}

/// Verify `bg_checksum`. With `metadata_csum`: the low 16 bits of the
/// CRC32C of the group number and the descriptor, the checksum field read
/// as zero, from the metadata seed. With `gdt_csum`: CRC16 of `s_uuid`,
/// the group number and the descriptor without the checksum field, the
/// fields after it only with `64bit`. Without either, nothing is stored.
fn verify_checksum(raw: &[u8], sb: &Superblock, csum_seed: Option<u32>, group: u64) -> Result<()> {
    let le_group = u32::try_from(group)
        .expect("group count is below 2^32")
        .to_le_bytes();
    let head = slice(raw, 0, BG_CHECKSUM)?;
    let tail = raw.get(BG_HIGH_FIELDS..).unwrap_or_default();
    let computed = if let Some(seed) = csum_seed {
        let mut crc = crc32c_update(seed, &le_group);
        crc = crc32c_update(crc, head);
        crc = crc32c_update(crc, &[0, 0]);
        crc = crc32c_update(crc, tail);
        low_half(crc)
    } else if sb.has_ro_compat(RO_COMPAT_GDT_CSUM) {
        let mut crc = crc16_modbus_update(0xffff, &sb.uuid);
        crc = crc16_modbus_update(crc, &le_group);
        crc = crc16_modbus_update(crc, head);
        if sb.has_incompat(INCOMPAT_64BIT) {
            crc = crc16_modbus_update(crc, tail);
        }
        crc
    } else {
        return Ok(());
    };
    let stored = le_u16(raw, BG_CHECKSUM)?;
    if stored != computed {
        return Err(error(format!(
            "Invalid group descriptor {group} checksum 0x{stored:04X} (computed 0x{computed:04X})"
        )));
    }
    Ok(())
}
