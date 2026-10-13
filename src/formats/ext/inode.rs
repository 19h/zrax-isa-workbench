//! Inode records: their location in the group's inode table, the fields
//! the reader uses, `i_extra_isize`, and the inode checksum
//! (`__ext4_iget`, `ext4_inode_csum`, `ext4_isize`).

use super::*;
use crate::formats::checksum::crc32c_update;

/// Size of `i_block`: the block map, extent tree root or inline data.
pub(super) const I_BLOCK_SIZE: usize = 60;

/// `i_mode` file type bits and the types the walk handles.
const S_IFMT: u16 = 0xf000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;

/// `i_flags` bits.
pub(super) const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
pub(super) const EXT4_INDEX_FL: u32 = 0x0000_1000;
pub(super) const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
pub(super) const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;

/// Offset of `i_block`.
const I_BLOCK: usize = 0x28;

/// Offsets of the checksum fields and of `i_extra_isize`. The inode
/// checksum covers the record with both checksum halves read as zero.
const I_CHECKSUM_LO: usize = 0x7c;
const I_EXTRA_ISIZE: usize = 0x80;
const I_CHECKSUM_HI: usize = 0x82;

/// End of `i_checksum_hi`; the field exists when
/// `EXT4_GOOD_OLD_INODE_SIZE + i_extra_isize` reaches it.
const I_CHECKSUM_HI_END: usize = I_CHECKSUM_HI + 2;

impl Inode {
    fn file_type(&self) -> u16 {
        self.mode & S_IFMT
    }

    pub(super) fn is_dir(&self) -> bool {
        self.file_type() == S_IFDIR
    }

    pub(super) fn is_regular(&self) -> bool {
        self.file_type() == S_IFREG
    }

    pub(super) fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }
}

impl Filesystem<'_> {
    /// Read and check inode `number`.
    ///
    /// Record fields: 0x00 `i_mode`, 0x04 `i_size_lo`, 0x1A
    /// `i_links_count`, 0x20 `i_flags`, 0x28 `i_block` (60 bytes), 0x64
    /// `i_generation`, 0x6C `i_size_high`, 0x7C `l_i_checksum_lo`, 0x80
    /// `i_extra_isize`, 0x82 `i_checksum_hi`.
    pub(super) fn inode(&self, number: u32) -> ReadResult<Inode> {
        let raw = self.inode_record(number)?;
        let mode = le_u16(raw, 0x00)?;
        let links_count = le_u16(raw, 0x1a)?;
        if mode == 0 || links_count == 0 {
            return invalid(format!(
                "Invalid inode {number}: not in use (mode 0x{mode:04X}, {links_count} links)"
            ));
        }
        let extra_isize = self.extra_isize(raw, number)?;
        let generation = le_u32(raw, 0x64)?;
        let csum_seed = self.csum_seed.map(|seed| {
            let crc = crc32c_update(seed, &number.to_le_bytes());
            crc32c_update(crc, &generation.to_le_bytes())
        });
        if self.verify_inodes {
            let seed = csum_seed.expect("inode checksums need metadata_csum");
            verify_checksum(raw, seed, extra_isize, number)?;
        }
        let size_low = u64::from(le_u32(raw, 0x04)?);
        let is_regular = mode & S_IFMT == S_IFREG;
        let size = if is_regular || self.sb.has_incompat(INCOMPAT_LARGEDIR) {
            size_low | (u64::from(le_u32(raw, 0x6c)?) << 32)
        } else {
            size_low
        };
        let block: [u8; I_BLOCK_SIZE] = slice(raw, I_BLOCK, I_BLOCK_SIZE)?
            .try_into()
            .expect("slice has exactly 60 bytes");
        Ok(Inode {
            number,
            mode,
            size,
            flags: le_u32(raw, 0x20)?,
            block,
            csum_seed,
        })
    }

    /// The record of inode `number` in its group's inode table. Groups
    /// with descriptor checksums record which inodes were never
    /// initialized; those are refused, as their bytes are not inodes. A
    /// record past the end of a truncated filesystem's input, or of a group
    /// whose descriptor is, is absent.
    fn inode_record(&self, number: u32) -> ReadResult<&[u8]> {
        if number == 0 || number > self.sb.inodes_count {
            return invalid(format!(
                "Invalid inode number {number} (the filesystem has {} inodes)",
                self.sb.inodes_count
            ));
        }
        let group = (number - 1) / self.sb.inodes_per_group;
        let index = (number - 1) % self.sb.inodes_per_group;
        // `s_inodes_count` is the group count times `s_inodes_per_group`
        // (checked with the superblock), so `group` indexes `groups` unless
        // its descriptor lies past the end of the input.
        let Some(&desc) = self.groups.get(group as usize) else {
            return Err(Fault::Absent);
        };
        if self.sb.has_group_desc_csum() {
            let initialized = self.sb.inodes_per_group.saturating_sub(desc.itable_unused);
            if desc.flags & EXT4_BG_INODE_UNINIT != 0 || index >= initialized {
                return invalid(format!(
                    "Invalid inode {number}: uninitialized in group {group}'s inode table"
                ));
            }
        }
        let block_size = self.sb.block_size as u64;
        let inode_size = self.sb.inode_size as u64;
        let range = desc
            .inode_table
            .checked_mul(block_size)
            .and_then(|table| table.checked_add(u64::from(index) * inode_size))
            .and_then(|offset| Some(offset..offset.checked_add(inode_size)?))
            .filter(|range| range.end <= self.sb.size())
            .ok_or_else(|| {
                error(format!(
                    "Invalid inode {number}: its record is beyond the filesystem"
                ))
            })?;
        let read = self.present(range.start, range.end);
        if let Err(Fault::Absent) = read {
            self.absent_blocks
                .borrow_mut()
                .insert(range.start / block_size);
        }
        let record = read?;
        self.charge(self.sb.inode_size)?;
        Ok(record)
    }

    /// `i_extra_isize`: 0 for 128-byte records; otherwise a multiple of 4
    /// that keeps the extra fields inside the record.
    fn extra_isize(&self, raw: &[u8], number: u32) -> Result<usize> {
        if self.sb.inode_size <= EXT4_GOOD_OLD_INODE_SIZE {
            return Ok(0);
        }
        let extra_isize = usize::from(le_u16(raw, I_EXTRA_ISIZE)?);
        if EXT4_GOOD_OLD_INODE_SIZE + extra_isize > self.sb.inode_size || extra_isize % 4 != 0 {
            return Err(error(format!(
                "Invalid inode {number} i_extra_isize {extra_isize} for {} B inodes",
                self.sb.inode_size
            )));
        }
        Ok(extra_isize)
    }
}

/// Verify the inode checksum: CRC32C from the inode's seed over the
/// record with `l_i_checksum_lo` and, when the extra fields reach it,
/// `i_checksum_hi` read as zero. Without `i_checksum_hi` only the low 16
/// bits are stored.
fn verify_checksum(raw: &[u8], seed: u32, extra_isize: usize, number: u32) -> Result<()> {
    let has_high = raw.len() > EXT4_GOOD_OLD_INODE_SIZE
        && EXT4_GOOD_OLD_INODE_SIZE + extra_isize >= I_CHECKSUM_HI_END;
    let mut crc = crc32c_update(seed, slice(raw, 0, I_CHECKSUM_LO)?);
    crc = crc32c_update(crc, &[0, 0]);
    let checksummed_end = if has_high {
        crc = crc32c_update(
            crc,
            slice(raw, I_CHECKSUM_LO + 2, I_CHECKSUM_HI - I_CHECKSUM_LO - 2)?,
        );
        crc = crc32c_update(crc, &[0, 0]);
        I_CHECKSUM_HI_END
    } else {
        I_CHECKSUM_LO + 2
    };
    crc = crc32c_update(crc, raw.get(checksummed_end..).unwrap_or_default());
    let low = u32::from(le_u16(raw, I_CHECKSUM_LO)?);
    let (stored, computed) = if has_high {
        let high = u32::from(le_u16(raw, I_CHECKSUM_HI)?);
        (low | (high << 16), crc)
    } else {
        (low, crc & 0xffff)
    };
    if stored != computed {
        return Err(error(format!(
            "Invalid inode {number} checksum 0x{stored:X} (computed 0x{computed:X})"
        )));
    }
    Ok(())
}
