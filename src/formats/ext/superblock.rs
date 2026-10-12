//! The primary superblock: geometry checks, checksum, checksum seed and
//! the locations of superblock backups and group descriptor blocks.

use super::*;
use crate::formats::checksum::crc32c_update;

/// Offset of `s_checksum`; the superblock checksum covers the bytes before
/// it.
const S_CHECKSUM: usize = 0x3fc;

impl Superblock {
    /// Parse the superblock at file offset 1024 and apply the kernel's
    /// checks that do not depend on the device size (`ext4_fill_super`,
    /// `ext4_handle_clustersize`, `ext4_check_geometry`).
    ///
    /// Fields: 0x00 `s_inodes_count`, 0x04 `s_blocks_count_lo`, 0x14
    /// `s_first_data_block`, 0x18 `s_log_block_size`, 0x1C
    /// `s_log_cluster_size`, 0x20 `s_blocks_per_group`, 0x24
    /// `s_clusters_per_group`, 0x28 `s_inodes_per_group`, 0x38 `s_magic`,
    /// 0x3A `s_state`, 0x48 `s_creator_os`, 0x4C `s_rev_level`, 0x54
    /// `s_first_ino`, 0x58 `s_inode_size`, 0x5C `s_feature_compat`, 0x60
    /// `s_feature_incompat`, 0x64 `s_feature_ro_compat`, 0x68 `s_uuid`,
    /// 0x78 `s_volume_name`, 0xFE `s_desc_size`, 0x104 `s_first_meta_bg`,
    /// 0x150 `s_blocks_count_hi`, 0x175 `s_checksum_type`, 0x24C
    /// `s_backup_bgs`, 0x270 `s_checksum_seed`, 0x3FC `s_checksum`.
    pub(super) fn parse(data: &[u8]) -> Result<Self> {
        let raw = slice(data, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)?;
        let magic = le_u16(raw, 0x38)?;
        if magic != EXT4_SUPER_MAGIC {
            return Err(error(format!("Invalid s_magic 0x{magic:04X}")));
        }
        let log_block_size = le_u32(raw, 0x18)?;
        if log_block_size > MAX_LOG_BLOCK_SIZE {
            return Err(error(format!(
                "Invalid s_log_block_size {log_block_size} (blocks above 64 KiB)"
            )));
        }
        let block_size = EXT4_MIN_BLOCK_SIZE << log_block_size;
        let rev_level = le_u32(raw, 0x4c)?;
        if rev_level > EXT4_DYNAMIC_REV {
            return Err(error(format!("Unsupported s_rev_level {rev_level}")));
        }
        let inode_size = inode_size(raw, rev_level, block_size)?;
        let compat = le_u32(raw, 0x5c)?;
        let incompat = le_u32(raw, 0x60)?;
        let ro_compat = le_u32(raw, 0x64)?;
        let ClusterGeometry {
            cluster_ratio,
            blocks_per_group,
        } = cluster_geometry(raw, block_size, ro_compat)?;

        let inodes_per_group = le_u32(raw, 0x28)?;
        let inodes_per_block = block_size / inode_size;
        let per_group_limit = block_size * 8;
        if (inodes_per_group as usize) < inodes_per_block
            || inodes_per_group as usize > per_group_limit
        {
            return Err(error(format!(
                "Invalid s_inodes_per_group {inodes_per_group}"
            )));
        }

        let is_64bit = incompat & INCOMPAT_64BIT != 0;
        let blocks_count = split_u64(raw, 0x04, is_64bit.then_some(0x150))?;
        let first_data_block = le_u32(raw, 0x14)?;
        if u64::from(first_data_block) >= blocks_count {
            return Err(error(format!(
                "Invalid s_first_data_block {first_data_block} for {blocks_count} blocks"
            )));
        }
        if first_data_block == 0 && block_size == EXT4_MIN_BLOCK_SIZE && cluster_ratio == 1 {
            return Err(error("Invalid s_first_data_block 0 for 1 KiB blocks"));
        }
        let desc_size = desc_size(raw, is_64bit)?;
        let group_count = group_count(
            blocks_count - u64::from(first_data_block),
            blocks_per_group,
            block_size / desc_size,
        )?;
        let inodes_count = le_u32(raw, 0x00)?;
        if u64::from(group_count) * u64::from(inodes_per_group) != u64::from(inodes_count) {
            return Err(error(format!(
                "Invalid s_inodes_count {inodes_count} for {group_count} groups of \
                 {inodes_per_group} inodes"
            )));
        }

        let uuid: [u8; 16] = slice(raw, 0x68, 16)?
            .try_into()
            .expect("slice has exactly 16 bytes");
        let name = slice(raw, 0x78, 16)?;
        let name = name.split(|&b| b == 0).next().unwrap_or_default();
        Ok(Self {
            inodes_count,
            blocks_count,
            first_data_block,
            block_size,
            blocks_per_group,
            inodes_per_group,
            state: le_u16(raw, 0x3a)?,
            creator_os: le_u32(raw, 0x48)?,
            rev_level,
            inode_size,
            compat,
            ro_compat,
            incompat,
            uuid,
            volume_name: String::from_utf8_lossy(name).into_owned(),
            desc_size,
            first_meta_bg: le_u32(raw, 0x104)?,
            backup_bgs: [le_u32(raw, 0x24c)?, le_u32(raw, 0x250)?],
            checksum_type: byte(raw, 0x175)?,
            checksum_seed: le_u32(raw, 0x270)?,
            checksum: le_u32(raw, S_CHECKSUM)?,
            group_count,
        })
    }

    /// With `metadata_csum`, check `s_checksum_type` and the superblock
    /// checksum: CRC32C (seed `0xFFFFFFFF`, no final XOR) of the bytes
    /// before `s_checksum` (`ext4_superblock_csum`).
    pub(super) fn verify_checksum(&self, data: &[u8]) -> Result<()> {
        if !self.has_metadata_csum() {
            return Ok(());
        }
        if self.checksum_type != EXT4_CRC32C_CHKSUM {
            return Err(error(format!(
                "Unsupported s_checksum_type {}",
                self.checksum_type
            )));
        }
        let covered = slice(data, SUPERBLOCK_OFFSET, S_CHECKSUM)?;
        let computed = crc32c_update(!0, covered);
        if computed != self.checksum {
            return Err(error(format!(
                "Invalid superblock checksum 0x{:08X} (computed 0x{computed:08X})",
                self.checksum
            )));
        }
        Ok(())
    }

    /// The metadata checksum seed: `s_checksum_seed` with `csum_seed`,
    /// otherwise the CRC32C of `s_uuid`.
    pub(super) fn csum_seed(&self) -> u32 {
        if self.has_incompat(INCOMPAT_CSUM_SEED) {
            self.checksum_seed
        } else {
            crc32c_update(!0, &self.uuid)
        }
    }

    /// Whether `group` holds a superblock backup (`ext4_bg_has_super`):
    /// group 0, the two `s_backup_bgs` with `sparse_super2`, every group
    /// without `sparse_super`, and otherwise groups 1 and the powers of 3,
    /// 5 and 7.
    pub(super) fn has_super(&self, group: u64) -> bool {
        if group == 0 {
            return true;
        }
        if self.has_compat(COMPAT_SPARSE_SUPER2) {
            return self
                .backup_bgs
                .iter()
                .any(|&backup| u64::from(backup) == group);
        }
        if group <= 1 || !self.has_ro_compat(RO_COMPAT_SPARSE_SUPER) {
            return true;
        }
        if group % 2 == 0 {
            return false;
        }
        [3, 5, 7].iter().any(|&base| is_power_of(group, base))
    }

    /// First block of `group`.
    pub(super) fn group_first_block(&self, group: u64) -> u64 {
        group * u64::from(self.blocks_per_group) + u64::from(self.first_data_block)
    }

    /// Block that holds group descriptor block `index` (`descriptor_loc`).
    /// Without `meta_bg`, and for the blocks before `s_first_meta_bg`, the
    /// descriptor table follows the superblock's block. With `meta_bg`, a
    /// descriptor block is in the first group it describes, after that
    /// group's superblock backup.
    pub(super) fn descriptor_block(&self, index: u64) -> u64 {
        let superblock_block = (SUPERBLOCK_OFFSET / self.block_size) as u64;
        if !self.has_incompat(INCOMPAT_META_BG) || index < u64::from(self.first_meta_bg) {
            return superblock_block + index + 1;
        }
        let group = index * (self.block_size / self.desc_size) as u64;
        let mut first = self.group_first_block(group);
        if self.has_super(group) {
            first += 1;
        }
        // With 1 KiB blocks and a first data block of 0 (bigalloc), group 0's
        // descriptors follow the superblock in block 1.
        if self.block_size == EXT4_MIN_BLOCK_SIZE && index == 0 && self.first_data_block == 0 {
            first += 1;
        }
        first
    }
}

/// The inode record size: 128 for revision 0; otherwise `s_inode_size`,
/// a power of two from 128 B to the block size, with `s_first_ino` at
/// least 11.
fn inode_size(raw: &[u8], rev_level: u32, block_size: usize) -> Result<usize> {
    if rev_level == EXT4_GOOD_OLD_REV {
        return Ok(EXT4_GOOD_OLD_INODE_SIZE);
    }
    let first_ino = le_u32(raw, 0x54)?;
    if first_ino < EXT4_GOOD_OLD_FIRST_INO {
        return Err(error(format!("Invalid s_first_ino {first_ino}")));
    }
    let inode_size = usize::from(le_u16(raw, 0x58)?);
    if inode_size < EXT4_GOOD_OLD_INODE_SIZE
        || !inode_size.is_power_of_two()
        || inode_size > block_size
    {
        return Err(error(format!("Invalid s_inode_size {inode_size}")));
    }
    Ok(inode_size)
}

/// Cluster and group geometry (`ext4_handle_clustersize`).
struct ClusterGeometry {
    /// Blocks per cluster.
    cluster_ratio: u32,
    /// `s_blocks_per_group`.
    blocks_per_group: u32,
}

/// With `bigalloc`, the cluster size is at least the block size and
/// `s_clusters_per_group`, at most the bits of one bitmap block, times the
/// cluster ratio is `s_blocks_per_group`. Without it, the cluster size is
/// the block size, `s_clusters_per_group` is ignored as the kernel ignores
/// it, and `s_blocks_per_group` is at most the bits of one bitmap block.
fn cluster_geometry(raw: &[u8], block_size: usize, ro_compat: u32) -> Result<ClusterGeometry> {
    let log_cluster_size = le_u32(raw, 0x1c)?;
    if log_cluster_size > MAX_LOG_CLUSTER_SIZE {
        return Err(error(format!(
            "Invalid s_log_cluster_size {log_cluster_size}"
        )));
    }
    let cluster_size = (EXT4_MIN_BLOCK_SIZE as u64) << log_cluster_size;
    let block_size = block_size as u64;
    let bitmap_bits = block_size * 8;
    let blocks_per_group = le_u32(raw, 0x20)?;
    if blocks_per_group == 0 {
        return Err(error("Invalid s_blocks_per_group 0"));
    }
    if ro_compat & RO_COMPAT_BIGALLOC == 0 {
        if cluster_size != block_size {
            return Err(error(format!(
                "Invalid s_log_cluster_size {log_cluster_size} for {} blocks without bigalloc",
                size_text(block_size)
            )));
        }
        if u64::from(blocks_per_group) > bitmap_bits {
            return Err(error(format!(
                "Invalid s_blocks_per_group {blocks_per_group} for {} blocks",
                size_text(block_size)
            )));
        }
        return Ok(ClusterGeometry {
            cluster_ratio: 1,
            blocks_per_group,
        });
    }
    if cluster_size < block_size {
        return Err(error(format!(
            "Invalid s_log_cluster_size {log_cluster_size} for {} blocks",
            size_text(block_size)
        )));
    }
    let cluster_ratio = cluster_size / block_size;
    let clusters_per_group = le_u32(raw, 0x24)?;
    if u64::from(clusters_per_group) > bitmap_bits
        || u64::from(clusters_per_group) * cluster_ratio != u64::from(blocks_per_group)
    {
        return Err(error(format!(
            "Invalid s_clusters_per_group {clusters_per_group} for {blocks_per_group} blocks \
             per group"
        )));
    }
    Ok(ClusterGeometry {
        cluster_ratio: u32::try_from(cluster_ratio).expect("at most 2^20 blocks per cluster"),
        blocks_per_group,
    })
}

/// Group descriptor size: `s_desc_size` with `64bit` (a power of two from
/// 64 B to 1 KiB), otherwise 32 B.
fn desc_size(raw: &[u8], is_64bit: bool) -> Result<usize> {
    if !is_64bit {
        return Ok(EXT4_MIN_DESC_SIZE);
    }
    let desc_size = usize::from(le_u16(raw, 0xfe)?);
    if !(EXT4_MIN_DESC_SIZE_64BIT..=EXT4_MAX_DESC_SIZE).contains(&desc_size)
        || !desc_size.is_power_of_two()
    {
        return Err(error(format!("Invalid s_desc_size {desc_size}")));
    }
    Ok(desc_size)
}

/// Number of groups that cover `data_blocks` blocks, limited as the kernel
/// limits it (`2^32 - descriptors per block`).
fn group_count(
    data_blocks: u64,
    blocks_per_group: u32,
    descriptors_per_block: usize,
) -> Result<u32> {
    let groups = blocks_for(data_blocks, u64::from(blocks_per_group));
    let limit = (1u64 << 32) - descriptors_per_block as u64;
    if groups > limit {
        return Err(error(format!("Invalid group count {groups}")));
    }
    Ok(u32::try_from(groups).expect("group count is below 2^32"))
}

/// Whether `value` is a power of `base` (`test_root` in `balloc.c`).
fn is_power_of(mut value: u64, base: u64) -> bool {
    while value > 1 && value % base == 0 {
        value /= base;
    }
    value == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1 KiB-block superblock with `sparse_super` and 8 blocks per group,
    /// for the backup and descriptor location rules.
    fn backup_layout() -> Superblock {
        let mut sb = Superblock::for_tests(1 << 20, 8);
        sb.ro_compat = RO_COMPAT_SPARSE_SUPER;
        sb
    }

    #[test]
    fn sparse_super_backups_are_in_groups_one_and_powers_of_three_five_and_seven() {
        let groups: Vec<u64> = (0..60).filter(|&g| backup_layout().has_super(g)).collect();
        assert_eq!(groups, [0, 1, 3, 5, 7, 9, 25, 27, 49]);
    }

    #[test]
    fn meta_bg_descriptor_blocks_follow_each_meta_groups_backup() {
        let mut sb = backup_layout();
        assert_eq!(sb.descriptor_block(0), 2);
        assert_eq!(sb.descriptor_block(3), 5);
        sb.incompat = INCOMPAT_META_BG;
        sb.first_meta_bg = 1;
        // 32 descriptors per 1 KiB block: block 1 describes groups 32-63,
        // and group 32 has no backup, so it starts at 1 + 32 * 8.
        assert_eq!(sb.descriptor_block(0), 2);
        assert_eq!(sb.descriptor_block(1), 257);
        // Group 64 is not a power of 3, 5 or 7 either; group 96 neither.
        assert_eq!(sb.descriptor_block(2), 513);
        sb.compat = COMPAT_SPARSE_SUPER2;
        sb.backup_bgs = [32, 0];
        assert_eq!(sb.descriptor_block(1), 258);
    }

    #[test]
    fn powers_are_recognized_without_overflow() {
        assert!(is_power_of(1, 3));
        assert!(is_power_of(3u64.pow(40), 3));
        assert!(!is_power_of(u64::MAX, 3));
        assert!(!is_power_of(0, 7));
    }
}
