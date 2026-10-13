//! ext2, ext3 and ext4 filesystem images: the superblock and its geometry,
//! block group descriptors (32- and 64-bit, `meta_bg`), inodes, block maps
//! and extent trees, and a linear directory walk from the root that lists
//! regular files in a recognized format as members.
//!
//! Sources (Linux v6.11, commit `98f7e32f20d28ec452afb208f9cffc08448a2652`):
//! - `fs/ext4/ext4.h`: `struct ext4_super_block`, `struct ext4_group_desc`,
//!   `struct ext4_inode`, the feature and inode flag bits,
//!   `struct ext4_dir_entry_2`, `struct ext4_dir_entry_tail` and
//!   `ext4_rec_len_from_disk`; `fs/ext4/ext4_extents.h`: the extent header,
//!   index and leaf entries and the extent block tail.
//! - `fs/ext4/super.c`: `ext4_handle_clustersize`, `ext4_check_geometry`,
//!   `descriptor_loc`, `ext4_check_descriptors`, `ext4_superblock_csum` and
//!   `ext4_group_desc_csum`; `fs/ext4/balloc.c`: `ext4_bg_has_super`.
//! - `fs/ext4/inode.c`: `__ext4_iget`, `ext4_inode_csum` and `ext4_isize`;
//!   `fs/ext4/extents.c`: `__ext4_ext_check` and
//!   `ext4_valid_extent_entries`; `fs/ext4/dir.c`: `__ext4_check_dir_entry`
//!   and `ext4_readdir`; `fs/ext4/namei.c`: `__ext4_read_dirblock` (which
//!   blocks of an htree directory are index blocks) and
//!   `ext4_dirblock_csum`.
//! - `Documentation/filesystems/ext4/`: `super.rst`, `group_descr.rst`,
//!   `inodes.rst`, `ifork.rst`, `directory.rst` and `checksums.rst`.
//! - util-linux v2.40.2 `libblkid/src/superblocks/ext.c`: the convention
//!   that names a filesystem ext2, ext3 or ext4 by its feature set.
//!
//! All fields are little-endian. Block numbers count filesystem blocks of
//! `1024 << s_log_block_size` bytes; offsets in notes and metadata are file
//! bytes. The format names no processor: `s_creator_os` is an operating
//! system, so members are classified from their own bytes.
//!
//! A filesystem larger than the input (`s_blocks_count` blocks; containers
//! hand on the first 64 MiB of a larger partition) is read as a truncated
//! filesystem when its superblock and its root inode are present: group
//! descriptors, inode records and other metadata blocks past the end of
//! the input are
//! skipped and counted, and files are listed only when all of their data
//! is present. Linux refuses to mount such a filesystem
//! (`ext4_check_geometry`: "block count exceeds size of device").

use crate::error::{ClassifierError, Result};
use crate::formats::container::Container;
use crate::types::FileFormat;
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

mod groups;
mod inode;
mod map;
mod superblock;
mod walk;

/// File offset of the primary superblock.
const SUPERBLOCK_OFFSET: usize = 1024;

/// Size of the superblock.
const SUPERBLOCK_SIZE: usize = 1024;

/// `s_magic` (superblock offset 0x38, file offset 0x438).
const EXT4_SUPER_MAGIC: u16 = 0xef53;

/// Smallest block size; the block size is `1024 << s_log_block_size`.
const EXT4_MIN_BLOCK_SIZE: usize = 1024;

/// `s_log_block_size` limit: 64 KiB blocks
/// (`EXT4_MAX_BLOCK_LOG_SIZE - EXT4_MIN_BLOCK_LOG_SIZE`).
const MAX_LOG_BLOCK_SIZE: u32 = 6;

/// `s_log_cluster_size` limit (`EXT4_MAX_CLUSTER_LOG_SIZE -
/// EXT4_MIN_BLOCK_LOG_SIZE`).
const MAX_LOG_CLUSTER_SIZE: u32 = 20;

/// `s_rev_level` values.
const EXT4_GOOD_OLD_REV: u32 = 0;
const EXT4_DYNAMIC_REV: u32 = 1;

/// Inode size and first ordinary inode of revision 0 filesystems.
const EXT4_GOOD_OLD_INODE_SIZE: usize = 128;
const EXT4_GOOD_OLD_FIRST_INO: u32 = 11;

/// Group descriptor sizes: the 32-byte form, and the range of
/// `s_desc_size` with `INCOMPAT_64BIT`.
const EXT4_MIN_DESC_SIZE: usize = 32;
const EXT4_MIN_DESC_SIZE_64BIT: usize = 64;
const EXT4_MAX_DESC_SIZE: usize = 1024;

/// The root directory inode.
const EXT4_ROOT_INO: u32 = 2;

/// `s_creator_os` value for Linux; inode checksums are defined only there.
const EXT4_OS_LINUX: u32 = 0;

/// `s_checksum_type` value for CRC32C.
const EXT4_CRC32C_CHKSUM: u8 = 1;

/// `bg_flags` bit: the group's inode table is not initialized.
const EXT4_BG_INODE_UNINIT: u16 = 0x0001;

/// `s_state` bit: errors were detected.
const EXT4_ERROR_FS: u16 = 0x0002;

/// `s_feature_compat` bits.
const COMPAT_DIR_PREALLOC: u32 = 0x0001;
const COMPAT_IMAGIC_INODES: u32 = 0x0002;
const COMPAT_HAS_JOURNAL: u32 = 0x0004;
const COMPAT_EXT_ATTR: u32 = 0x0008;
const COMPAT_RESIZE_INODE: u32 = 0x0010;
const COMPAT_DIR_INDEX: u32 = 0x0020;
const COMPAT_SPARSE_SUPER2: u32 = 0x0200;
const COMPAT_FAST_COMMIT: u32 = 0x0400;
const COMPAT_STABLE_INODES: u32 = 0x0800;
const COMPAT_ORPHAN_FILE: u32 = 0x1000;

/// `s_feature_ro_compat` bits.
const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_BTREE_DIR: u32 = 0x0004;
const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
const RO_COMPAT_QUOTA: u32 = 0x0100;
const RO_COMPAT_BIGALLOC: u32 = 0x0200;
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
const RO_COMPAT_READONLY: u32 = 0x1000;
const RO_COMPAT_PROJECT: u32 = 0x2000;
const RO_COMPAT_VERITY: u32 = 0x8000;
const RO_COMPAT_ORPHAN_PRESENT: u32 = 0x1_0000;

/// `s_feature_incompat` bits.
const INCOMPAT_COMPRESSION: u32 = 0x0001;
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_MMP: u32 = 0x0100;
const INCOMPAT_FLEX_BG: u32 = 0x0200;
const INCOMPAT_EA_INODE: u32 = 0x0400;
const INCOMPAT_DIRDATA: u32 = 0x1000;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;
const INCOMPAT_CASEFOLD: u32 = 0x2_0000;

/// Incompatible features this reader handles: the kernel's
/// `EXT4_FEATURE_INCOMPAT_SUPP`. Compression, external journal devices and
/// Lustre `dirdata` are refused, as the kernel refuses them.
const SUPPORTED_INCOMPAT: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_META_BG
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_MMP
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR;

/// Features that ext2 and ext3 implementations understand (libblkid
/// `EXT2_FEATURE_*_SUPP` and `EXT3_FEATURE_*_SUPP`; both ro-compat sets are
/// the same). A filesystem with any other ro-compat or incompat feature is
/// named ext4.
const EXT3_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE | RO_COMPAT_BTREE_DIR;
const EXT2_INCOMPAT: u32 = INCOMPAT_FILETYPE | INCOMPAT_META_BG;
const EXT3_INCOMPAT: u32 = EXT2_INCOMPAT | INCOMPAT_RECOVER;

/// Which feature word a feature bit belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureSet {
    Compat,
    RoCompat,
    Incompat,
}

/// Feature names, the lowercase of the kernel's `EXT4_FEATURE_*` names.
const FEATURE_NAMES: &[(FeatureSet, u32, &str)] = &[
    (FeatureSet::Compat, COMPAT_DIR_PREALLOC, "dir_prealloc"),
    (FeatureSet::Compat, COMPAT_IMAGIC_INODES, "imagic_inodes"),
    (FeatureSet::Compat, COMPAT_HAS_JOURNAL, "has_journal"),
    (FeatureSet::Compat, COMPAT_EXT_ATTR, "ext_attr"),
    (FeatureSet::Compat, COMPAT_RESIZE_INODE, "resize_inode"),
    (FeatureSet::Compat, COMPAT_DIR_INDEX, "dir_index"),
    (FeatureSet::Compat, COMPAT_SPARSE_SUPER2, "sparse_super2"),
    (FeatureSet::Compat, COMPAT_FAST_COMMIT, "fast_commit"),
    (FeatureSet::Compat, COMPAT_STABLE_INODES, "stable_inodes"),
    (FeatureSet::Compat, COMPAT_ORPHAN_FILE, "orphan_file"),
    (FeatureSet::RoCompat, RO_COMPAT_SPARSE_SUPER, "sparse_super"),
    (FeatureSet::RoCompat, RO_COMPAT_LARGE_FILE, "large_file"),
    (FeatureSet::RoCompat, RO_COMPAT_BTREE_DIR, "btree_dir"),
    (FeatureSet::RoCompat, RO_COMPAT_HUGE_FILE, "huge_file"),
    (FeatureSet::RoCompat, RO_COMPAT_GDT_CSUM, "gdt_csum"),
    (FeatureSet::RoCompat, RO_COMPAT_DIR_NLINK, "dir_nlink"),
    (FeatureSet::RoCompat, RO_COMPAT_EXTRA_ISIZE, "extra_isize"),
    (FeatureSet::RoCompat, RO_COMPAT_QUOTA, "quota"),
    (FeatureSet::RoCompat, RO_COMPAT_BIGALLOC, "bigalloc"),
    (
        FeatureSet::RoCompat,
        RO_COMPAT_METADATA_CSUM,
        "metadata_csum",
    ),
    (FeatureSet::RoCompat, RO_COMPAT_READONLY, "readonly"),
    (FeatureSet::RoCompat, RO_COMPAT_PROJECT, "project"),
    (FeatureSet::RoCompat, RO_COMPAT_VERITY, "verity"),
    (
        FeatureSet::RoCompat,
        RO_COMPAT_ORPHAN_PRESENT,
        "orphan_present",
    ),
    (FeatureSet::Incompat, INCOMPAT_COMPRESSION, "compression"),
    (FeatureSet::Incompat, INCOMPAT_FILETYPE, "filetype"),
    (FeatureSet::Incompat, INCOMPAT_RECOVER, "recover"),
    (FeatureSet::Incompat, INCOMPAT_JOURNAL_DEV, "journal_dev"),
    (FeatureSet::Incompat, INCOMPAT_META_BG, "meta_bg"),
    (FeatureSet::Incompat, INCOMPAT_EXTENTS, "extents"),
    (FeatureSet::Incompat, INCOMPAT_64BIT, "64bit"),
    (FeatureSet::Incompat, INCOMPAT_MMP, "mmp"),
    (FeatureSet::Incompat, INCOMPAT_FLEX_BG, "flex_bg"),
    (FeatureSet::Incompat, INCOMPAT_EA_INODE, "ea_inode"),
    (FeatureSet::Incompat, INCOMPAT_DIRDATA, "dirdata"),
    (FeatureSet::Incompat, INCOMPAT_CSUM_SEED, "csum_seed"),
    (FeatureSet::Incompat, INCOMPAT_LARGEDIR, "largedir"),
    (FeatureSet::Incompat, INCOMPAT_INLINE_DATA, "inline_data"),
    (FeatureSet::Incompat, INCOMPAT_ENCRYPT, "encrypt"),
    (FeatureSet::Incompat, INCOMPAT_CASEFOLD, "casefold"),
];

/// `s_creator_os` names (`EXT4_OS_*`).
const CREATOR_OS_NAMES: &[(u32, &str)] = &[
    (EXT4_OS_LINUX, "Linux"),
    (1, "Hurd"),
    (2, "Masix"),
    (3, "FreeBSD"),
    (4, "Lites"),
];

/// A filesystem named by its feature set, as libblkid names it: ext3 with a
/// journal and only ext3 features, ext2 without a journal and only ext2
/// features, otherwise ext4. The name is a convention, not a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// No journal and only ext2 features.
    Ext2,
    /// A journal (`has_journal`) and only ext3 features.
    Ext3,
    /// Any other feature set (`extents`, `64bit`, `metadata_csum`, ...).
    Ext4,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Ext2 | Self::Ext3 | Self::Ext4 => FileFormat::Ext,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
        }
    }

    /// No layout is weak: detection needs the magic and a consistent
    /// superblock geometry.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Ext2 | Self::Ext3 | Self::Ext4 => false,
        }
    }

    /// The name for a feature set (`probe_ext2`, `probe_ext3` and
    /// `probe_ext4` in libblkid).
    fn from_features(compat: u32, ro_compat: u32, incompat: u32) -> Self {
        let has_journal = compat & COMPAT_HAS_JOURNAL != 0;
        let ext3_ro_compat = ro_compat & !EXT3_RO_COMPAT == 0;
        if has_journal && ext3_ro_compat && incompat & !EXT3_INCOMPAT == 0 {
            Self::Ext3
        } else if !has_journal && ext3_ro_compat && incompat & !EXT2_INCOMPAT == 0 {
            Self::Ext2
        } else {
            Self::Ext4
        }
    }
}

/// The superblock fields the reader uses, after the geometry checks of
/// [`Superblock::parse`]. Block numbers are filesystem blocks.
#[derive(Debug, Clone)]
struct Superblock {
    /// `s_inodes_count`.
    inodes_count: u32,
    /// `s_blocks_count_lo`, plus `s_blocks_count_hi` with `64bit`.
    blocks_count: u64,
    /// `s_first_data_block`: 1 for 1 KiB blocks, else 0.
    first_data_block: u32,
    /// Block size in bytes.
    block_size: usize,
    /// `s_blocks_per_group`.
    blocks_per_group: u32,
    /// `s_inodes_per_group`.
    inodes_per_group: u32,
    /// `s_state`.
    state: u16,
    /// `s_creator_os`.
    creator_os: u32,
    /// `s_rev_level`.
    rev_level: u32,
    /// Inode record size in bytes (`s_inode_size`, 128 for revision 0).
    inode_size: usize,
    /// `s_feature_compat`.
    compat: u32,
    /// `s_feature_ro_compat`.
    ro_compat: u32,
    /// `s_feature_incompat`.
    incompat: u32,
    /// `s_uuid`.
    uuid: [u8; 16],
    /// `s_volume_name`, up to its first NUL byte.
    volume_name: String,
    /// Group descriptor size in bytes (`s_desc_size` with `64bit`, else 32).
    desc_size: usize,
    /// `s_first_meta_bg`.
    first_meta_bg: u32,
    /// `s_backup_bgs`: the groups that hold superblock backups with
    /// `sparse_super2`.
    backup_bgs: [u32; 2],
    /// `s_checksum_type`.
    checksum_type: u8,
    /// `s_checksum_seed`, used with `csum_seed`.
    checksum_seed: u32,
    /// `s_checksum`.
    checksum: u32,
    /// Number of block groups, computed from the block count.
    group_count: u32,
}

impl Superblock {
    fn has_compat(&self, bit: u32) -> bool {
        self.compat & bit != 0
    }

    fn has_ro_compat(&self, bit: u32) -> bool {
        self.ro_compat & bit != 0
    }

    fn has_incompat(&self, bit: u32) -> bool {
        self.incompat & bit != 0
    }

    fn has_metadata_csum(&self) -> bool {
        self.has_ro_compat(RO_COMPAT_METADATA_CSUM)
    }

    /// Group descriptor flags and `bg_itable_unused` are maintained
    /// (`ext4_has_group_desc_csum`).
    fn has_group_desc_csum(&self) -> bool {
        self.has_metadata_csum() || self.has_ro_compat(RO_COMPAT_GDT_CSUM)
    }

    fn layout(&self) -> Layout {
        Layout::from_features(self.compat, self.ro_compat, self.incompat)
    }

    /// Filesystem size in bytes, saturated at `u64::MAX`.
    fn size(&self) -> u64 {
        self.blocks_count.saturating_mul(self.block_size as u64)
    }
}

/// The group descriptor fields the reader uses. Block numbers are
/// filesystem blocks.
#[derive(Debug, Clone, Copy)]
struct GroupDesc {
    /// First block of the group's inode table
    /// (`bg_inode_table_lo`, plus `bg_inode_table_hi` with `64bit`).
    inode_table: u64,
    /// `bg_flags`.
    flags: u16,
    /// `bg_itable_unused_lo`, plus `bg_itable_unused_hi` with `64bit`:
    /// inodes at the end of the table that were never used.
    itable_unused: u32,
}

/// An inode, after the checks of [`Filesystem::inode`].
#[derive(Debug, Clone)]
struct Inode {
    /// Inode number (1-based).
    number: u32,
    /// `i_mode`.
    mode: u16,
    /// File size in bytes (`i_size_lo`, plus `i_size_high` for regular
    /// files and, with `largedir`, directories).
    size: u64,
    /// `i_flags`.
    flags: u32,
    /// `i_block`: block map, extent tree root or inline data.
    block: [u8; inode::I_BLOCK_SIZE],
    /// Seed of the inode's extent block and directory block checksums,
    /// with `metadata_csum`.
    csum_seed: Option<u32>,
}

/// A parsed filesystem: the bytes that belong to it, its superblock and
/// group descriptors.
struct Filesystem<'a> {
    /// The filesystem's bytes (`s_blocks_count` blocks), or the bytes of
    /// them present when the input ends inside the filesystem.
    data: &'a [u8],
    sb: Superblock,
    /// The group descriptors: all of them, or those before the first one
    /// past the end of a truncated filesystem's input.
    groups: Vec<GroupDesc>,
    /// Metadata checksum seed, with `metadata_csum`.
    csum_seed: Option<u32>,
    /// Inode checksums are defined (`metadata_csum` and a Linux creator).
    verify_inodes: bool,
    /// Bytes of metadata (inode records, directory blocks, extent and
    /// indirect blocks) the reader may still read; see
    /// [`Filesystem::charge`].
    metadata_budget: Cell<u64>,
    /// Metadata blocks (group descriptors, inode tables, directory, extent
    /// and indirect blocks) past the end of a truncated filesystem's input,
    /// by number, as the reader asked for them.
    absent_blocks: RefCell<BTreeSet<u64>>,
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::ExtParseError {
        message: message.into(),
    }
}

/// Why a read of the filesystem failed.
#[derive(Debug)]
enum Fault {
    /// The filesystem is invalid; the error says how.
    Invalid(ClassifierError),
    /// The bytes lie inside the filesystem but past the end of the input,
    /// which holds only the start of a truncated filesystem.
    Absent,
}

impl From<ClassifierError> for Fault {
    fn from(e: ClassifierError) -> Self {
        Self::Invalid(e)
    }
}

/// The result of a read of the filesystem's bytes.
type ReadResult<T> = std::result::Result<T, Fault>;

/// A read that failed because the filesystem is invalid.
fn invalid<T>(message: impl Into<String>) -> ReadResult<T> {
    Err(Fault::Invalid(error(message)))
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid file range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated filesystem at 0x{start:X} + {len} B")))
}

fn byte(data: &[u8], at: usize) -> Result<u8> {
    Ok(slice(data, at, 1)?[0])
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

/// A 64-bit value split into a low and an optional high 32-bit field.
fn split_u64(data: &[u8], low_at: usize, high_at: Option<usize>) -> Result<u64> {
    let low = u64::from(le_u32(data, low_at)?);
    let high = match high_at {
        Some(at) => u64::from(le_u32(data, at)?),
        None => 0,
    };
    Ok(low | (high << 32))
}

/// Blocks of `block_size` bytes that hold `size` bytes.
fn blocks_for(size: u64, block_size: u64) -> u64 {
    size / block_size + u64::from(size % block_size != 0)
}

/// The low 16 bits of a CRC32C, the part a 16-bit checksum field stores.
fn low_half(crc: u32) -> u16 {
    u16::try_from(crc & 0xffff).expect("masked to 16 bits")
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
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

/// Names of the features in `compat`, `ro_compat` and `incompat`, with the
/// value of any bits that have no name.
fn feature_names(compat: u32, ro_compat: u32, incompat: u32) -> Vec<String> {
    let words = [
        (FeatureSet::Compat, compat, "compat"),
        (FeatureSet::RoCompat, ro_compat, "ro_compat"),
        (FeatureSet::Incompat, incompat, "incompat"),
    ];
    let mut names = Vec::new();
    for (set, word, word_name) in words {
        let mut named = 0u32;
        for &(feature_set, bit, name) in FEATURE_NAMES {
            if feature_set == set && word & bit != 0 {
                names.push(name.to_string());
                named |= bit;
            }
        }
        let unnamed = word & !named;
        if unnamed != 0 {
            names.push(format!("{word_name} 0x{unnamed:X}"));
        }
    }
    names
}

/// `s_uuid` in the 8-4-4-4-12 text form.
fn uuid_text(uuid: &[u8; 16]) -> String {
    let hex: Vec<String> = uuid.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        hex[..4].concat(),
        hex[4..6].concat(),
        hex[6..8].concat(),
        hex[8..10].concat(),
        hex[10..].concat()
    )
}

fn creator_os_name(creator_os: u32) -> String {
    CREATOR_OS_NAMES
        .iter()
        .find(|&&(id, _)| id == creator_os)
        .map_or_else(
            || format!("unknown ({creator_os})"),
            |&(_, name)| name.to_string(),
        )
}

/// Detect an ext2, ext3 or ext4 filesystem: magic `0xEF53` at file offset
/// 0x438 and a superblock whose block size, cluster size, inode size and
/// group geometry are consistent. The image size, the features and the
/// checksums are checked by [`parse_container`], so a damaged image is a
/// parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    Superblock::parse(data).ok().map(|sb| sb.layout())
}

/// Parse an ext filesystem image into the shared container model. Regular
/// files that start with a recognized format are its children, labeled by
/// their path.
///
/// # Errors
///
/// [`ClassifierError::ExtParseError`] for an invalid superblock, a
/// superblock checksum mismatch, an unsupported incompatible feature, an
/// image followed by data other than padding, invalid group descriptors,
/// or an unreadable root inode, and for an image shorter than the
/// filesystem whose root inode lies past the end of the input. Damage below
/// the root directory is reported in notes instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let sb = Superblock::parse(data)?;
    sb.verify_checksum(data)?;
    let unsupported = sb.incompat & !SUPPORTED_INCOMPAT;
    if unsupported != 0 {
        return Err(error(format!(
            "Unsupported incompatible features: {}",
            feature_names(0, 0, unsupported).join(", ")
        )));
    }
    let fs_size = match usize::try_from(sb.size())
        .ok()
        .filter(|&size| size <= data.len())
    {
        Some(fs_size) => {
            let trailing = &data[fs_size..];
            if !is_padding(trailing) {
                return Err(error(format!(
                    "Invalid trailing data: {} B after the filesystem at 0x{fs_size:X} are not \
                     padding",
                    trailing.len()
                )));
            }
            fs_size
        }
        // The input ends inside the filesystem: all of it belongs to it.
        None => data.len(),
    };

    let fs = Filesystem::new(&data[..fs_size], sb)?;
    // The root inode must be present; without it nothing can be listed.
    match walk::check_root(&fs) {
        Ok(()) => {}
        Err(Fault::Invalid(e)) => return Err(e),
        Err(Fault::Absent) => {
            let sb = &fs.sb;
            return Err(error(format!(
                "Truncated filesystem: {} blocks of {} need {} B, {} B present",
                sb.blocks_count,
                size_text(sb.block_size as u64),
                sb.size(),
                data.len()
            )));
        }
    }
    let mut c = Container::new(FileFormat::Ext, layout.label(), "ext");
    c.consumed = fs_size;
    describe(&fs, layout, &mut c);
    walk::walk(&fs, &mut c);
    Ok(c)
}

/// Summary notes and metadata from the superblock.
fn describe(fs: &Filesystem<'_>, layout: Layout, c: &mut Container<'_>) {
    let sb = &fs.sb;
    let descriptors = if sb.has_incompat(INCOMPAT_64BIT) {
        "64-bit"
    } else {
        "32-bit"
    };
    let groups = if sb.group_count == 1 {
        "1 block group".to_string()
    } else {
        format!("{} block groups", sb.group_count)
    };
    c.notes.push(format!(
        "{} filesystem: {} blocks, {} B inodes; {groups}; {descriptors} group descriptors",
        layout.label(),
        size_text(sb.block_size as u64),
        sb.inode_size
    ));
    if fs.is_truncated() {
        c.notes.push(format!(
            "Volume truncated: {} of {} present; files are listed only when all of their data \
             is present",
            fs.present_text(),
            size_text(sb.size())
        ));
    }
    c.notes.push(checksum_note(fs));
    if sb.has_incompat(INCOMPAT_RECOVER) {
        c.notes
            .push("The journal needs recovery; file contents may be stale".to_string());
    }
    if sb.state & EXT4_ERROR_FS != 0 {
        c.notes
            .push("The superblock state records filesystem errors".to_string());
    }
    c.notes.push(format!(
        "No processor field: s_creator_os names the operating system ({}); \
         members are classified from their own bytes",
        creator_os_name(sb.creator_os)
    ));

    let features = feature_names(sb.compat, sb.ro_compat, sb.incompat);
    c.push_metadata("ext_revision", "Revision level", u64::from(sb.rev_level));
    c.push_metadata("ext_block_size", "Block size (B)", sb.block_size as u64);
    c.push_metadata("ext_inode_size", "Inode size (B)", sb.inode_size as u64);
    c.push_metadata("ext_block_count", "Blocks", sb.blocks_count);
    c.push_metadata("ext_inode_count", "Inodes", u64::from(sb.inodes_count));
    c.push_metadata("ext_group_count", "Block groups", u64::from(sb.group_count));
    c.push_metadata("ext_features", "Features", features.join(", "));
    c.push_metadata("ext_uuid", "UUID", uuid_text(&sb.uuid));
    if !sb.volume_name.is_empty() {
        c.push_metadata("ext_volume_name", "Volume name", sb.volume_name.clone());
    }
    c.push_metadata(
        "ext_creator_os",
        "Creator OS",
        creator_os_name(sb.creator_os),
    );
}

/// Which metadata checksums the reader verified.
fn checksum_note(fs: &Filesystem<'_>) -> String {
    let sb = &fs.sb;
    if sb.has_metadata_csum() {
        let inodes = if fs.verify_inodes {
            "inode, extent block and directory block checksums verified for the metadata read"
        } else {
            "extent block and directory block checksums verified for the metadata read; \
             inode checksums not verified (defined only for a Linux creator OS)"
        };
        format!(
            "metadata_csum: superblock and group descriptor checksums verified (CRC32C); \
             {inodes}; bitmap, htree index, extended attribute and journal checksums not \
             verified"
        )
    } else if sb.has_ro_compat(RO_COMPAT_GDT_CSUM) {
        "gdt_csum: group descriptor checksums verified (CRC16); \
         the filesystem has no other metadata checksums"
            .to_string()
    } else {
        "The filesystem has no metadata checksums".to_string()
    }
}

impl<'a> Filesystem<'a> {
    /// Read the group descriptors and derive the checksum seed. The reader
    /// may read twice the filesystem size in metadata: a consistent
    /// filesystem stores each inode record and directory, extent and
    /// indirect block once, and a file's mapping blocks are read at most
    /// twice (for its prefix and for its contents).
    fn new(data: &'a [u8], sb: Superblock) -> Result<Self> {
        let csum_seed = sb.has_metadata_csum().then(|| sb.csum_seed());
        let verify_inodes = csum_seed.is_some() && sb.creator_os == EXT4_OS_LINUX;
        let absent_blocks = RefCell::default();
        let groups = groups::parse(data, &sb, csum_seed, &absent_blocks)?;
        let metadata_budget = Cell::new((data.len() as u64).saturating_mul(2));
        Ok(Self {
            data,
            sb,
            groups,
            csum_seed,
            verify_inodes,
            metadata_budget,
            absent_blocks,
        })
    }

    /// Whether the input ends before the filesystem does.
    fn is_truncated(&self) -> bool {
        (self.data.len() as u64) < self.sb.size()
    }

    /// The bytes of the filesystem present, as text for notes.
    fn present_text(&self) -> String {
        size_text(self.data.len() as u64)
    }

    /// What the metadata read limit is a multiple of, for messages.
    fn budget_basis(&self) -> String {
        if self.is_truncated() {
            format!("the {} present", self.present_text())
        } else {
            "the filesystem size".to_string()
        }
    }

    /// The bytes of `count` blocks starting at block `first`; absent when
    /// they pass the end of the input.
    fn blocks(&self, first: u64, count: u64) -> ReadResult<&'a [u8]> {
        let end = first
            .checked_add(count)
            .filter(|&end| end <= self.sb.blocks_count)
            .ok_or_else(|| {
                error(format!(
                    "Invalid block range 0x{first:X} + {count} beyond the {} blocks of the \
                     filesystem",
                    self.sb.blocks_count
                ))
            })?;
        let block_size = self.sb.block_size as u64;
        // A truncated filesystem may declare more bytes than u64 counts;
        // such blocks lie past the end of the input.
        match (first.checked_mul(block_size), end.checked_mul(block_size)) {
            (Some(start), Some(stop)) => self.present(start, stop),
            _ => Err(Fault::Absent),
        }
    }

    /// The bytes from file offset `start` to `stop`, a range inside the
    /// filesystem; absent when it passes the end of the input.
    fn present(&self, start: u64, stop: u64) -> ReadResult<&'a [u8]> {
        if stop > self.data.len() as u64 {
            return Err(Fault::Absent);
        }
        // Both ends lie within the bytes present, so they fit in usize.
        let start = usize::try_from(start).expect("offset is in the image");
        let stop = usize::try_from(stop).expect("offset is in the image");
        Ok(&self.data[start..stop])
    }

    fn block(&self, number: u64) -> ReadResult<&'a [u8]> {
        self.blocks(number, 1)
    }

    /// File offset of block `number`, which [`Self::blocks`] has read.
    fn offset(&self, number: u64) -> usize {
        usize::try_from(number * self.sb.block_size as u64).expect("block offset is in the image")
    }

    /// Account for `size` bytes of metadata about to be read.
    fn charge(&self, size: usize) -> Result<()> {
        let remaining = self.metadata_budget.get();
        let Some(left) = remaining.checked_sub(size as u64) else {
            self.metadata_budget.set(0);
            return Err(error(format!(
                "Invalid metadata: more than {} B read (twice {})",
                (self.data.len() as u64).saturating_mul(2),
                self.budget_basis()
            )));
        };
        self.metadata_budget.set(left);
        Ok(())
    }

    /// The metadata read limit was reached; the walk stops.
    fn is_exhausted(&self) -> bool {
        self.metadata_budget.get() == 0
    }

    /// Block `number`, read as metadata and charged to the metadata budget.
    fn charged_block(&self, number: u64) -> ReadResult<&'a [u8]> {
        let block = self.block(number)?;
        self.charge(block.len())?;
        Ok(block)
    }

    /// Block `number`, read as metadata and charged to the metadata budget.
    /// A block past the end of the input is recorded as absent.
    fn metadata_block(&self, number: u64) -> ReadResult<&'a [u8]> {
        let read = self.charged_block(number);
        if let Err(Fault::Absent) = read {
            self.absent_blocks.borrow_mut().insert(number);
        }
        read
    }
}

/// Bytes read from a file, borrowed when they are stored contiguously.
struct FileData<'a> {
    bytes: Cow<'a, [u8]>,
    /// The first stored run, if any block is stored.
    first_run: Option<StoredRun>,
    /// How the bytes were reassembled when they are not one stored run.
    transform: &'static str,
}

/// File bytes stored contiguously in the image.
#[derive(Debug, Clone, Copy)]
struct StoredRun {
    /// File offset in the image.
    offset: usize,
    /// Size in bytes, at most the bytes of the file it holds.
    size: usize,
}

#[cfg(test)]
impl Superblock {
    /// A revision 1 superblock with 1 KiB blocks (`s_first_data_block` 1),
    /// 128-byte inodes, 8 inodes per group and no features, for unit tests
    /// of the layout rules. The counts are not checked against each other.
    fn for_tests(blocks_count: u64, blocks_per_group: u32) -> Self {
        Self {
            inodes_count: 8,
            blocks_count,
            first_data_block: 1,
            block_size: EXT4_MIN_BLOCK_SIZE,
            blocks_per_group,
            inodes_per_group: 8,
            state: 1,
            creator_os: EXT4_OS_LINUX,
            rev_level: EXT4_DYNAMIC_REV,
            inode_size: EXT4_GOOD_OLD_INODE_SIZE,
            compat: 0,
            ro_compat: 0,
            incompat: 0,
            uuid: [0; 16],
            volume_name: String::new(),
            desc_size: EXT4_MIN_DESC_SIZE,
            first_meta_bg: 0,
            backup_bgs: [0; 2],
            checksum_type: 0,
            checksum_seed: 0,
            checksum: 0,
            group_count: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_follow_the_libblkid_feature_convention() {
        assert_eq!(
            Layout::from_features(COMPAT_EXT_ATTR, RO_COMPAT_SPARSE_SUPER, INCOMPAT_FILETYPE),
            Layout::Ext2
        );
        assert_eq!(
            Layout::from_features(COMPAT_HAS_JOURNAL, RO_COMPAT_LARGE_FILE, INCOMPAT_RECOVER),
            Layout::Ext3
        );
        assert_eq!(Layout::from_features(0, 0, INCOMPAT_EXTENTS), Layout::Ext4);
        // A journal that needs recovery is an ext3 feature, not an ext2 one.
        assert_eq!(Layout::from_features(0, 0, INCOMPAT_RECOVER), Layout::Ext4);
        assert_eq!(
            Layout::from_features(COMPAT_HAS_JOURNAL, RO_COMPAT_METADATA_CSUM, 0),
            Layout::Ext4
        );
    }

    #[test]
    fn feature_names_list_unnamed_bits_by_value() {
        assert_eq!(
            feature_names(COMPAT_HAS_JOURNAL | 0x8000, 0, INCOMPAT_64BIT),
            ["has_journal", "compat 0x8000", "64bit"]
        );
    }

    #[test]
    fn uuids_use_the_hyphenated_text_form() {
        let uuid = [
            0x5a, 0x52, 0x41, 0x58, 0x65, 0x78, 0x74, 0x34, 0x80, 0, 0, 0, 0, 0, 0, 4,
        ];
        assert_eq!(uuid_text(&uuid), "5a524158-6578-7434-8000-000000000004");
    }
}
