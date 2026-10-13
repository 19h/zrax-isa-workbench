//! EROFS filesystem images: the superblock, compact and extended inodes,
//! directories, the flat-plain, flat-inline and chunk-based data layouts,
//! the LZ4 and DEFLATE compressed layouts (full and compact indexes, big
//! physical clusters, tail packing), and a directory walk from the root
//! that lists regular files in a recognized format as members.
//!
//! Sources (Linux v6.11, commit `98f7e32f20d28ec452afb208f9cffc08448a2652`):
//! - `fs/erofs/erofs_fs.h`: `struct erofs_super_block`,
//!   `struct erofs_inode_compact`, `struct erofs_inode_extended`, the data
//!   layouts, `struct erofs_inode_chunk_index`, `struct erofs_dirent`,
//!   `struct z_erofs_map_header`, `struct z_erofs_lcluster_index` and the
//!   feature, advise and lcluster type values;
//!   `include/uapi/linux/magic.h`: `EROFS_SUPER_MAGIC_V1`.
//! - `fs/erofs/super.c`: `erofs_read_superblock`,
//!   `erofs_superblock_csum_verify` and `erofs_read_metadata`;
//!   `fs/erofs/inode.c`: `erofs_read_inode`; `fs/erofs/internal.h`:
//!   `erofs_iloc`; `fs/erofs/data.c`: `erofs_map_blocks_flatmode` and
//!   `erofs_map_blocks`; `fs/erofs/dir.c`: `erofs_readdir` and
//!   `erofs_fill_dentries`.
//! - `fs/erofs/zmap.c` (full and compact lcluster indexes, extent and
//!   pcluster lengths, tail packing), `fs/erofs/decompressor.c`
//!   (`z_erofs_fixup_insize`, `z_erofs_lz4_decompress_mem`,
//!   `z_erofs_transform_plain`, `z_erofs_parse_cfgs`),
//!   `fs/erofs/decompressor_deflate.c` and `fs/erofs/zdata.c` (when a
//!   pcluster is decoded in full).
//! - `Documentation/filesystems/erofs.rst`: the on-disk overview.
//!
//! All fields are little-endian. Block addresses count filesystem blocks
//! of `1 << blkszbits` bytes; offsets in notes and metadata are file
//! bytes. The format names no processor, so members are classified from
//! their own bytes.

use crate::error::{ClassifierError, Result};
use crate::formats::checksum::crc32c_update;
use crate::formats::container::{Container, MAX_EXTRACTED};
use crate::types::FileFormat;
use std::cell::{Cell, OnceCell};

mod inode;
mod walk;
mod zmap;

/// File offset of the superblock (`EROFS_SUPER_OFFSET`).
const EROFS_SUPER_OFFSET: usize = 1024;

/// `EROFS_SUPER_MAGIC_V1`.
const EROFS_SUPER_MAGIC_V1: u32 = 0xe0f5_e1e2;

/// Size of `struct erofs_super_block`, and of each extension slot
/// (`EROFS_SB_EXTSLOT_SIZE`).
const SUPERBLOCK_SIZE: usize = 128;
const EROFS_SB_EXTSLOT_SIZE: usize = 16;

/// `blkszbits` range. The kernel accepts 9 up to its `PAGE_SHIFT`; 16
/// (64 KiB) is the largest page size Linux supports (our bound).
const MIN_BLOCK_SIZE_BITS: u8 = 9;
const MAX_BLOCK_SIZE_BITS: u8 = 16;

/// The superblock and its extension slots must fit in a page after the
/// first 1024 bytes (`PAGE_SIZE - EROFS_SUPER_OFFSET`); 4 KiB pages are
/// assumed, or the block size when it is larger.
const MIN_PAGE_SIZE: usize = 4096;

/// Most bytes decoded from compressed files in one image: recognition
/// probes and the [`MAX_EXTRACTED`] bytes of extracted members.
const DECODE_LIMIT: u64 = 2 * MAX_EXTRACTED as u64;

/// Inode slots are 32 bytes (`islotbits` 5).
const INODE_SLOT_SIZE: u64 = 32;

/// `feature_compat` bits.
const EROFS_FEATURE_COMPAT_SB_CHKSUM: u32 = 0x0000_0001;
const EROFS_FEATURE_COMPAT_MTIME: u32 = 0x0000_0002;
const EROFS_FEATURE_COMPAT_XATTR_FILTER: u32 = 0x0000_0004;

/// `feature_incompat` bits. Two pairs share a bit: `COMPR_CFGS` and
/// `BIG_PCLUSTER`, `DEVICE_TABLE` and `COMPR_HEAD2`, `FRAGMENTS` and
/// `DEDUPE`.
const EROFS_FEATURE_INCOMPAT_ZERO_PADDING: u32 = 0x0000_0001;
const EROFS_FEATURE_INCOMPAT_COMPR_CFGS: u32 = 0x0000_0002;
const EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER: u32 = 0x0000_0002;
const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;
const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;
const EROFS_FEATURE_INCOMPAT_ZTAILPACKING: u32 = 0x0000_0010;
const EROFS_FEATURE_INCOMPAT_FRAGMENTS: u32 = 0x0000_0020;
const EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES: u32 = 0x0000_0040;

/// `EROFS_ALL_FEATURE_INCOMPAT`: the kernel refuses any other bit.
const EROFS_ALL_FEATURE_INCOMPAT: u32 = EROFS_FEATURE_INCOMPAT_ZERO_PADDING
    | EROFS_FEATURE_INCOMPAT_COMPR_CFGS
    | EROFS_FEATURE_INCOMPAT_CHUNKED_FILE
    | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE
    | EROFS_FEATURE_INCOMPAT_ZTAILPACKING
    | EROFS_FEATURE_INCOMPAT_FRAGMENTS
    | EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES;

/// Feature names, as `dump.erofs` and the kernel's feature macros name
/// them.
const COMPAT_FEATURE_NAMES: &[(u32, &str)] = &[
    (EROFS_FEATURE_COMPAT_SB_CHKSUM, "sb_csum"),
    (EROFS_FEATURE_COMPAT_MTIME, "mtime"),
    (EROFS_FEATURE_COMPAT_XATTR_FILTER, "xattr_filter"),
];
const INCOMPAT_FEATURE_NAMES: &[(u32, &str)] = &[
    (EROFS_FEATURE_INCOMPAT_ZERO_PADDING, "zero_padding"),
    (EROFS_FEATURE_INCOMPAT_COMPR_CFGS, "compr_cfgs/big_pcluster"),
    (EROFS_FEATURE_INCOMPAT_CHUNKED_FILE, "chunked_file"),
    (
        EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
        "device_table/compr_head2",
    ),
    (EROFS_FEATURE_INCOMPAT_ZTAILPACKING, "ztailpacking"),
    (EROFS_FEATURE_INCOMPAT_FRAGMENTS, "fragments/dedupe"),
    (EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES, "xattr_prefixes"),
];

/// Compression algorithms (`Z_EROFS_COMPRESSION_*`), indexed by their
/// value, and the mask of the ones the format defines.
const Z_EROFS_COMPRESSION_LZ4: u8 = 0;
const Z_EROFS_COMPRESSION_LZMA: u8 = 1;
const Z_EROFS_COMPRESSION_DEFLATE: u8 = 2;
const ALGORITHM_NAMES: [&str; 4] = ["LZ4", "LZMA", "DEFLATE", "Zstandard"];
const Z_EROFS_ALL_COMPR_ALGS: u16 = (1 << ALGORITHM_NAMES.len()) - 1;

/// An EROFS image. The format has one layout; its features are reported
/// in notes and metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// An EROFS filesystem (superblock magic `0xE0F5E1E2` at 1024).
    Erofs,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Erofs => FileFormat::Erofs,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Erofs => "EROFS",
        }
    }

    /// Detection needs the magic and a supported block size.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Erofs => false,
        }
    }
}

/// The superblock fields the reader uses, after the checks of
/// [`Superblock::parse`].
#[derive(Debug, Clone)]
struct Superblock {
    /// `blkszbits`.
    block_size_bits: u8,
    /// Block size in bytes.
    block_size: usize,
    /// `checksum`, verified when `sb_csum` is set.
    checksum: u32,
    feature_compat: u32,
    feature_incompat: u32,
    /// Superblock size including extension slots, in bytes.
    sb_size: usize,
    /// `root_nid`.
    root_nid: u64,
    /// `inos`: inodes in use.
    inos: u64,
    /// `blocks`: blocks of the primary device.
    blocks: u32,
    /// `meta_blkaddr`: first block of the inode area.
    meta_blkaddr: u32,
    uuid: [u8; 16],
    /// `volume_name`, up to its NUL byte.
    volume_name: String,
    /// `available_compr_algs` with `COMPR_CFGS`, otherwise LZ4 only.
    available_algorithms: u16,
    /// `extra_devices` with `DEVICE_TABLE`, otherwise 0.
    extra_devices: u16,
    /// `packed_nid`: the inode holding fragments, when used.
    packed_nid: u64,
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::ErofsParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated image at 0x{start:X} + {len} B")))
}

/// [`slice`] with a 64-bit offset and size from the input.
fn slice64(data: &[u8], start: u64, len: u64) -> Result<&[u8]> {
    match (usize::try_from(start), usize::try_from(len)) {
        (Ok(start), Ok(len)) => slice(data, start, len),
        _ => Err(error(format!("Truncated image at 0x{start:X} + {len} B"))),
    }
}

/// The `N` bytes of a fixed-size field at `at`.
fn field<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    let bytes = slice(data, at, N)?;
    Ok(bytes.try_into().expect("slice has exactly N bytes"))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(field(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(field(data, at)?))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(field(data, at)?))
}

/// `value` rounded up to a multiple of `align`, a power of two.
fn align_up(value: u64, align: u64) -> Option<u64> {
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
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

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// The names of the bits of `word`, with the value of bits that have no
/// name.
fn feature_names(word: u32, names: &[(u32, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut named = 0u32;
    for &(bit, name) in names {
        if word & bit != 0 {
            out.push(name.to_string());
            named |= bit;
        }
    }
    if word & !named != 0 {
        out.push(format!("0x{:X}", word & !named));
    }
    out
}

/// `uuid` in the 8-4-4-4-12 text form.
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

impl Superblock {
    /// `erofs_read_superblock`, in its order: magic, `blkszbits`,
    /// `dirblkbits`, the checksum, the incompatible features, the
    /// extension slots and the volume name. Superblock fields: magic (0),
    /// checksum (4), `feature_compat` (8), `blkszbits` (12), `sb_extslots`
    /// (13), `root_nid` (14), `inos` (16), `blocks` (36), `meta_blkaddr`
    /// (40), `uuid` (48), `volume_name` (64), `feature_incompat` (80),
    /// `u1` (84), `extra_devices` (86), `dirblkbits` (90), `packed_nid`
    /// (96).
    fn parse(data: &[u8]) -> Result<Self> {
        let sb = slice(data, EROFS_SUPER_OFFSET, SUPERBLOCK_SIZE)?;
        if le_u32(sb, 0)? != EROFS_SUPER_MAGIC_V1 {
            return Err(error("Missing EROFS superblock magic at 0x400"));
        }
        let block_size_bits = sb[12];
        if !(MIN_BLOCK_SIZE_BITS..=MAX_BLOCK_SIZE_BITS).contains(&block_size_bits) {
            return Err(error(format!(
                "Unsupported block size: blkszbits {block_size_bits}"
            )));
        }
        if sb[90] != 0 {
            return Err(error(format!("Unsupported dirblkbits {}", sb[90])));
        }
        let block_size = 1usize << block_size_bits;
        let feature_compat = le_u32(sb, 8)?;
        let checksum = le_u32(sb, 4)?;
        if feature_compat & EROFS_FEATURE_COMPAT_SB_CHKSUM != 0 {
            verify_checksum(data, block_size, checksum)?;
        }
        let feature_incompat = le_u32(sb, 80)?;
        let unknown = feature_incompat & !EROFS_ALL_FEATURE_INCOMPAT;
        if unknown != 0 {
            return Err(error(format!(
                "Unsupported incompatible features 0x{unknown:X}"
            )));
        }
        let sb_size = SUPERBLOCK_SIZE + usize::from(sb[13]) * EROFS_SB_EXTSLOT_SIZE;
        if sb_size > block_size.max(MIN_PAGE_SIZE) - EROFS_SUPER_OFFSET {
            return Err(error(format!(
                "Invalid sb_extslots {}: the superblock exceeds its block",
                sb[13]
            )));
        }
        let name_field = &sb[64..80];
        let Some(name_len) = name_field.iter().position(|&b| b == 0) else {
            return Err(error("Invalid volume name: no NUL terminator"));
        };
        let u1 = le_u16(sb, 84)?;
        let available_algorithms = if feature_incompat & EROFS_FEATURE_INCOMPAT_COMPR_CFGS != 0 {
            u1
        } else {
            1 << Z_EROFS_COMPRESSION_LZ4
        };
        let extra_devices = if feature_incompat & EROFS_FEATURE_INCOMPAT_DEVICE_TABLE != 0 {
            le_u16(sb, 86)?
        } else {
            0
        };
        Ok(Self {
            block_size_bits,
            block_size,
            checksum,
            feature_compat,
            feature_incompat,
            sb_size,
            root_nid: u64::from(le_u16(sb, 14)?),
            inos: le_u64(sb, 16)?,
            blocks: le_u32(sb, 36)?,
            meta_blkaddr: le_u32(sb, 40)?,
            uuid: field(sb, 48)?,
            volume_name: String::from_utf8_lossy(&name_field[..name_len]).into_owned(),
            available_algorithms,
            extra_devices,
            packed_nid: le_u64(sb, 96)?,
        })
    }

    fn has_incompat(&self, bit: u32) -> bool {
        self.feature_incompat & bit != 0
    }

    /// Filesystem size in bytes.
    fn size(&self) -> u64 {
        u64::from(self.blocks) << self.block_size_bits
    }

    /// Names of the available compression algorithms.
    fn algorithm_names(&self) -> Vec<&'static str> {
        ALGORITHM_NAMES
            .iter()
            .enumerate()
            .filter(|&(i, _)| self.available_algorithms & (1 << i) != 0)
            .map(|(_, &name)| name)
            .collect()
    }
}

/// `erofs_superblock_csum_verify`: CRC32C (seed `~0`, no final inversion)
/// of the bytes from the superblock to the end of block 0 (or of one
/// block's worth for blocks of 1 KiB or less), with the checksum field
/// zeroed.
fn verify_checksum(data: &[u8], block_size: usize, stored: u32) -> Result<()> {
    let len = if block_size > EROFS_SUPER_OFFSET {
        block_size - EROFS_SUPER_OFFSET
    } else {
        block_size
    };
    let bytes = slice(data, EROFS_SUPER_OFFSET, len)?;
    let crc = crc32c_update(!0, &bytes[..4]);
    let crc = crc32c_update(crc, &[0; 4]);
    let crc = crc32c_update(crc, &bytes[8..]);
    if crc != stored {
        return Err(error(format!(
            "Invalid superblock checksum 0x{stored:08X} (computed 0x{crc:08X})"
        )));
    }
    Ok(())
}

/// `z_erofs_parse_cfgs`: with `COMPR_CFGS`, the algorithms must be ones
/// the format defines and each has a configuration record (`le16` length,
/// 0 meaning 65536, then the data, 4-byte aligned) after the superblock.
fn check_compression_configs(data: &[u8], sb: &Superblock) -> Result<()> {
    if !sb.has_incompat(EROFS_FEATURE_INCOMPAT_COMPR_CFGS) {
        return Ok(());
    }
    let unknown = sb.available_algorithms & !Z_EROFS_ALL_COMPR_ALGS;
    if unknown != 0 {
        return Err(error(format!(
            "Unsupported compression algorithms 0x{unknown:X}"
        )));
    }
    let mut offset = (EROFS_SUPER_OFFSET + sb.sb_size) as u64;
    for (algorithm, name) in ALGORITHM_NAMES.iter().enumerate() {
        if sb.available_algorithms & (1 << algorithm) == 0 {
            continue;
        }
        offset = align_up(offset, 4).expect("a small offset");
        let at = usize::try_from(offset).expect("a small offset");
        let len = match le_u16(data, at)? {
            0 => 1 << 16,
            len => u64::from(len),
        };
        offset += 2;
        slice64(data, offset, len)
            .map_err(|_| error(format!("Truncated {name} configuration at 0x{at:X}")))?;
        offset += len;
    }
    Ok(())
}

/// A parsed filesystem: the bytes that belong to it and its superblock.
struct Filesystem<'a> {
    /// The filesystem's bytes (`blocks` blocks).
    data: &'a [u8],
    sb: Superblock,
    /// Bytes of metadata (inodes, directory data, compressed indexes) and
    /// decoded probe data the reader may still read; see
    /// [`Filesystem::charge`].
    budget: Cell<u64>,
    /// The budget it started with.
    initial_budget: u64,
    /// Bytes the compressed-file reader may still decode, for recognition
    /// probes and extraction together; see [`Filesystem::charge_decoded`].
    decode_budget: Cell<u64>,
    /// The packed inode's data, or why it cannot be read.
    packed: OnceCell<std::result::Result<zmap::PackedData, String>>,
    /// The packed inode is being read, so fragments are refused.
    reading_packed: Cell<bool>,
}

impl<'a> Filesystem<'a> {
    /// The reader may read twice the filesystem size in metadata and
    /// probes, but at least 1 MiB.
    fn new(data: &'a [u8], sb: Superblock) -> Self {
        let initial_budget = (data.len() as u64).saturating_mul(2).max(1 << 20);
        Self {
            data,
            sb,
            budget: Cell::new(initial_budget),
            initial_budget,
            decode_budget: Cell::new(DECODE_LIMIT),
            packed: OnceCell::new(),
            reading_packed: Cell::new(false),
        }
    }

    /// File offset of block `block`.
    fn block_offset(&self, block: u64) -> u64 {
        block << self.sb.block_size_bits
    }

    /// `len` bytes at file offset `offset`, inside the filesystem.
    fn bytes(&self, offset: u64, len: u64) -> Result<&'a [u8]> {
        slice64(self.data, offset, len).map_err(|_| {
            error(format!(
                "Invalid range 0x{offset:X} + {len} B beyond the {} B filesystem",
                self.data.len()
            ))
        })
    }

    /// Account for `size` bytes of metadata or probe data about to be read.
    fn charge(&self, size: u64) -> Result<()> {
        let remaining = self.budget.get();
        let Some(left) = remaining.checked_sub(size) else {
            self.budget.set(0);
            return Err(error(format!(
                "Invalid metadata: more than {} B read",
                self.initial_budget
            )));
        };
        self.budget.set(left);
        Ok(())
    }

    /// Account for `size` bytes about to be decoded from a compressed file.
    fn charge_decoded(&self, size: u64) -> Result<()> {
        let Some(left) = self.decode_budget.get().checked_sub(size) else {
            return Err(error(format!(
                "Unsupported extent of {size} B: more than {} decoded in this image",
                size_text(DECODE_LIMIT)
            )));
        };
        self.decode_budget.set(left);
        Ok(())
    }

    /// The read limit was reached; the walk stops.
    fn is_exhausted(&self) -> bool {
        self.budget.get() == 0
    }
}

/// Detect an EROFS image: magic `0xE0F5E1E2` at 1024 and a supported block
/// size. The checksum, features and the root directory are checked by
/// [`parse_container`], so a damaged image is a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let sb = data.get(EROFS_SUPER_OFFSET..EROFS_SUPER_OFFSET + SUPERBLOCK_SIZE)?;
    let magic = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
    let block_size_bits = sb[12];
    let supported = (MIN_BLOCK_SIZE_BITS..=MAX_BLOCK_SIZE_BITS).contains(&block_size_bits);
    (magic == EROFS_SUPER_MAGIC_V1 && supported).then_some(Layout::Erofs)
}

/// Parse an EROFS image into the shared container model. Regular files
/// that start with a recognized format are its children, labeled by their
/// path.
///
/// # Errors
///
/// [`ClassifierError::ErofsParseError`] for an invalid superblock, a
/// superblock checksum mismatch, an unsupported feature, compression
/// algorithm or block size, an image shorter than its `blocks`, data after
/// the filesystem that is neither padding nor an AVB footer, or an
/// unreadable root directory. Damage below the root is reported in notes.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let sb = Superblock::parse(data)?;
    check_compression_configs(data, &sb)?;
    let superblock_end = (EROFS_SUPER_OFFSET + sb.sb_size) as u64;
    if sb.size() < superblock_end {
        return Err(error(format!(
            "Invalid blocks {}: the filesystem ends before its superblock",
            sb.blocks
        )));
    }
    let Some(fs_size) = usize::try_from(sb.size())
        .ok()
        .filter(|&size| size <= data.len())
    else {
        return Err(error(format!(
            "Truncated filesystem: {} blocks of {} need {} B, {} B present",
            sb.blocks,
            size_text(sb.block_size as u64),
            sb.size(),
            data.len()
        )));
    };
    let trailing = &data[fs_size..];
    let mut tail_note = None;
    if !is_padding(trailing) {
        match crate::formats::android::avb_footer_original_size(data) {
            Some(original) => {
                tail_note = Some(format!(
                    "AVB footer: {} after the filesystem (original image size {original} B) hold AVB data; hashtree and signatures not verified",
                    size_text(trailing.len() as u64)
                ));
            }
            None => {
                return Err(error(format!(
                    "Invalid trailing data: {} B after the filesystem at 0x{fs_size:X} are not padding",
                    trailing.len()
                )));
            }
        }
    }
    let fs = Filesystem::new(&data[..fs_size], sb);
    let mut c = Container::new(layout.format(), layout.label(), "erofs");
    c.consumed = fs_size;
    describe(&fs, &mut c);
    c.notes.extend(tail_note);
    walk::walk(&fs, &mut c)?;
    Ok(c)
}

/// Summary notes and metadata from the superblock.
fn describe(fs: &Filesystem<'_>, c: &mut Container<'_>) {
    let sb = &fs.sb;
    let compat = feature_names(sb.feature_compat, COMPAT_FEATURE_NAMES);
    let incompat = feature_names(sb.feature_incompat, INCOMPAT_FEATURE_NAMES);
    c.notes.push(format!(
        "EROFS filesystem: {} blocks of {}; {} inodes; root nid {}",
        sb.blocks,
        size_text(sb.block_size as u64),
        sb.inos,
        sb.root_nid
    ));
    c.notes
        .push(if sb.feature_compat & EROFS_FEATURE_COMPAT_SB_CHKSUM != 0 {
            "Superblock checksum verified (CRC32C); the format has no other metadata checksums"
                .to_string()
        } else {
            "The superblock has no checksum (sb_csum not set)".to_string()
        });
    let uses_compression = sb.has_incompat(EROFS_FEATURE_INCOMPAT_COMPR_CFGS)
        || sb.has_incompat(EROFS_FEATURE_INCOMPAT_ZERO_PADDING);
    if uses_compression {
        c.notes.push(format!(
            "Compression algorithms: {}",
            sb.algorithm_names().join(", ")
        ));
    }
    if sb.extra_devices > 0 {
        c.notes.push(format!(
            "{} besides the primary one; data on them is not in this file",
            counted(
                usize::from(sb.extra_devices),
                "extra device",
                "extra devices"
            )
        ));
    }
    c.notes.push(
        "No processor field: the format names no CPU; members are classified from their own bytes"
            .to_string(),
    );
    c.push_metadata("erofs_block_size", "Block size (B)", sb.block_size as u64);
    c.push_metadata("erofs_block_count", "Blocks", u64::from(sb.blocks));
    c.push_metadata("erofs_inode_count", "Inodes", sb.inos);
    c.push_metadata("erofs_root_nid", "Root nid", sb.root_nid);
    c.push_metadata(
        "erofs_meta_blkaddr",
        "Inode area block",
        u64::from(sb.meta_blkaddr),
    );
    c.push_metadata(
        "erofs_compat_features",
        "Compatible features",
        compat.join(", "),
    );
    c.push_metadata(
        "erofs_incompat_features",
        "Incompatible features",
        incompat.join(", "),
    );
    c.push_metadata("erofs_uuid", "UUID", uuid_text(&sb.uuid));
    c.push_metadata(
        "erofs_superblock_checksum",
        "Superblock checksum",
        format!("0x{:08X}", sb.checksum),
    );
    if !sb.volume_name.is_empty() {
        c.push_metadata("erofs_volume_name", "Volume name", sb.volume_name.clone());
    }
    if sb.has_incompat(EROFS_FEATURE_INCOMPAT_FRAGMENTS) {
        c.push_metadata("erofs_packed_nid", "Packed inode nid", sb.packed_nid);
    }
    if uses_compression {
        c.push_metadata(
            "erofs_compression_algorithms",
            "Compression algorithms",
            sb.algorithm_names().join(", "),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_names_list_unnamed_bits_by_value() {
        assert_eq!(
            feature_names(
                EROFS_FEATURE_INCOMPAT_ZERO_PADDING | 0x100,
                INCOMPAT_FEATURE_NAMES
            ),
            ["zero_padding", "0x100"]
        );
        assert_eq!(align_up(13, 8), Some(16));
        assert_eq!(align_up(u64::MAX, 8), None);
        assert_eq!(size_text(4096), "4 KiB");
    }

    #[test]
    fn detection_needs_the_magic_and_a_supported_block_size() {
        let mut image = vec![0u8; 2048];
        image[1024..1028].copy_from_slice(&EROFS_SUPER_MAGIC_V1.to_le_bytes());
        image[1024 + 12] = 12;
        assert_eq!(detect(&image), Some(Layout::Erofs));
        image[1024 + 12] = 17;
        assert_eq!(detect(&image), None);
        assert_eq!(detect(&image[..1100]), None);
    }
}
