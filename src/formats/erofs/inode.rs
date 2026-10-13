//! Inodes and the uncompressed data layouts: `erofs_read_inode` for the
//! 32-byte compact and 64-byte extended inodes, and
//! `erofs_map_blocks_flatmode` and `erofs_map_blocks` for the flat-plain,
//! flat-inline (tail packing) and chunk-based layouts. Compressed layouts
//! are read by [`super::zmap`].

use super::*;
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;

/// `i_format`: bit 0 is the inode version, bits 1-3 the data layout; the
/// kernel refuses higher bits (`EROFS_I_ALL`).
const EROFS_I_VERSION_MASK: u16 = 0x01;
const EROFS_I_DATALAYOUT_BIT: u16 = 1;
const EROFS_I_DATALAYOUT_MASK: u16 = 0x07;
const EROFS_I_ALL: u16 = 0x0f;

/// Inode versions (`EROFS_INODE_LAYOUT_*`) and their sizes.
const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;
const COMPACT_INODE_SIZE: u64 = 32;
const EXTENDED_INODE_SIZE: u64 = 64;

/// Data layouts (`EROFS_INODE_*`).
const EROFS_INODE_FLAT_PLAIN: u16 = 0;
const EROFS_INODE_COMPRESSED_FULL: u16 = 1;
const EROFS_INODE_FLAT_INLINE: u16 = 2;
const EROFS_INODE_COMPRESSED_COMPACT: u16 = 3;
const EROFS_INODE_CHUNK_BASED: u16 = 4;

/// Chunk format (`i_u.c.format`): chunk size bits above the block size,
/// and the flag for 8-byte chunk indexes instead of a 4-byte block map.
const EROFS_CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001f;
const EROFS_CHUNK_FORMAT_INDEXES: u16 = 0x0020;
const EROFS_CHUNK_FORMAT_ALL: u16 = EROFS_CHUNK_FORMAT_BLKBITS_MASK | EROFS_CHUNK_FORMAT_INDEXES;

/// Block map entry and chunk index sizes (`EROFS_BLOCK_MAP_ENTRY_SIZE`,
/// `struct erofs_inode_chunk_index`), and the hole address
/// (`EROFS_NULL_ADDR`).
const BLOCK_MAP_ENTRY_SIZE: u64 = 4;
const CHUNK_INDEX_SIZE: u64 = 8;
const EROFS_NULL_ADDR: u32 = 0xffff_ffff;

/// The inline xattr header (`struct erofs_xattr_ibody_header`) and the
/// 4-byte units counted by `i_xattr_icount` after it.
const XATTR_IBODY_HEADER_SIZE: u64 = 12;
const XATTR_ENTRY_UNIT: u64 = 4;

/// File type bits of `i_mode`.
const S_IFMT: u16 = 0o170_000;
const S_IFSOCK: u16 = 0o140_000;
const S_IFLNK: u16 = 0o120_000;
const S_IFREG: u16 = 0o100_000;
const S_IFBLK: u16 = 0o060_000;
const S_IFDIR: u16 = 0o040_000;
const S_IFCHR: u16 = 0o020_000;
const S_IFIFO: u16 = 0o010_000;

/// Transform names for file data that is not one stored run.
const TAIL_TRANSFORM: &str = "EROFS tail packing";
const CHUNK_TRANSFORM: &str = "EROFS chunks";

/// An inode's data layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DataLayout {
    /// All blocks at `raw_blkaddr`.
    FlatPlain,
    /// Compressed, one 8-byte index per logical cluster.
    CompressedFull,
    /// Blocks at `raw_blkaddr`, the last partial block after the inode.
    FlatInline,
    /// Compressed, compacted 2- and 4-byte indexes.
    CompressedCompact,
    /// Chunks located by a block map or chunk indexes.
    ChunkBased,
}

impl DataLayout {
    pub(super) fn is_compressed(self) -> bool {
        matches!(self, Self::CompressedFull | Self::CompressedCompact)
    }
}

/// An inode after the checks of `erofs_read_inode`.
#[derive(Debug, Clone)]
pub(super) struct Inode {
    pub(super) nid: u64,
    /// File offset of the inode (`erofs_iloc`).
    pub(super) offset: u64,
    /// 32 or 64 bytes.
    pub(super) record_size: u64,
    /// Inline xattr bytes after the inode.
    pub(super) xattr_size: u64,
    pub(super) layout: DataLayout,
    pub(super) mode: u16,
    /// File size in bytes.
    pub(super) size: u64,
    /// `i_u`: `raw_blkaddr`, `compressed_blocks` or the chunk format.
    pub(super) union: u32,
}

impl Inode {
    pub(super) fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub(super) fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    /// File offset just after the inode and its inline xattrs, where
    /// inline data, chunk tables and compressed indexes start.
    pub(super) fn body_offset(&self) -> u64 {
        self.offset + self.record_size + self.xattr_size
    }
}

/// Bytes read from a file, borrowed when they are stored contiguously.
pub(super) struct FileData<'a> {
    pub(super) bytes: Cow<'a, [u8]>,
    /// The first stored run, if any byte is stored.
    pub(super) first_run: Option<StoredRun>,
    /// How the bytes were reassembled or decoded when they are not one
    /// stored run.
    pub(super) transform: &'static str,
}

/// File bytes stored contiguously in the image.
#[derive(Debug, Clone, Copy)]
pub(super) struct StoredRun {
    /// File offset in the image.
    pub(super) offset: usize,
    /// Size in bytes.
    pub(super) size: usize,
}

impl<'a> FileData<'a> {
    /// One stored run.
    fn stored(offset: u64, bytes: &'a [u8]) -> Self {
        Self {
            first_run: (!bytes.is_empty()).then(|| StoredRun {
                offset: usize::try_from(offset).expect("the run lies in the image"),
                size: bytes.len(),
            }),
            bytes: Cow::Borrowed(bytes),
            transform: "",
        }
    }
}

/// Inline xattr size for `i_xattr_icount` (`erofs_xattr_ibody_size`).
fn xattr_size(icount: u16) -> u64 {
    if icount == 0 {
        return 0;
    }
    XATTR_IBODY_HEADER_SIZE + XATTR_ENTRY_UNIT * (u64::from(icount) - 1)
}

/// `i_u.c.format`: the low 16 bits of `i_u` (`struct
/// erofs_inode_chunk_info`).
fn chunk_format(union: u32) -> u16 {
    u16::try_from(union & 0xffff).expect("masked to 16 bits")
}

/// `value` divided by `2^bits`, rounded up.
pub(super) fn shift_up(value: u64, bits: u32) -> u64 {
    (value >> bits) + u64::from(value & ((1 << bits) - 1) != 0)
}

impl<'a> Filesystem<'a> {
    /// Inode `nid`: compact (`i_format` 0, `i_xattr_icount` 2, `i_mode` 4,
    /// `i_size` u32 8, `i_u` 16) or extended (`i_size` u64 8, `i_u` 16).
    pub(super) fn inode(&self, nid: u64) -> Result<Inode> {
        let offset = nid
            .checked_mul(INODE_SLOT_SIZE)
            .and_then(|slot| slot.checked_add(self.block_offset(u64::from(self.sb.meta_blkaddr))))
            .ok_or_else(|| error(format!("Invalid nid {nid}")))?;
        let compact = self.bytes(offset, COMPACT_INODE_SIZE)?;
        let format = le_u16(compact, 0)?;
        if format & !EROFS_I_ALL != 0 {
            return Err(error(format!(
                "Unsupported i_format 0x{format:X} of nid {nid}"
            )));
        }
        let layout = match (format >> EROFS_I_DATALAYOUT_BIT) & EROFS_I_DATALAYOUT_MASK {
            EROFS_INODE_FLAT_PLAIN => DataLayout::FlatPlain,
            EROFS_INODE_COMPRESSED_FULL => DataLayout::CompressedFull,
            EROFS_INODE_FLAT_INLINE => DataLayout::FlatInline,
            EROFS_INODE_COMPRESSED_COMPACT => DataLayout::CompressedCompact,
            EROFS_INODE_CHUNK_BASED => DataLayout::ChunkBased,
            other => {
                return Err(error(format!(
                    "Unsupported data layout {other} of nid {nid}"
                )))
            }
        };
        let extended = format & EROFS_I_VERSION_MASK == EROFS_INODE_LAYOUT_EXTENDED;
        let (record_size, size) = if extended {
            let bytes = self.bytes(offset, EXTENDED_INODE_SIZE)?;
            (EXTENDED_INODE_SIZE, le_u64(bytes, 8)?)
        } else {
            (COMPACT_INODE_SIZE, u64::from(le_u32(compact, 8)?))
        };
        self.charge(record_size)?;
        let mode = le_u16(compact, 4)?;
        if !matches!(
            mode & S_IFMT,
            S_IFREG | S_IFDIR | S_IFLNK | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK
        ) {
            return Err(error(format!("Invalid i_mode 0o{mode:o} of nid {nid}")));
        }
        let union = le_u32(compact, 16)?;
        if layout == DataLayout::ChunkBased && chunk_format(union) & !EROFS_CHUNK_FORMAT_ALL != 0 {
            return Err(error(format!(
                "Unsupported chunk format 0x{:X} of nid {nid}",
                chunk_format(union)
            )));
        }
        Ok(Inode {
            nid,
            offset,
            record_size,
            xattr_size: xattr_size(le_u16(compact, 2)?),
            layout,
            mode,
            size,
            union,
        })
    }

    /// The first `len` bytes of `inode`'s data (`len` at most its size and
    /// at most [`MAX_PAYLOAD`]).
    pub(super) fn read(&self, inode: &Inode, len: u64) -> Result<FileData<'a>> {
        if len > inode.size || len > MAX_PAYLOAD as u64 {
            return Err(error(format!(
                "Unsupported read of {len} B from nid {} ({} B)",
                inode.nid, inode.size
            )));
        }
        match inode.layout {
            DataLayout::FlatPlain | DataLayout::FlatInline => self.read_flat(inode, len),
            DataLayout::ChunkBased => self.read_chunks(inode, len),
            DataLayout::CompressedFull | DataLayout::CompressedCompact => {
                zmap::read(self, inode, len)
            }
        }
    }

    /// `erofs_map_blocks_flatmode`: whole blocks at `raw_blkaddr`, and for
    /// flat-inline files the last block's bytes after the inode, which may
    /// not cross a block boundary.
    fn read_flat(&self, inode: &Inode, len: u64) -> Result<FileData<'a>> {
        let block_size = self.sb.block_size as u64;
        // Bytes stored in whole blocks: all of them for flat-plain files;
        // all but the last block's for flat-inline files, whose last block
        // (partial or full) follows the inode.
        let in_blocks = match inode.layout {
            DataLayout::FlatInline if inode.size > 0 => (inode.size - 1) & !(block_size - 1),
            DataLayout::FlatInline => 0,
            _ => inode.size,
        };
        let start = self.block_offset(u64::from(inode.union));
        if len <= in_blocks {
            return Ok(FileData::stored(start, self.bytes(start, len)?));
        }
        let tail_len = inode.size - in_blocks;
        let tail_at = inode.body_offset();
        if tail_at % block_size + tail_len > block_size {
            return Err(error(format!(
                "Invalid inline data of nid {}: {tail_len} B at 0x{tail_at:X} cross a block boundary",
                inode.nid
            )));
        }
        let tail = self.bytes(tail_at, len - in_blocks)?;
        if in_blocks == 0 {
            return Ok(FileData::stored(tail_at, tail));
        }
        let head = self.bytes(start, in_blocks)?;
        let mut bytes = Vec::with_capacity(head.len() + tail.len());
        bytes.extend_from_slice(head);
        bytes.extend_from_slice(tail);
        Ok(FileData {
            bytes: Cow::Owned(bytes),
            first_run: FileData::stored(start, head).first_run,
            transform: TAIL_TRANSFORM,
        })
    }

    /// `erofs_map_blocks` for chunk-based files: a 4-byte block address or
    /// an 8-byte index (`advise`, `device_id`, `blkaddr`) per chunk, after
    /// the inode aligned to the entry size; `EROFS_NULL_ADDR` is a hole.
    fn read_chunks(&self, inode: &Inode, len: u64) -> Result<FileData<'a>> {
        let format = chunk_format(inode.union);
        // At most 16 + 31 bits, so chunk sizes fit in 64 bits.
        let chunk_bits = u32::from(self.sb.block_size_bits)
            + u32::from(format & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
        let unit = if format & EROFS_CHUNK_FORMAT_INDEXES != 0 {
            CHUNK_INDEX_SIZE
        } else {
            BLOCK_MAP_ENTRY_SIZE
        };
        let table = align_up(inode.body_offset(), unit)
            .ok_or_else(|| error(format!("Invalid chunk table of nid {}", inode.nid)))?;
        let device_mask = (u32::from(self.sb.extra_devices) + 1).next_power_of_two() - 1;
        let chunk_size = 1u64 << chunk_bits;
        let chunks = shift_up(len, chunk_bits);
        // Stored runs as (file offset, size), merged when consecutive chunks
        // are stored back to back.
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let mut follows_stored_chunk = false;
        let mut out = Vec::new();
        for k in 0..chunks {
            let entry_at = table + k * unit;
            let entry = self.bytes(entry_at, unit)?;
            self.charge(unit)?;
            let (device, blkaddr) = if unit == CHUNK_INDEX_SIZE {
                (
                    u32::from(le_u16(entry, 2)?) & device_mask,
                    le_u32(entry, 4)?,
                )
            } else {
                (0, le_u32(entry, 0)?)
            };
            let chunk_len = chunk_size.min(len - k * chunk_size);
            if blkaddr == EROFS_NULL_ADDR {
                let hole = usize::try_from(chunk_len).expect("at most the read length");
                out.resize(out.len() + hole, 0);
                follows_stored_chunk = false;
                continue;
            }
            if device != 0 {
                return Err(error(format!(
                    "Unsupported chunk {k} of nid {} on extra device {device}",
                    inode.nid
                )));
            }
            let at = self.block_offset(u64::from(blkaddr));
            out.extend_from_slice(self.bytes(at, chunk_len)?);
            match runs.last_mut() {
                Some((start, size)) if follows_stored_chunk && *start + *size == at => {
                    *size += chunk_len;
                }
                _ => runs.push((at, chunk_len)),
            }
            follows_stored_chunk = true;
        }
        if let [(offset, size)] = runs.as_slice() {
            if *size == len {
                return Ok(FileData::stored(*offset, self.bytes(*offset, *size)?));
            }
        }
        let first_run = runs.first().map(|&(offset, size)| StoredRun {
            offset: usize::try_from(offset).expect("the run lies in the image"),
            size: usize::try_from(size).expect("the run lies in the image"),
        });
        Ok(FileData {
            bytes: Cow::Owned(out),
            first_run,
            transform: CHUNK_TRANSFORM,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_xattrs_count_a_header_and_4_byte_units() {
        assert_eq!(xattr_size(0), 0);
        assert_eq!(xattr_size(1), 12);
        assert_eq!(xattr_size(3), 20);
        assert_eq!(shift_up(4097, 12), 2);
        assert_eq!(shift_up(4096, 12), 1);
        assert_eq!(shift_up(0, 12), 0);
    }
}
