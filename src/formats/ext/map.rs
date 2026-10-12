//! File block mapping: extent trees (`ext4_extents.h`, `__ext4_ext_check`,
//! `ext4_valid_extent_entries`) and ext2/ext3 block maps with single,
//! double and triple indirect blocks (`ifork.rst`), and reading a file's
//! first bytes with holes and unwritten extents as zeros.

use super::inode::{EXT4_EXTENTS_FL, EXT4_INLINE_DATA_FL};
use super::*;
use crate::formats::checksum::crc32c_update;

/// Extent header magic (`EXT4_EXT_MAGIC`).
const EXT4_EXT_MAGIC: u16 = 0xf30a;

/// Deepest extent tree (`EXT4_MAX_EXTENT_DEPTH`).
const EXT4_MAX_EXTENT_DEPTH: u16 = 5;

/// Extent header and entry sizes; leaf extents and index entries are both
/// 12 bytes.
const EXTENT_HEADER_SIZE: usize = 12;
const EXTENT_ENTRY_SIZE: usize = 12;

/// `ee_len` above this marks an unwritten extent of
/// `ee_len - EXT_INIT_MAX_LEN` blocks, which reads as zeros.
const EXT_INIT_MAX_LEN: u16 = 1 << 15;

/// Logical blocks an extent may reach: `ee_block + len` must not wrap the
/// 32-bit logical block number.
const LOGICAL_BLOCK_LIMIT: u64 = 1 << 32;

/// Block map slots in `i_block`: 12 direct blocks, then the single, double
/// and triple indirect blocks.
const EXT4_NDIR_BLOCKS: usize = 12;
const EXT4_IND_BLOCK: usize = 12;
const EXT4_DIND_BLOCK: usize = 13;
const EXT4_TIND_BLOCK: usize = 14;

/// Size of a block number in a block map.
const BLOCK_POINTER_SIZE: usize = 4;

/// Transforms that reassemble a file's bytes from its blocks.
const EXTENT_TRANSFORM: &str = "ext extent map";
const BLOCK_MAP_TRANSFORM: &str = "ext block map";

/// Logical file blocks stored in consecutive filesystem blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Run {
    /// First logical block of the file.
    pub(super) logical: u64,
    /// First filesystem block.
    pub(super) physical: u64,
    /// Length in blocks.
    pub(super) blocks: u64,
}

/// Logical blocks `start..end`.
#[derive(Debug, Clone, Copy)]
struct Span {
    start: u64,
    end: u64,
}

impl Span {
    fn intersect(self, start: u64, end: u64) -> Option<Self> {
        let span = Self {
            start: self.start.max(start),
            end: self.end.min(end),
        };
        (span.start < span.end).then_some(span)
    }
}

/// An extent tree node header: `eh_magic`, `eh_entries` (2), `eh_max` (4),
/// `eh_depth` (6).
struct ExtentHeader {
    entries: usize,
    max: usize,
    depth: u16,
}

/// Append `run`, merging it with the previous run when both the logical
/// and the physical blocks continue it.
fn push_run(runs: &mut Vec<Run>, run: Run) {
    if let Some(last) = runs.last_mut() {
        if last.logical + last.blocks == run.logical && last.physical + last.blocks == run.physical
        {
            last.blocks += run.blocks;
            return;
        }
    }
    runs.push(run);
}

/// A 48-bit block number from a 32-bit low and a 16-bit high field
/// (`ei_leaf_lo`/`ei_leaf_hi`, `ee_start_lo`/`ee_start_hi`).
fn block_number(node: &[u8], low_at: usize, high_at: usize) -> Result<u64> {
    let low = u64::from(le_u32(node, low_at)?);
    let high = u64::from(le_u16(node, high_at)?);
    Ok(low | (high << 32))
}

/// Parse and check an extent node header in `node`, which holds the
/// header and up to `(node.len() - 12) / 12` entries.
fn extent_header(node: &[u8], number: u32) -> Result<ExtentHeader> {
    let magic = le_u16(node, 0)?;
    if magic != EXT4_EXT_MAGIC {
        return Err(error(format!(
            "Invalid inode {number} extent header magic 0x{magic:04X}"
        )));
    }
    let header = ExtentHeader {
        entries: usize::from(le_u16(node, 2)?),
        max: usize::from(le_u16(node, 4)?),
        depth: le_u16(node, 6)?,
    };
    let capacity = node.len().saturating_sub(EXTENT_HEADER_SIZE) / EXTENT_ENTRY_SIZE;
    if header.max == 0 || header.max > capacity {
        return Err(error(format!(
            "Invalid inode {number} extent header: eh_max {} (at most {capacity})",
            header.max
        )));
    }
    if header.entries > header.max {
        return Err(error(format!(
            "Invalid inode {number} extent header: eh_entries {} above eh_max {}",
            header.entries, header.max
        )));
    }
    Ok(header)
}

impl<'a> Filesystem<'a> {
    /// The stored runs of `inode`'s logical blocks below `end`, in logical
    /// order. Holes and unwritten extents are absent.
    pub(super) fn runs(&self, inode: &Inode, end: u64) -> Result<Vec<Run>> {
        let mut runs = Vec::new();
        let span = Span { start: 0, end };
        if inode.has_flag(EXT4_EXTENTS_FL) {
            let header = extent_header(&inode.block, inode.number)?;
            if header.depth > EXT4_MAX_EXTENT_DEPTH {
                return Err(error(format!(
                    "Invalid inode {} extent depth {} (at most {EXT4_MAX_EXTENT_DEPTH})",
                    inode.number, header.depth
                )));
            }
            self.extent_node(inode, &inode.block, &header, span, &mut runs)?;
        } else {
            self.block_map(inode, span, &mut runs)?;
        }
        Ok(runs)
    }

    /// Collect the runs below one extent node. An index entry covers the
    /// logical blocks from its `ei_block` to the next entry's, as the
    /// kernel's lookup assigns them, so each logical block is resolved
    /// through one path and the nodes visited are bounded by the blocks
    /// read.
    fn extent_node(
        &self,
        inode: &Inode,
        node: &[u8],
        header: &ExtentHeader,
        span: Span,
        runs: &mut Vec<Run>,
    ) -> Result<()> {
        if header.depth == 0 {
            return self.extent_leaf(inode, node, header, span, runs);
        }
        let mut previous: Option<u64> = None;
        for i in 0..header.entries {
            let at = EXTENT_HEADER_SIZE + i * EXTENT_ENTRY_SIZE;
            let first = u64::from(le_u32(node, at)?);
            if previous.is_some_and(|previous| first <= previous) {
                return Err(error(format!(
                    "Invalid inode {} extent index: logical block 0x{first:X} does not follow \
                     the previous entry",
                    inode.number
                )));
            }
            previous = Some(first);
            let start = if i == 0 { 0 } else { first };
            let end = if i + 1 < header.entries {
                u64::from(le_u32(node, at + EXTENT_ENTRY_SIZE)?)
            } else {
                u64::MAX
            };
            let Some(child_span) = span.intersect(start, end) else {
                continue;
            };
            let leaf = block_number(node, at + 4, at + 8)?;
            let child = self.metadata_block(leaf)?;
            let child_header = extent_header(child, inode.number)?;
            if child_header.depth != header.depth - 1 {
                return Err(error(format!(
                    "Invalid inode {} extent block 0x{leaf:X}: depth {} under depth {}",
                    inode.number, child_header.depth, header.depth
                )));
            }
            if let Some(seed) = inode.csum_seed {
                verify_extent_block(child, &child_header, seed, inode.number, leaf)?;
            }
            self.extent_node(inode, child, &child_header, child_span, runs)?;
        }
        Ok(())
    }

    /// Leaf extents: `ee_block`, `ee_len` (4), `ee_start_hi` (6),
    /// `ee_start_lo` (8). Extents are nonempty, sorted, do not overlap and
    /// lie in the filesystem.
    fn extent_leaf(
        &self,
        inode: &Inode,
        node: &[u8],
        header: &ExtentHeader,
        span: Span,
        runs: &mut Vec<Run>,
    ) -> Result<()> {
        let mut next_free = 0u64;
        for i in 0..header.entries {
            let at = EXTENT_HEADER_SIZE + i * EXTENT_ENTRY_SIZE;
            let first = u64::from(le_u32(node, at)?);
            let length = le_u16(node, at + 4)?;
            let (blocks, initialized) = if length > EXT_INIT_MAX_LEN {
                (u64::from(length - EXT_INIT_MAX_LEN), false)
            } else {
                (u64::from(length), true)
            };
            let end = first + blocks;
            if blocks == 0 || end > LOGICAL_BLOCK_LIMIT {
                return Err(error(format!(
                    "Invalid inode {} extent at logical block 0x{first:X}: length {blocks}",
                    inode.number
                )));
            }
            if first < next_free {
                return Err(error(format!(
                    "Invalid inode {} extent at logical block 0x{first:X}: it overlaps the \
                     previous extent",
                    inode.number
                )));
            }
            next_free = end;
            let physical = block_number(node, at + 8, at + 6)?;
            if physical
                .checked_add(blocks)
                .map_or(true, |stop| stop > self.sb.blocks_count)
            {
                return Err(error(format!(
                    "Invalid inode {} extent: blocks 0x{physical:X} + {blocks} beyond the \
                     filesystem",
                    inode.number
                )));
            }
            let Some(covered) = span.intersect(first, end) else {
                continue;
            };
            if initialized {
                push_run(
                    runs,
                    Run {
                        logical: covered.start,
                        physical: physical + (covered.start - first),
                        blocks: covered.end - covered.start,
                    },
                );
            }
        }
        Ok(())
    }

    /// An ext2/ext3 block map: `i_block[0..12]` are direct blocks, then one
    /// single, one double and one triple indirect block. Block number 0 is
    /// a hole.
    fn block_map(&self, inode: &Inode, span: Span, runs: &mut Vec<Run>) -> Result<()> {
        for slot in 0..EXT4_NDIR_BLOCKS {
            let logical = slot as u64;
            if logical >= span.end {
                return Ok(());
            }
            let pointer = le_u32(&inode.block, slot * BLOCK_POINTER_SIZE)?;
            self.map_block(inode, logical, pointer, runs)?;
        }
        let per_block = (self.sb.block_size / BLOCK_POINTER_SIZE) as u64;
        let mut first = EXT4_NDIR_BLOCKS as u64;
        for (slot, level) in [
            (EXT4_IND_BLOCK, 1),
            (EXT4_DIND_BLOCK, 2),
            (EXT4_TIND_BLOCK, 3),
        ] {
            if first >= span.end {
                break;
            }
            let pointer = le_u32(&inode.block, slot * BLOCK_POINTER_SIZE)?;
            if pointer != 0 {
                self.indirect_block(inode, pointer, level, first, span, runs)?;
            }
            first += per_block.pow(level);
        }
        Ok(())
    }

    /// One indirect block of `level` (1: block numbers of data, 2 and 3:
    /// of lower indirect blocks) whose first entry maps logical block
    /// `first`.
    fn indirect_block(
        &self,
        inode: &Inode,
        pointer: u32,
        level: u32,
        first: u64,
        span: Span,
        runs: &mut Vec<Run>,
    ) -> Result<()> {
        let number = u64::from(pointer);
        self.check_pointer(inode, number)?;
        let block = self.metadata_block(number)?;
        let per_block = (self.sb.block_size / BLOCK_POINTER_SIZE) as u64;
        let child_blocks = per_block.pow(level - 1);
        for entry in 0..self.sb.block_size / BLOCK_POINTER_SIZE {
            let logical = first + entry as u64 * child_blocks;
            if logical >= span.end {
                break;
            }
            let child = le_u32(block, entry * BLOCK_POINTER_SIZE)?;
            if child == 0 {
                continue;
            }
            if level == 1 {
                self.map_block(inode, logical, child, runs)?;
            } else {
                self.indirect_block(inode, child, level - 1, logical, span, runs)?;
            }
        }
        Ok(())
    }

    /// Map logical block `logical` to block `pointer`, unless it is a hole.
    fn map_block(
        &self,
        inode: &Inode,
        logical: u64,
        pointer: u32,
        runs: &mut Vec<Run>,
    ) -> Result<()> {
        if pointer == 0 {
            return Ok(());
        }
        let physical = u64::from(pointer);
        self.check_pointer(inode, physical)?;
        push_run(
            runs,
            Run {
                logical,
                physical,
                blocks: 1,
            },
        );
        Ok(())
    }

    fn check_pointer(&self, inode: &Inode, block: u64) -> Result<()> {
        if block >= self.sb.blocks_count {
            return Err(error(format!(
                "Invalid inode {} block map entry 0x{block:X} beyond the filesystem",
                inode.number
            )));
        }
        Ok(())
    }

    /// The first `len` bytes of `inode`'s contents. Bytes stored in one run
    /// from the start of the file are borrowed; otherwise the stored runs
    /// are copied into zeroed bytes of `len`.
    pub(super) fn read(&self, inode: &Inode, len: usize) -> Result<FileData<'a>> {
        if inode.has_flag(EXT4_INLINE_DATA_FL) {
            return Err(error(format!(
                "Unsupported inline data in inode {}",
                inode.number
            )));
        }
        let block_size = self.sb.block_size as u64;
        let end = blocks_for(len as u64, block_size);
        let runs = self.runs(inode, end)?;
        let transform = if inode.has_flag(EXT4_EXTENTS_FL) {
            EXTENT_TRANSFORM
        } else {
            BLOCK_MAP_TRANSFORM
        };
        let first_run = runs.first().map(|run| {
            let stored = usize::try_from(run.blocks * block_size).unwrap_or(usize::MAX);
            StoredRun {
                offset: self.offset(run.physical),
                size: stored.min(len - file_position(run, block_size)),
            }
        });
        if let [run] = runs[..] {
            if run.logical == 0 && run.blocks * block_size >= len as u64 {
                let stored = self.blocks(run.physical, run.blocks)?;
                return Ok(FileData {
                    bytes: Cow::Borrowed(&stored[..len]),
                    first_run,
                    transform,
                });
            }
        }
        let mut bytes = vec![0u8; len];
        for run in &runs {
            let stored = self.blocks(run.physical, run.blocks)?;
            let start = file_position(run, block_size);
            let size = stored.len().min(len - start);
            bytes[start..start + size].copy_from_slice(&stored[..size]);
        }
        Ok(FileData {
            bytes: Cow::Owned(bytes),
            first_run,
            transform,
        })
    }
}

/// Byte position of `run` in its file. [`Filesystem::read`] collects only
/// the runs below the block that holds the requested length, so each starts
/// inside the bytes read.
fn file_position(run: &Run, block_size: u64) -> usize {
    usize::try_from(run.logical * block_size).expect("runs start inside the bytes read")
}

/// Verify an extent block's tail: CRC32C from the inode's seed over the
/// header and `eh_max` entries, stored after them (`ext4_extent_block_csum`).
fn verify_extent_block(
    block: &[u8],
    header: &ExtentHeader,
    seed: u32,
    number: u32,
    location: u64,
) -> Result<()> {
    let tail = EXTENT_HEADER_SIZE + header.max * EXTENT_ENTRY_SIZE;
    let stored = le_u32(block, tail)?;
    let computed = crc32c_update(seed, slice(block, 0, tail)?);
    if stored != computed {
        return Err(error(format!(
            "Invalid inode {number} extent block 0x{location:X} checksum 0x{stored:08X} \
             (computed 0x{computed:08X})"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Blocks in the test filesystem.
    const BLOCKS: usize = 16;

    /// Pointers in one 1 KiB indirect block.
    const POINTERS_PER_BLOCK: u64 = 256;

    /// A filesystem of [`BLOCKS`] 1 KiB blocks without group descriptors:
    /// enough for the block mapping, which reads only blocks.
    fn filesystem(data: &[u8]) -> Filesystem<'_> {
        Filesystem {
            data,
            sb: Superblock::for_tests(BLOCKS as u64, 8192),
            groups: Vec::new(),
            csum_seed: None,
            verify_inodes: false,
            metadata_budget: Cell::new(u64::MAX),
        }
    }

    /// A regular file inode whose block map holds `(slot, block number)`.
    fn block_map_inode(slots: &[(usize, u32)]) -> Inode {
        let mut block = [0u8; inode::I_BLOCK_SIZE];
        for &(slot, number) in slots {
            let at = slot * BLOCK_POINTER_SIZE;
            block[at..at + BLOCK_POINTER_SIZE].copy_from_slice(&number.to_le_bytes());
        }
        Inode {
            number: 12,
            // S_IFREG with permissions 0644.
            mode: 0x81a4,
            size: 0,
            flags: 0,
            block,
            csum_seed: None,
        }
    }

    /// Store block number `value` as entry `entry` of block `block`.
    fn set_pointer(data: &mut [u8], block: usize, entry: usize, value: u32) {
        let at = block * EXT4_MIN_BLOCK_SIZE + entry * BLOCK_POINTER_SIZE;
        data[at..at + BLOCK_POINTER_SIZE].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn block_maps_resolve_direct_single_double_and_triple_indirect_blocks() {
        let mut data = vec![0u8; BLOCKS * EXT4_MIN_BLOCK_SIZE];
        // Triple-indirect block 1 -> double-indirect block 2 -> indirect
        // block 3, whose first two entries map blocks 5 and 6.
        set_pointer(&mut data, 1, 0, 2);
        set_pointer(&mut data, 2, 0, 3);
        set_pointer(&mut data, 3, 0, 5);
        set_pointer(&mut data, 3, 1, 6);
        // Double-indirect block 9, entry 1 -> indirect block 10, entry 3 ->
        // block 11.
        set_pointer(&mut data, 9, 1, 10);
        set_pointer(&mut data, 10, 3, 11);
        // Single-indirect block 4, entry 2 -> block 7.
        set_pointer(&mut data, 4, 2, 7);
        let fs = filesystem(&data);
        let inode = block_map_inode(&[
            (0, 8),
            (EXT4_IND_BLOCK, 4),
            (EXT4_DIND_BLOCK, 9),
            (EXT4_TIND_BLOCK, 1),
        ]);
        let single = EXT4_NDIR_BLOCKS as u64;
        let double = single + POINTERS_PER_BLOCK;
        let triple = double + POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
        let runs = fs.runs(&inode, triple + 2).expect("valid block map");
        let expected = [
            Run {
                logical: 0,
                physical: 8,
                blocks: 1,
            },
            Run {
                logical: single + 2,
                physical: 7,
                blocks: 1,
            },
            Run {
                logical: double + POINTERS_PER_BLOCK + 3,
                physical: 11,
                blocks: 1,
            },
            // Blocks 5 and 6 continue each other and are merged.
            Run {
                logical: triple,
                physical: 5,
                blocks: 2,
            },
        ];
        assert_eq!(runs, expected);
        // Only the runs below the requested end are collected.
        assert_eq!(fs.runs(&inode, triple + 1).expect("valid")[3].blocks, 1);
        assert_eq!(fs.runs(&inode, 1).expect("valid"), expected[..1]);
    }

    #[test]
    fn block_map_entries_beyond_the_filesystem_are_errors() {
        let mut data = vec![0u8; BLOCKS * EXT4_MIN_BLOCK_SIZE];
        set_pointer(&mut data, 1, 0, 16);
        let fs = filesystem(&data);
        let inode = block_map_inode(&[(EXT4_IND_BLOCK, 1)]);
        let message = fs.runs(&inode, 64).expect_err("out of range").to_string();
        assert!(
            message.contains("block map entry 0x10 beyond the filesystem"),
            "{message}"
        );
    }

    #[test]
    fn extent_headers_bound_entries_by_the_node_size() {
        let mut node = [0u8; inode::I_BLOCK_SIZE];
        node[..2].copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
        // eh_entries 1, eh_max 4: the root holds four entries.
        node[2..4].copy_from_slice(&1u16.to_le_bytes());
        node[4..6].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(extent_header(&node, 12).expect("valid").max, 4);
        node[4..6].copy_from_slice(&5u16.to_le_bytes());
        assert!(extent_header(&node, 12).is_err(), "eh_max 5 in 60 bytes");
        node[4..6].copy_from_slice(&0u16.to_le_bytes());
        assert!(extent_header(&node, 12).is_err(), "eh_max 0");
    }
}
