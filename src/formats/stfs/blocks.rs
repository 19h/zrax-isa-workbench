//! STFS block addressing and hash tables (sources in the family module).
//!
//! Blocks are 4 KiB. Data blocks are numbered from 0 without the hash
//! tables stored between them: a level-0 table for every 170 data blocks,
//! a level-1 table for every 170 level-0 tables and one level-2 table, each
//! stored once (the read-only format) or twice, with the parent record
//! choosing the active copy. Velocity and xenia map block numbers to
//! backing blocks (4 KiB slots counted from the first hash table) with the
//! same formulas, which this module follows. Every hash table that is read
//! is checked once against the SHA-1 in its parent record (the top table
//! against the volume descriptor), and every data block that is read
//! against its level-0 record.

use super::*;
use std::collections::BTreeSet;

/// Block size, 0x1000 bytes (Free60; xenia `kBlockSize`).
pub(super) const BLOCK_SHIFT: u32 = 12;
pub(super) const BLOCK_SIZE: usize = 1 << BLOCK_SHIFT;

/// Records per hash table (Free60: a hash block for every 0xAA blocks).
const TABLE_RECORDS: u32 = 170;

/// Data blocks one hash table covers at levels 0, 1 and 2 (xenia
/// `kBlocksPerHashLevel`). The level-2 count is also the most blocks a
/// volume may allocate (Velocity `CalcualateTopLevel`).
const BLOCKS_PER_LEVEL: [u32; 3] = [170, 28_900, 4_913_000];
const MAX_BLOCKS: u32 = BLOCKS_PER_LEVEL[2];

/// A hash record (Free60; xenia `StfsHashEntry`): the SHA-1 of the block
/// or table below, a status byte and a 24-bit big-endian next block.
const RECORD_SIZE: usize = 0x18;
const RECORD_SHA1_SIZE: usize = 0x14;
const RECORD_STATUS: usize = 0x14;
const RECORD_NEXT_BLOCK: usize = 0x15;

/// Status bit of a level-1 or level-2 record that selects the second copy
/// of the table below (Velocity `(status & 0x40) << 6`; xenia
/// `levelN_active_index`).
const ACTIVE_INDEX: u8 = 0x40;

/// The next block that ends a chain (xenia `kEndOfChain`).
pub(super) const END_OF_CHAIN: u32 = 0xFF_FFFF;

/// Block separation flags (xenia `StfsVolumeDescriptor` `flags`): one copy
/// of each hash table instead of two, and the top table's active copy is
/// the second.
const READ_ONLY_FORMAT: u8 = 0x01;
const ROOT_ACTIVE_INDEX: u8 = 0x02;

/// Volume descriptor fields, relative to the descriptor: block separation,
/// file table block count (16-bit little-endian), file table block number
/// (24-bit little-endian), top hash table SHA-1, then the allocated and
/// free block counts (32-bit big-endian).
const BLOCK_SEPARATION_FIELD: usize = 0x02;
const FILE_TABLE_BLOCKS_FIELD: usize = 0x03;
const FILE_TABLE_BLOCK_FIELD: usize = 0x05;
const TOP_HASH_FIELD: usize = 0x08;
const ALLOCATED_BLOCKS_FIELD: usize = 0x1C;
const FREE_BLOCKS_FIELD: usize = 0x20;

/// A defect that leaves one file, or the whole file table, unreadable.
pub(super) type Walk<T> = std::result::Result<T, String>;

/// The STFS volume descriptor (Free60 "Volume Descriptor"; Velocity
/// `ReadStfsVolumeDescriptorEx`; xenia `StfsVolumeDescriptor`).
pub(super) struct VolumeDescriptor {
    /// Flags: read-only format (bit 0), top table's active copy (bit 1).
    pub(super) block_separation: u8,
    /// Blocks in the file table chain.
    pub(super) file_table_blocks: u16,
    /// First block of the file table.
    pub(super) file_table_block: u32,
    /// SHA-1 of the active copy of the top hash table.
    pub(super) top_hash: [u8; RECORD_SHA1_SIZE],
    /// Data blocks allocated in the volume.
    pub(super) allocated_blocks: u32,
    /// Allocated blocks that are free.
    pub(super) free_blocks: u32,
}

impl VolumeDescriptor {
    /// The descriptor at `at`, whose size byte the header check has read.
    pub(super) fn read(data: &[u8], at: usize) -> Result<Self> {
        let descriptor = slice(data, at, usize::from(VOLUME_DESCRIPTOR_SIZE))?;
        Ok(Self {
            block_separation: descriptor[BLOCK_SEPARATION_FIELD],
            file_table_blocks: le_u16(descriptor, FILE_TABLE_BLOCKS_FIELD)?,
            file_table_block: le_u24(descriptor, FILE_TABLE_BLOCK_FIELD)?,
            top_hash: array(descriptor, TOP_HASH_FIELD)?,
            allocated_blocks: be_u32(descriptor, ALLOCATED_BLOCKS_FIELD)?,
            free_blocks: be_u32(descriptor, FREE_BLOCKS_FIELD)?,
        })
    }

    fn is_read_only_format(&self) -> bool {
        self.block_separation & READ_ONLY_FORMAT != 0
    }
}

/// Where data blocks and hash tables lie.
#[derive(Debug, Clone, Copy)]
struct Geometry {
    /// File offset of the first hash table: the header size rounded up to
    /// 4 KiB.
    first_table_offset: u64,
    /// Backing blocks per hash table: 1 in the read-only format, else 2.
    copies: u64,
    /// Data blocks allocated in the volume.
    allocated_blocks: u32,
}

impl Geometry {
    /// The highest hash level: 0 for up to 170 blocks, 1 for up to 28,900,
    /// else 2 (Velocity `CalcualateTopLevel`).
    fn top_level(&self) -> usize {
        BLOCKS_PER_LEVEL
            .iter()
            .position(|&covered| self.allocated_blocks <= covered)
            .unwrap_or(BLOCKS_PER_LEVEL.len() - 1)
    }

    /// Backing block of data block `block` (xenia `BlockToOffsetSTFS`;
    /// Velocity `ComputeBackingDataBlockNumber`): the data blocks before it
    /// and the tables stored before it, which are one level-0 table per
    /// started group of 170 blocks, from block 170 on one level-1 table per
    /// started group of 28,900 blocks, and from block 28,900 on the level-2
    /// table.
    fn data_slot(&self, block: u32) -> u64 {
        let block = u64::from(block);
        let [level0, level1, _] = BLOCKS_PER_LEVEL.map(u64::from);
        let mut tables = block / level0 + 1;
        if block >= level0 {
            tables += block / level1 + 1;
        }
        if block >= level1 {
            tables += 1;
        }
        block + tables * self.copies
    }

    /// Backing block of the first copy of the level-`level` table that
    /// covers data block `block` (xenia `BlockToHashBlockNumberSTFS`;
    /// Velocity `ComputeLevel0BackingHashBlockNumber` to
    /// `ComputeLevel2BackingHashBlockNumber`). The first level-1 table
    /// follows the first 170 data blocks; later ones precede their groups.
    fn table_slot(&self, level: usize, block: u32) -> u64 {
        let block = u64::from(block);
        let [level0, level1, _] = BLOCKS_PER_LEVEL.map(u64::from);
        // Backing blocks from one level-0 table to the next (Velocity
        // `blockStep[0]`), and from the level-2 table to the second
        // level-1 table (`blockStep[1]`).
        let step0 = level0 + self.copies;
        let step1 = level1 + (level0 + 1) * self.copies;
        match level {
            0 if block < level0 => 0,
            0 => {
                let slot = block / level0 * step0 + (block / level1 + 1) * self.copies;
                if block < level1 {
                    slot
                } else {
                    slot + self.copies
                }
            }
            1 if block < level1 => step0,
            1 => block / level1 * step1 + self.copies,
            _ => step1,
        }
    }

    fn slot_offset(&self, slot: u64) -> u64 {
        self.first_table_offset + slot * BLOCK_SIZE as u64
    }

    /// File offset of data block `block`.
    fn block_offset(&self, block: u32) -> u64 {
        self.slot_offset(self.data_slot(block))
    }

    /// File offset just past the last allocated data block, or of the
    /// first hash table when no block is allocated.
    fn end_offset(&self) -> u64 {
        match self.allocated_blocks.checked_sub(1) {
            Some(last) => self.block_offset(last) + BLOCK_SIZE as u64,
            None => self.first_table_offset,
        }
    }
}

/// A hash record.
#[derive(Debug, Clone, Copy)]
pub(super) struct HashRecord {
    sha1: [u8; RECORD_SHA1_SIZE],
    status: u8,
    /// Next block of the chain, or [`END_OF_CHAIN`] (level-0 records).
    pub(super) next_block: u32,
}

/// Record `index` (below 170) of a 4 KiB hash table.
fn record_at(table: &[u8], index: u32) -> Walk<HashRecord> {
    let at = index as usize * RECORD_SIZE;
    let record = table
        .get(at..at + RECORD_SIZE)
        .ok_or_else(|| format!("hash record {index} lies outside its table"))?;
    Ok(HashRecord {
        sha1: record[..RECORD_SHA1_SIZE]
            .try_into()
            .expect("a record holds a SHA-1"),
        status: record[RECORD_STATUS],
        next_block: be_u24(record, RECORD_NEXT_BLOCK).expect("a record holds a next block"),
    })
}

/// A data block as stored in the file.
#[derive(Debug, Clone, Copy)]
pub(super) struct StoredBlock<'a> {
    /// File offset of the block.
    pub(super) offset: usize,
    /// The 4 KiB of the block.
    pub(super) bytes: &'a [u8],
}

/// What the SHA-1 checks found, for the notes.
#[derive(Debug, Default)]
struct HashCheck {
    top_table_matches: bool,
    /// Hash tables below the top table that were checked.
    tables: usize,
    table_mismatches: usize,
    /// Data blocks that were checked.
    blocks: usize,
    block_mismatches: usize,
    /// The first table or block whose SHA-1 did not match.
    first_mismatch: Option<String>,
}

/// An STFS volume: its geometry, the top table's state and the SHA-1
/// checks made so far.
pub(super) struct Volume<'a> {
    data: &'a [u8],
    geometry: Geometry,
    block_separation: u8,
    top_hash: [u8; RECORD_SHA1_SIZE],
    free_blocks: u32,
    /// File offsets of the tables checked so far, so each is hashed once.
    checked_tables: BTreeSet<u64>,
    check: HashCheck,
}

impl<'a> Volume<'a> {
    /// The volume of a package whose header is `header_size` bytes. The
    /// top hash table must lie in the file when any block is allocated.
    pub(super) fn new(
        data: &'a [u8],
        header_size: u32,
        descriptor: &VolumeDescriptor,
    ) -> Result<Self> {
        if descriptor.allocated_blocks > MAX_BLOCKS {
            return Err(error(format!(
                "Invalid STFS allocated block count {} at 0x{:X}: at most {MAX_BLOCKS}",
                descriptor.allocated_blocks,
                VOLUME_DESCRIPTOR_OFFSET + ALLOCATED_BLOCKS_FIELD
            )));
        }
        let copies = if descriptor.is_read_only_format() {
            1
        } else {
            2
        };
        let mut volume = Self {
            data,
            geometry: Geometry {
                first_table_offset: round_up_to_block(header_size) as u64,
                copies,
                allocated_blocks: descriptor.allocated_blocks,
            },
            block_separation: descriptor.block_separation,
            top_hash: descriptor.top_hash,
            free_blocks: descriptor.free_blocks,
            checked_tables: BTreeSet::new(),
            check: HashCheck::default(),
        };
        if descriptor.allocated_blocks > 0 {
            let top = volume.geometry.top_level();
            let offset = volume.table_offset(top, 0, volume.is_top_second_copy());
            let table = range(data, offset, BLOCK_SIZE)
                .ok_or_else(|| error(format!("Truncated STFS top hash table at 0x{offset:X}")))?;
            volume.check.top_table_matches = sha1(table) == volume.top_hash;
        }
        Ok(volume)
    }

    /// Data blocks allocated in the volume.
    pub(super) fn allocated_blocks(&self) -> u32 {
        self.geometry.allocated_blocks
    }

    /// The top table's active copy is the second one: only when there are
    /// two copies (xenia ignores the flag in the read-only format, where
    /// the second copy would be a data block).
    fn is_top_second_copy(&self) -> bool {
        self.geometry.copies == 2 && self.block_separation & ROOT_ACTIVE_INDEX != 0
    }

    /// File offset of a copy of the level-`level` table covering `block`.
    fn table_offset(&self, level: usize, block: u32, second_copy: bool) -> u64 {
        let first = self
            .geometry
            .slot_offset(self.geometry.table_slot(level, block));
        if second_copy {
            first + BLOCK_SIZE as u64
        } else {
            first
        }
    }

    /// The active copy of the level-`level` table covering `block`, which
    /// is checked against its parent record the first time it is read.
    fn table(&mut self, level: usize, block: u32) -> Walk<&'a [u8]> {
        let top = self.geometry.top_level();
        if level == top {
            let offset = self.table_offset(top, block, self.is_top_second_copy());
            return range(self.data, offset, BLOCK_SIZE).ok_or_else(|| {
                format!("the top hash table at 0x{offset:X} lies outside the file")
            });
        }
        let parent = self.table(level + 1, block)?;
        let record = record_at(parent, (block / BLOCKS_PER_LEVEL[level]) % TABLE_RECORDS)?;
        let second_copy = self.geometry.copies == 2 && record.status & ACTIVE_INDEX != 0;
        let offset = self.table_offset(level, block, second_copy);
        let table = range(self.data, offset, BLOCK_SIZE).ok_or_else(|| {
            format!("the level-{level} hash table at 0x{offset:X} lies outside the file")
        })?;
        if self.checked_tables.insert(offset) {
            self.check.tables += 1;
            if sha1(table) != record.sha1 {
                self.check.table_mismatches += 1;
                self.mismatch(format!("level-{level} hash table at 0x{offset:X}"));
            }
        }
        Ok(table)
    }

    /// The level-0 record of `block`.
    pub(super) fn record(&mut self, block: u32) -> Walk<HashRecord> {
        self.ensure_allocated(block)?;
        let table = self.table(0, block)?;
        record_at(table, block % TABLE_RECORDS)
    }

    /// The stored bytes of `block`, not checked (a recognition probe).
    pub(super) fn unchecked_block(&self, block: u32) -> Walk<StoredBlock<'a>> {
        self.ensure_allocated(block)?;
        let offset = self.geometry.block_offset(block);
        let bytes = range(self.data, offset, BLOCK_SIZE)
            .ok_or_else(|| format!("data block {block} at 0x{offset:X} lies outside the file"))?;
        let offset = usize::try_from(offset).expect("the block lies in the file");
        Ok(StoredBlock { offset, bytes })
    }

    /// The stored bytes of `block`, checked against its level-0 record.
    pub(super) fn block(&mut self, block: u32) -> Walk<StoredBlock<'a>> {
        let stored = self.unchecked_block(block)?;
        let record = self.record(block)?;
        self.check.blocks += 1;
        if sha1(stored.bytes) != record.sha1 {
            self.check.block_mismatches += 1;
            self.mismatch(format!("data block {block} at 0x{:X}", stored.offset));
        }
        Ok(stored)
    }

    fn ensure_allocated(&self, block: u32) -> Walk<()> {
        if block < self.geometry.allocated_blocks {
            Ok(())
        } else {
            Err(format!(
                "block {block} is not allocated (the volume has {} blocks)",
                self.geometry.allocated_blocks
            ))
        }
    }

    fn mismatch(&mut self, what: String) {
        if self.check.first_mismatch.is_none() {
            self.check.first_mismatch = Some(what);
        }
    }

    /// Notes and metadata for the volume descriptor and the extent of the
    /// package, which ends at its last allocated block.
    pub(super) fn push_notes(&self, descriptor: &VolumeDescriptor, c: &mut Container<'_>) {
        let prefix = c.key_prefix;
        let copies = if self.geometry.copies == 1 {
            "read-only format (one copy of each hash table)".to_string()
        } else {
            format!(
                "two copies of each hash table; top table copy {} active",
                if self.is_top_second_copy() { 2 } else { 1 }
            )
        };
        let levels = self.geometry.top_level() + 1;
        c.notes.push(format!(
            "STFS volume: {} allocated, {} free; {copies}; {} of hash tables from 0x{:X}",
            counted(self.geometry.allocated_blocks as usize, "block", "blocks"),
            self.free_blocks,
            counted(levels, "level", "levels"),
            self.geometry.first_table_offset
        ));
        let end = self.geometry.end_offset();
        let len = self.data.len() as u64;
        if len < end {
            c.notes.push(format!(
                "Truncated package: the allocated blocks end at 0x{end:X}, the file at 0x{len:X}"
            ));
        } else if len > end {
            c.notes.push(format!(
                "{} B after the last allocated block at 0x{end:X} are not parsed",
                len - end
            ));
        }
        c.consumed = usize::try_from(end.min(len)).expect("bounded by the input length");
        c.push_metadata(format!("{prefix}_volume_type"), "Volume type", "STFS");
        c.push_metadata(
            format!("{prefix}_block_separation"),
            "Block separation flags",
            u64::from(self.block_separation),
        );
        c.push_metadata(
            format!("{prefix}_allocated_blocks"),
            "Allocated blocks",
            u64::from(self.geometry.allocated_blocks),
        );
        c.push_metadata(
            format!("{prefix}_free_blocks"),
            "Free blocks",
            u64::from(self.free_blocks),
        );
        c.push_metadata(
            format!("{prefix}_file_table_block"),
            "File table first block",
            u64::from(descriptor.file_table_block),
        );
        c.push_metadata(
            format!("{prefix}_file_table_blocks"),
            "File table blocks",
            u64::from(descriptor.file_table_blocks),
        );
    }

    /// Notes for the SHA-1 checks made while the package was read.
    pub(super) fn push_check_notes(&self, c: &mut Container<'_>) {
        if self.geometry.allocated_blocks == 0 {
            return;
        }
        let verdict = if self.check.top_table_matches {
            "matches"
        } else {
            "does not match"
        };
        c.notes.push(format!(
            "SHA-1 of the top hash table {verdict} the volume descriptor"
        ));
        let check = &self.check;
        let checked = nonzero_counts(&[
            (check.tables, "further hash table", "further hash tables"),
            (check.blocks, "data block", "data blocks"),
        ]);
        if checked.is_empty() {
            return;
        }
        let checked =
            format!("SHA-1 checked for {checked} (the file table and the files read in full)");
        match &check.first_mismatch {
            None => c.notes.push(format!("{checked}: all match")),
            Some(first) => {
                let mismatches = check.table_mismatches + check.block_mismatches;
                c.notes.push(format!(
                    "{checked}: {} {}; first: {first}",
                    nonzero_counts(&[
                        (check.table_mismatches, "table", "tables"),
                        (check.block_mismatches, "block", "blocks"),
                    ]),
                    if mismatches == 1 {
                        "does not match"
                    } else {
                        "do not match"
                    }
                ));
            }
        }
    }
}

/// The counts that are not zero, with their nouns, joined by "and".
fn nonzero_counts(counts: &[(usize, &str, &str)]) -> String {
    counts
        .iter()
        .filter(|(n, _, _)| *n > 0)
        .map(|&(n, singular, plural)| counted(n, singular, plural))
        .collect::<Vec<_>>()
        .join(" and ")
}

/// The `len` bytes at `start` for a range computed from the volume, or
/// `None` when they do not lie in `data`.
fn range(data: &[u8], start: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(start).ok()?;
    data.get(start..start.checked_add(len)?)
}

fn sha1(bytes: &[u8]) -> [u8; RECORD_SHA1_SIZE] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry(copies: u64, allocated_blocks: u32) -> Geometry {
        Geometry {
            first_table_offset: 0xA000,
            copies,
            allocated_blocks,
        }
    }

    #[test]
    fn read_only_format_places_one_table_before_each_group() {
        let g = geometry(1, MAX_BLOCKS);
        // Level-0 table 0, data 0-169, level-1 table 0, level-0 table 1.
        assert_eq!(g.table_slot(0, 0), 0);
        assert_eq!(g.data_slot(0), 1);
        assert_eq!(g.data_slot(169), 170);
        assert_eq!(g.table_slot(1, 0), 171);
        assert_eq!(g.table_slot(0, 170), 172);
        assert_eq!(g.data_slot(170), 173);
        // After 170 level-0 groups: the level-2 table, level-1 table 1,
        // level-0 table 170, then block 28,900.
        assert_eq!(g.table_slot(2, 0), 0x718F);
        assert_eq!(g.table_slot(1, 28_900), 0x7190);
        assert_eq!(g.table_slot(0, 28_900), 0x7191);
        assert_eq!(g.data_slot(28_900), 0x7192);
        assert_eq!(g.data_slot(28_899), 0x718E);
    }

    #[test]
    fn two_copy_format_doubles_every_table() {
        let g = geometry(2, MAX_BLOCKS);
        assert_eq!(g.data_slot(0), 2);
        assert_eq!(g.table_slot(1, 0), 0xAC);
        assert_eq!(g.table_slot(0, 170), 0xAE);
        assert_eq!(g.data_slot(170), 0xB0);
        // Velocity `blockStep` for two copies: 0xAC and 0x723A.
        assert_eq!(g.table_slot(2, 0), 0x723A);
        assert_eq!(g.table_slot(1, 28_900), 0x723C);
        assert_eq!(g.table_slot(0, 28_900), 0x723E);
        assert_eq!(g.data_slot(28_900), 0x7240);
    }

    #[test]
    fn block_171_follows_the_first_level_1_table_too() {
        // Free60's example counts one level-0 table between blocks 0 and
        // 171; its C# helper, Velocity and xenia also count the first
        // level-1 table, which follows block 169.
        let g = geometry(1, 200);
        assert_eq!(g.data_slot(171) - g.data_slot(0), 171 + 2);
        assert_eq!(g.block_offset(0), 0xB000);
    }

    #[test]
    fn top_levels_follow_the_block_count() {
        assert_eq!(geometry(1, 0).top_level(), 0);
        assert_eq!(geometry(1, 170).top_level(), 0);
        assert_eq!(geometry(1, 171).top_level(), 1);
        assert_eq!(geometry(1, 28_900).top_level(), 1);
        assert_eq!(geometry(1, 28_901).top_level(), 2);
        assert_eq!(geometry(1, MAX_BLOCKS).top_level(), 2);
    }

    #[test]
    fn package_ends_after_its_last_allocated_block() {
        assert_eq!(geometry(1, 0).end_offset(), 0xA000);
        assert_eq!(geometry(1, 1).end_offset(), 0xC000);
        assert_eq!(geometry(2, 1).end_offset(), 0xD000);
    }

    #[test]
    fn records_hold_a_sha1_a_status_and_a_big_endian_next_block() {
        let mut table = vec![0u8; BLOCK_SIZE];
        table[RECORD_SIZE + RECORD_STATUS] = 0x80;
        table[RECORD_SIZE + RECORD_NEXT_BLOCK..RECORD_SIZE + RECORD_SIZE]
            .copy_from_slice(&[0x01, 0x02, 0x03]);
        let record = record_at(&table, 1).unwrap();
        assert_eq!(record.status, 0x80);
        assert_eq!(record.next_block, 0x01_0203);
        assert!(record_at(&table[..RECORD_SIZE], 1).is_err());
    }
}
