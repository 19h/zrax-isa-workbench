//! Amiga disk images: ADF floppy images holding an `AmigaDOS` volume (OFS
//! or FFS), bootable ADF floppies without one, hard disk images with a
//! Rigid Disk Block and unpartitioned hardfiles. The directory tree is
//! walked from the root block's hash table; regular files that start with a
//! recognized format (Amiga Hunk executables, for example) are members,
//! reassembled from their data blocks, and boot block code is a 680x0
//! child.
//!
//! Sources (pins and hashes in `docs/adf.md`):
//! - [FAQ] Laurent Clévy, "The .ADF (Amiga Disk File) format FAQ", v1.14
//!   (`doc/FAQ/adf_info.txt` in `ADFlib` at `73880de7`): sections 3
//!   (geometry), 4.1 (boot block), 4.2 (root block, hash and checksum), 4.3
//!   (bitmap), 4.4 (files), 4.5 (directories), 4.6 (links), 5.4
//!   (international mode), 6 (hard disks) and 7 (hardfiles).
//! - [ADFLIB] `ADFlib` at `73880de7`: `src/adf_blk.h`, `src/adf_raw.c`,
//!   `src/adf_dir.c`, `src/adf_file_block.c`, `src/adf_file_util.c`,
//!   `src/adf_vol.h` and `src/adf_dev_type.c`.
//! - [AMITOOLS] amitools at `3b57f205`: `amitools/fs/DosType.py`,
//!   `block/BootBlock.py`, `block/EntryBlock.py`, `ADFSFile.py` and
//!   `blkdev/PartBlockDevice.py`.
//! - [RKRM] Amiga ROM Kernel Reference Manual: Devices, 3rd ed., chapter
//!   11 "Amiga `BootStrap`", "Bootblock Booting"; `devices/bootblock.i`,
//!   `devices/hardblocks.h` and `dos/filehandler.h` (2.04 Includes, V37.4).
//! - [HRM] Amiga Hardware Reference Manual, 3rd ed., chapter 1
//!   "Components of the Amiga".
//! - [LINUX] Linux v6.6 `fs/affs/super.c` (root block position) and
//!   `block/partitions/amiga.c` (Rigid Disk Block partitions).
//!
//! All fields are big-endian. Blocks are 512 B and block numbers count from
//! the start of their volume (the image, or the partition); offsets in
//! notes and metadata are file bytes. The format names no processor for the
//! files it holds, so members are classified from their own bytes.
//! Kickstart runs boot block code on the Amiga's 680x0 ([HRM]: the 68000,
//! 68010, 68020 or 68030; [RKRM]: the code is entered with the I/O request
//! in A1 and `SysBase` in A6), so that code is a child with a 68000-family
//! target.

use crate::error::{ClassifierError, Result};
use crate::formats::container::Container;
use crate::types::FileFormat;

mod boot;
mod rdb;
mod volume;
mod walk;

/// The block size of every layout handled here ([FAQ] 3; [RKRM]
/// `devices/hardblocks.h`: "only 512 byte blocks are currently supported by
/// the file system").
const BLOCK_SIZE: usize = 512;

/// Longs (32-bit words) in a block.
const BLOCK_LONGS: usize = BLOCK_SIZE / 4;

// Fields that the root, directory, file header, extension and OFS data
// blocks share ([FAQ] 4.2, 4.4, 4.5; [ADFLIB] `adf_blk.h`).

/// Primary block type.
const TYPE: usize = 0x000;
/// `header_key`: the block's own number in entry and extension blocks, the
/// file header block in OFS data blocks.
const HEADER_KEY: usize = 0x004;
/// `high_seq`: data block pointers stored in a file header or extension
/// block.
const HIGH_SEQ: usize = 0x008;
/// The normal checksum ([FAQ] 4.2.3).
const CHECKSUM: usize = 0x014;
/// The hash table of the root and directory blocks, and the data block
/// pointers of file header and extension blocks.
const TABLE: usize = 0x018;
/// `name_len` and the name (the volume name in the root block).
const NAME: usize = 0x1b0;
/// `hash_chain`: the next entry with the same hash.
const HASH_CHAIN: usize = 0x1f0;
/// `parent`: the directory of an entry, the file header of an extension
/// block.
const PARENT: usize = 0x1f4;
/// `extension`: a file's first extension block, or a directory's first
/// directory cache block.
const EXTENSION: usize = 0x1f8;
/// Secondary block type.
const SECONDARY_TYPE: usize = 0x1fc;

/// Entries in a hash table and data block pointers in a file header or
/// extension block: `BSIZE / 4 - 56` ([FAQ] 4.2, 4.4; [ADFLIB]
/// `ADF_HT_SIZE`, `ADF_MAX_DATABLK`).
const TABLE_ENTRIES: usize = BLOCK_LONGS - 56;

/// Primary types ([ADFLIB] `adf_blk.h`).
const T_HEADER: u32 = 2;
const T_DATA: u32 = 8;
const T_LIST: u32 = 16;

/// Secondary types ([ADFLIB] `adf_blk.h`; [AMITOOLS] `Block.py`). The
/// negative ones are stored as two's complement longs.
const ST_ROOT: u32 = 1;
const ST_USERDIR: u32 = 2;
const ST_SOFTLINK: u32 = 3;
const ST_LINKDIR: u32 = 4;
/// -3
const ST_FILE: u32 = 0xffff_fffd;
/// -4
const ST_LINKFILE: u32 = 0xffff_fffc;

/// Floppy density, from the image size ([FAQ] 3: 11 sectors per track on
/// DD disks, 22 on HD disks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Density {
    /// Double density: 11 sectors per track, 901,120 B for 80 cylinders.
    Double,
    /// High density: 22 sectors per track, 1,802,240 B for 80 cylinders.
    High,
}

/// An Amiga disk image layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// An ADF floppy image holding an `AmigaDOS` volume: `DOS` and a DOS
    /// type of 0-7 in the boot block and a valid root block in the middle.
    Floppy(Density),
    /// An ADF floppy image whose boot block Kickstart runs (the `DOS`
    /// signature and a valid boot block checksum over code) but which
    /// holds no `AmigaDOS` root block: a disk with a loader of its own.
    BootFloppy(Density),
    /// A hard disk image with a Rigid Disk Block (`RDSK`) in its first 16
    /// blocks.
    RigidDisk,
    /// A hard disk image holding one `AmigaDOS` volume and no Rigid Disk
    /// Block, as UAE creates them ([FAQ] 7).
    Hardfile,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Floppy(_) | Self::BootFloppy(_) => FileFormat::Adf,
            Self::RigidDisk | Self::Hardfile => FileFormat::AmigaHdf,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Floppy(Density::Double) => "AmigaDOS DD floppy",
            Self::Floppy(Density::High) => "AmigaDOS HD floppy",
            Self::BootFloppy(Density::Double) => "Bootable non-DOS DD floppy",
            Self::BootFloppy(Density::High) => "Bootable non-DOS HD floppy",
            Self::RigidDisk => "Rigid Disk Block",
            Self::Hardfile => "Unpartitioned hardfile",
        }
    }

    /// Every layout is recognized from a signature (`DOS` at offset 0, or
    /// `RDSK`) together with a 32-bit checksum that the parser checks
    /// anyway, at a position fixed by the image size.
    pub fn is_weak(self) -> bool {
        false
    }
}

/// Strong recognition:
/// - an ADF floppy: an image of exactly 80-83 cylinders of 2 heads and 11
///   or 22 sectors, `DOS` at offset 0, and either a DOS type of 0-7 with a
///   root block in the middle of the disk whose types and checksum are
///   valid ([`Layout::Floppy`]), or a boot block checksum that is valid
///   over boot code ([`Layout::BootFloppy`]);
/// - a Rigid Disk Block: `RDSK` at the start of one of the first 16 blocks
///   with a valid checksum, and after block 0 a partition list that starts
///   at a valid `PART` block ([`Layout::RigidDisk`]);
/// - a hardfile: a whole number of blocks, `DOS` and a DOS type of 0-7 at
///   offset 0, and a valid root block in the middle ([`Layout::Hardfile`]).
pub fn detect(data: &[u8]) -> Option<Layout> {
    if let Some(layout) = volume::detect_floppy(data) {
        return Some(layout);
    }
    if rdb::detect(data) {
        return Some(Layout::RigidDisk);
    }
    volume::detect_hardfile(data).then_some(Layout::Hardfile)
}

/// Parse an Amiga disk image into the shared container model: the regular
/// files that start with a recognized format, labeled by their path (with
/// the drive name on a partitioned disk), then file system handlers and
/// boot block code.
///
/// # Errors
///
/// [`ClassifierError::AdfParseError`] for an image whose size, signature,
/// DOS type, root block or boot block does not match `layout`, and for a
/// Rigid Disk Block that is missing, fails its checksum or names a block
/// size other than 512 B. Damage below the root block (and in partitions)
/// is reported in notes instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Floppy(density) => volume::parse_floppy(data, density),
        Layout::BootFloppy(density) => volume::parse_boot_floppy(data, density),
        Layout::RigidDisk => rdb::parse(data),
        Layout::Hardfile => volume::parse_hardfile(data),
    }
}

/// A result below the root block of a volume: the error is a defect that
/// skips the entry and becomes a note.
type Walk<T> = std::result::Result<T, String>;

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::AdfParseError {
        message: message.into(),
    }
}

/// One 512-byte block of the input.
#[derive(Debug, Clone, Copy)]
struct Block<'a> {
    /// Block number in its volume (or on the disk, for Rigid Disk Block
    /// structures).
    number: u32,
    /// File offset.
    offset: usize,
    bytes: &'a [u8; BLOCK_SIZE],
}

impl<'a> Block<'a> {
    /// The block at file offset `offset`, if the input holds all of it.
    fn at(data: &'a [u8], number: u32, offset: usize) -> Option<Self> {
        let end = offset.checked_add(BLOCK_SIZE)?;
        let bytes = data.get(offset..end)?.try_into().ok()?;
        Some(Self {
            number,
            offset,
            bytes,
        })
    }

    /// The long at byte `at`, a field offset inside the block.
    fn long(&self, at: usize) -> u32 {
        let field = self
            .bytes
            .get(at..at + 4)
            .expect("field offsets lie inside the block");
        u32::from_be_bytes(field.try_into().expect("4 bytes"))
    }

    /// The wrapping sum of the first `longs` longs. The normal checksum of
    /// an `AmigaDOS` block makes the sum of all 128 longs 0 ([FAQ] 4.2.3),
    /// and the Rigid Disk Block structures make the sum of their summed
    /// longs 0 ([RKRM] `devices/hardblocks.h`).
    fn sum(&self, longs: usize) -> u32 {
        self.bytes
            .chunks_exact(4)
            .take(longs)
            .map(|long| u32::from_be_bytes(long.try_into().expect("4 bytes")))
            .fold(0u32, u32::wrapping_add)
    }

    /// The normal checksum is valid: the 128 longs sum to 0.
    fn is_checksum_valid(&self) -> bool {
        self.sum(BLOCK_LONGS) == 0
    }

    /// The checksum the long at `at` must hold for the 128 longs to sum
    /// to 0.
    fn expected_checksum(&self, at: usize) -> u32 {
        self.long(at).wrapping_sub(self.sum(BLOCK_LONGS))
    }

    /// The BCPL string at `at`: a length byte of at most `max` and the
    /// characters after it.
    fn bstr(&self, at: usize, max: usize) -> Option<&'a [u8]> {
        let bytes: &'a [u8; BLOCK_SIZE] = self.bytes;
        let len = usize::from(*bytes.get(at)?);
        if len > max {
            return None;
        }
        bytes.get(at + 1..at + 1 + len)
    }
}

/// A set of block numbers below a bound, one bit each: the blocks a walk
/// has read, so that it reads none twice.
#[derive(Debug)]
struct BlockSet {
    words: Vec<u64>,
}

impl BlockSet {
    /// A set for block numbers below `blocks`.
    fn new(blocks: usize) -> Self {
        Self {
            words: vec![0; blocks / 64 + 1],
        }
    }

    /// Add `number`; false when the set holds it already or it is not
    /// below the bound.
    fn insert(&mut self, number: u32) -> bool {
        let bit = usize::try_from(number).unwrap_or(usize::MAX);
        let Some(word) = self.words.get_mut(bit / 64) else {
            return false;
        };
        let mask = 1u64 << (bit % 64);
        let fresh = *word & mask == 0;
        *word |= mask;
        fresh
    }
}

/// Amiga text: ISO 8859-1 ([FAQ] 5.4), which maps one to one onto the
/// first 256 Unicode code points.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// `value` divided by `divisor`, rounded up. `divisor` is not zero.
fn div_round_up(value: usize, divisor: usize) -> usize {
    value / divisor + usize::from(value % divisor != 0)
}

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A block of zeros with `longs` stored at the start.
    fn block(longs: &[u32]) -> [u8; BLOCK_SIZE] {
        let mut bytes = [0u8; BLOCK_SIZE];
        for (i, long) in longs.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&long.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn normal_checksums_make_the_block_sum_zero() {
        let mut bytes = block(&[2, 0, 0, 72, 0, 0, 0x1234_5678]);
        let b = Block::at(&bytes, 0, 0).unwrap();
        assert!(!b.is_checksum_valid());
        let expected = b.expected_checksum(0x14);
        assert_eq!(expected, 0u32.wrapping_sub(2 + 72 + 0x1234_5678));
        bytes[0x14..0x18].copy_from_slice(&expected.to_be_bytes());
        let b = Block::at(&bytes, 0, 0).unwrap();
        assert!(b.is_checksum_valid());
        assert_eq!(b.expected_checksum(0x14), expected);
    }

    #[test]
    fn bcpl_strings_are_bounded_by_their_length_byte() {
        let mut bytes = [0u8; BLOCK_SIZE];
        bytes[0x1b0] = 5;
        bytes[0x1b1..0x1b6].copy_from_slice(b"Empty");
        let b = Block::at(&bytes, 0, 0).unwrap();
        assert_eq!(b.bstr(0x1b0, 30), Some(&b"Empty"[..]));
        assert_eq!(b.bstr(0x1b0, 4), None);
        bytes[0x1ff] = 9;
        let b = Block::at(&bytes, 0, 0).unwrap();
        assert_eq!(b.bstr(0x1ff, 30), None, "runs past the block");
    }

    #[test]
    fn blocks_must_lie_inside_the_input() {
        let data = [0u8; 1000];
        assert!(Block::at(&data, 0, 0).is_some());
        assert!(Block::at(&data, 1, 512).is_none());
        assert!(Block::at(&data, 1, usize::MAX).is_none());
    }

    #[test]
    fn block_sets_hold_each_block_once() {
        let mut set = BlockSet::new(100);
        assert!(set.insert(5));
        assert!(!set.insert(5));
        assert!(set.insert(127), "rounded up to whole words");
        assert!(!set.insert(128));
        assert!(!set.insert(u32::MAX));
    }

    #[test]
    fn latin1_text_maps_to_unicode() {
        assert_eq!(latin1(b"Disk\xe9"), "Disk\u{e9}");
    }

    #[test]
    fn sizes_use_exact_binary_units() {
        assert_eq!(size_text(901_120), "880 KiB");
        assert_eq!(size_text(64 << 20), "64 MiB");
        assert_eq!(size_text(1000), "1000 B");
        assert_eq!(div_round_up(977, 488), 3);
        assert_eq!(div_round_up(976, 488), 2);
    }
}
