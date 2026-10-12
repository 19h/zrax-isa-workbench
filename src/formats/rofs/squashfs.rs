//! Squashfs: 4.0 images are enumerated; 1.x-3.x, big-endian and streamed
//! images are recognized from their superblock (sources in the family
//! module).
//!
//! A 4.0 image is little-endian throughout: a 96-byte superblock, optional
//! compressor options in a metadata block at offset 96, data and fragment
//! blocks, then the inode, directory, fragment, export, id and xattr tables.
//! A metadata block is a 2-byte header (bit 15 set when stored
//! uncompressed, low 15 bits the stored size) and at most 8 KiB of decoded
//! data. An inode reference holds a table-relative metadata block offset in
//! bits 16-47 and an offset into that block's decoded bytes in bits 0-15.

use super::*;

/// `SQUASHFS_MAGIC`, read little-endian (`hsqs` on disk).
const SQUASHFS_MAGIC: u32 = 0x7371_7368;

/// `SQUASHFS_MAGIC_SWAP`: a big-endian image (`sqsh` on disk).
const SQUASHFS_MAGIC_SWAP: u32 = 0x6873_7173;

/// `SQUASHFS_MAGIC_STREAMED` (`HSQS` on disk) and its byte-swapped form
/// (`SQSH`), squashfs-tools 4.7.5.
const SQUASHFS_MAGIC_STREAMED: u32 = 0x5351_5348;
const SQUASHFS_MAGIC_STREAMED_SWAPPED: u32 = 0x4853_5153;

/// Size of the 4.0 superblock, and of the streamed placeholder header.
const SUPERBLOCK_SIZE: usize = 96;

/// Version fields of every superblock revision (major at 28, minor at 30).
const VERSION_MAJOR: usize = 28;
const VERSION_MINOR: usize = 30;

/// Decoded size limit of a metadata block (`SQUASHFS_METADATA_SIZE`).
const METADATA_SIZE: usize = 8192;

/// Metadata block header bit: stored uncompressed (`SQUASHFS_COMPRESSED_BIT`).
const METADATA_UNCOMPRESSED: u16 = 0x8000;

/// Largest distance between consecutive metadata blocks of a table: one
/// block and its 2-byte header (`SQUASHFS_METADATA_SIZE +
/// SQUASHFS_BLOCK_OFFSET`, `id.c` and `export.c`).
const MAX_METADATA_SPAN: u64 = 8194;

/// Block list and fragment entry bit: stored uncompressed
/// (`SQUASHFS_COMPRESSED_BIT_BLOCK`).
const BLOCK_UNCOMPRESSED: u32 = 1 << 24;

/// Stored size bits of a block list or fragment entry.
const BLOCK_SIZE_MASK: u32 = 0x00ff_ffff;

/// Bits 25-31 of a block size, which the kernel rejects
/// (`squashfs_block_size`).
const BLOCK_RESERVED: u32 = 0xfe00_0000;

/// No fragment (`SQUASHFS_INVALID_FRAG`).
const INVALID_FRAGMENT: u32 = 0xffff_ffff;

/// An absent optional table (`SQUASHFS_INVALID_BLK`).
const INVALID_TABLE: u64 = u64::MAX;

/// Block sizes mksquashfs accepts: 4 KiB to 1 MiB (`SQUASHFS_FILE_MAX_LOG`).
const MIN_BLOCK_LOG: u16 = 12;
const MAX_BLOCK_LOG: u16 = 20;

/// Superblock flag bit 10 (`SQUASHFS_COMP_OPT`): compressor options follow
/// the superblock.
const COMP_OPT: u16 = 1 << 10;

/// Table entry sizes: fragment entries, uid/gid entries, export entries
/// (inode references) and xattr id entries.
const FRAGMENT_ENTRY_SIZE: u64 = 16;
const ID_ENTRY_SIZE: u64 = 4;
const LOOKUP_ENTRY_SIZE: u64 = 8;
const XATTR_ID_ENTRY_SIZE: u64 = 16;

/// Size of one index entry: the file offset (u64) of a table block.
const INDEX_ENTRY_SIZE: u64 = 8;

/// Xattr id table header: xattr table start (u64), id count (u32), unused.
const XATTR_ID_HEADER_SIZE: u64 = 16;

/// Inode types (`SQUASHFS_*_TYPE`); extended types are the basic ones
/// plus 7.
const DIR_TYPE: u16 = 1;
const REG_TYPE: u16 = 2;
const LDIR_TYPE: u16 = 8;
const LREG_TYPE: u16 = 9;

/// Directory entries name basic types 1-7 (`SQUASHFS_MAX_DIR_TYPE`).
const MAX_DIR_TYPE: u16 = 7;

/// Offset of the inode number in the inode header (type, mode, uid, gid,
/// mtime, inode number).
const INODE_NUMBER: usize = 12;

/// Directory header: entry count minus one, inode table block, base
/// inode number.
const DIR_HEADER_SIZE: usize = 12;

/// Directory entry before its name: inode offset, inode number delta, type
/// and name size minus one.
const DIR_ENTRY_SIZE: usize = 8;

/// Extended directory index entry before its name: listing position, start
/// block and name size minus one.
const DIR_INDEX_SIZE: usize = 12;

/// Most entries per directory header (`SQUASHFS_DIR_COUNT`) and longest
/// name (`SQUASHFS_NAME_LEN`).
const DIR_COUNT_MAX: usize = 256;
const NAME_MAX: usize = 256;

/// A directory's `file_size` counts the `.` and `..` entries the kernel
/// invents.
const DIR_SIZE_BIAS: u32 = 3;

/// Compressor IDs (`squashfs_fs.h` `*_COMPRESSION`).
const ZLIB_COMPRESSION: u16 = 1;
const LZMA_COMPRESSION: u16 = 2;
const LZO_COMPRESSION: u16 = 3;
const XZ_COMPRESSION: u16 = 4;
const LZ4_COMPRESSION: u16 = 5;
const ZSTD_COMPRESSION: u16 = 6;

/// The transform of a member assembled from stored blocks, sparse blocks
/// or a stored fragment without decoding.
const ASSEMBLED: &str = "SquashFS block list";

/// Compressor option payloads (`*_wrapper.h`), all little-endian.
#[derive(Clone, Copy)]
enum Options {
    /// Level (i32), window bits (i16), strategy bitmap (i16).
    Gzip,
    /// LZMA defines no options.
    Lzma,
    /// Algorithm (i32), level (i32).
    Lzo,
    /// Dictionary size (i32), BCJ filter bitmap (i32).
    Xz,
    /// Version (i32, must be 1), flags (i32, bit 0 high compression).
    Lz4,
    /// Level (i32).
    Zstd,
}

impl Options {
    /// Payload size in bytes, or `None` when the compressor has no options.
    fn size(self) -> Option<usize> {
        match self {
            Self::Gzip | Self::Lzo | Self::Xz | Self::Lz4 => Some(8),
            Self::Zstd => Some(4),
            Self::Lzma => None,
        }
    }
}

/// A compressor: ID, squashfs-tools name, the codec of one block, and its
/// options payload.
struct Compressor {
    id: u16,
    name: &'static str,
    codec: Codec,
    options: Options,
}

/// Every compressor ID with its per-block stream: gzip writes zlib
/// streams, LZMA writes LZMA-alone streams, LZO and LZ4 write raw blocks,
/// xz and zstd write complete streams (`*_wrapper.c`).
const COMPRESSORS: &[Compressor] = &[
    Compressor {
        id: ZLIB_COMPRESSION,
        name: "gzip",
        codec: Codec::Zlib,
        options: Options::Gzip,
    },
    Compressor {
        id: LZMA_COMPRESSION,
        name: "lzma",
        codec: Codec::Lzma,
        options: Options::Lzma,
    },
    Compressor {
        id: LZO_COMPRESSION,
        name: "lzo",
        codec: Codec::Lzo1x,
        options: Options::Lzo,
    },
    Compressor {
        id: XZ_COMPRESSION,
        name: "xz",
        codec: Codec::Xz,
        options: Options::Xz,
    },
    Compressor {
        id: LZ4_COMPRESSION,
        name: "lz4",
        codec: Codec::Lz4Block,
        options: Options::Lz4,
    },
    Compressor {
        id: ZSTD_COMPRESSION,
        name: "zstd",
        codec: Codec::Zstd,
        options: Options::Zstd,
    },
];

/// xz option filter bits in `xz_wrapper.c` `bcj[]` order; squashfs-tools
/// 4.7.5 adds arm64 and riscv.
const XZ_BCJ_FILTERS: [&str; 8] = [
    "x86", "powerpc", "ia64", "arm", "armthumb", "sparc", "arm64", "riscv",
];

/// LZO option algorithms (`lzo_wrapper.h`).
const LZO_ALGORITHMS: [&str; 5] = [
    "lzo1x_1",
    "lzo1x_1_11",
    "lzo1x_1_12",
    "lzo1x_1_15",
    "lzo1x_999",
];

/// LZ4 options: the only version (`LZ4_LEGACY`) and the high-compression
/// flag (`LZ4_HC`).
const LZ4_OPTIONS_VERSION: u32 = 1;
const LZ4_HC: u32 = 1;

/// Squashfs 1.x-3.x superblock fields (`squashfs_super_block_3`, packed,
/// in the image's byte order).
const LEGACY_INODES: usize = 4;
const LEGACY_BYTES_USED_2: usize = 8;
const LEGACY_BLOCK_SIZE_1: usize = 32;
const LEGACY_BLOCK_LOG: usize = 34;
const LEGACY_BLOCK_SIZE: usize = 51;
const LEGACY_FRAGMENTS: usize = 55;
const LEGACY_BYTES_USED: usize = 63;

/// Strong recognition by the superblock magic. A little-endian image
/// whose version is not 1-3 goes to the 4.0 parser, which reports an
/// unsupported version; a streamed image also needs its zeroed header.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    match le_u32(data, 0).ok()? {
        SQUASHFS_MAGIC => match le_u16(data, VERSION_MAJOR) {
            Ok(1..=3) => Some(Layout::SquashfsLegacy),
            _ => Some(Layout::Squashfs),
        },
        SQUASHFS_MAGIC_SWAP => Some(Layout::SquashfsLegacy),
        SQUASHFS_MAGIC_STREAMED | SQUASHFS_MAGIC_STREAMED_SWAPPED if is_streamed_header(data) => {
            Some(Layout::SquashfsStreamed)
        }
        _ => None,
    }
}

/// The streamed placeholder: zeros after the magic up to 96 bytes.
fn is_streamed_header(data: &[u8]) -> bool {
    data.get(4..SUPERBLOCK_SIZE)
        .is_some_and(|rest| rest.iter().all(|b| *b == 0))
}

/// The 4.0 superblock fields the reader uses. Table starts are file
/// offsets.
struct Superblock {
    inodes: u32,
    block_size: usize,
    fragments: u32,
    compressor: &'static Compressor,
    flags: u16,
    no_ids: u16,
    root_inode: u64,
    bytes_used: usize,
    id_table_start: u64,
    xattr_id_table_start: u64,
    inode_table_start: u64,
    directory_table_start: u64,
    fragment_table_start: u64,
    lookup_table_start: u64,
}

/// Superblock (96 bytes): magic, inode count (4), mkfs time (8), block size
/// (12), fragment count (16), compressor (20), block log (22), flags (24),
/// id count (26), version (28, 30), root inode reference (32), bytes used
/// (40), then the id (48), xattr id (56), inode (64), directory (72),
/// fragment (80) and export (88) table starts. Checked in the kernel's
/// order (`squashfs_fill_super`).
fn superblock(data: &[u8]) -> Result<Superblock> {
    let header = slice(data, 0, SUPERBLOCK_SIZE)?;
    if le_u32(header, 0)? != SQUASHFS_MAGIC {
        return Err(error("Missing SquashFS magic"));
    }
    let major = le_u16(header, VERSION_MAJOR)?;
    let minor = le_u16(header, VERSION_MINOR)?;
    if (major, minor) != (4, 0) {
        return Err(error(format!(
            "Unsupported SquashFS version {major}.{minor}"
        )));
    }
    let compressor_id = le_u16(header, 20)?;
    let compressor = COMPRESSORS
        .iter()
        .find(|c| c.id == compressor_id)
        .ok_or_else(|| error(format!("Unknown SquashFS compressor ID {compressor_id}")))?;
    let bytes_used = le_u64(header, 40)?;
    if bytes_used > data.len() as u64 {
        return Err(error(format!(
            "Truncated SquashFS image: bytes_used is {bytes_used} B, {} B present",
            data.len()
        )));
    }
    if bytes_used < SUPERBLOCK_SIZE as u64 {
        return Err(error(format!("Invalid SquashFS bytes_used {bytes_used} B")));
    }
    let block_size = le_u32(header, 12)?;
    let block_log = le_u16(header, 22)?;
    if !(MIN_BLOCK_LOG..=MAX_BLOCK_LOG).contains(&block_log) || block_size != 1 << block_log {
        return Err(error(format!(
            "Invalid SquashFS block size {block_size} B (block_log {block_log})"
        )));
    }
    let root_inode = le_u64(header, 32)?;
    if inode_offset(root_inode) > METADATA_SIZE {
        return Err(error(format!(
            "Invalid SquashFS root inode reference 0x{root_inode:X}"
        )));
    }
    Ok(Superblock {
        inodes: le_u32(header, 4)?,
        block_size: to_usize(block_size.into(), "SquashFS block size")?,
        fragments: le_u32(header, 16)?,
        compressor,
        flags: le_u16(header, 24)?,
        no_ids: le_u16(header, 26)?,
        root_inode,
        bytes_used: to_usize(bytes_used, "SquashFS bytes_used")?,
        id_table_start: le_u64(header, 48)?,
        xattr_id_table_start: le_u64(header, 56)?,
        inode_table_start: le_u64(header, 64)?,
        directory_table_start: le_u64(header, 72)?,
        fragment_table_start: le_u64(header, 80)?,
        lookup_table_start: le_u64(header, 88)?,
    })
}

/// Table-relative metadata block of an inode reference.
fn inode_block(reference: u64) -> u64 {
    reference >> 16
}

/// Offset into the decoded metadata block of an inode reference.
fn inode_offset(reference: u64) -> usize {
    usize::from((reference & 0xffff) as u16)
}

/// One decoded metadata block and the file offset of the next one.
struct MetadataBlock<'a> {
    bytes: Cow<'a, [u8]>,
    next: usize,
}

/// The metadata block at file offset `offset`. The kernel rejects a stored
/// size of 0 or above 8 KiB.
fn metadata_block(image: &[u8], offset: usize, codec: Codec) -> Result<MetadataBlock<'_>> {
    let header = le_u16(image, offset)?;
    let stored_size = usize::from(header & !METADATA_UNCOMPRESSED);
    if stored_size == 0 || stored_size > METADATA_SIZE {
        return Err(error(format!(
            "Invalid SquashFS metadata block at 0x{offset:X}: stored size {stored_size} B"
        )));
    }
    // `le_u16` proved two bytes at `offset`, so `offset + 2` cannot overflow.
    let start = offset + 2;
    let stored = slice(image, start, stored_size)?;
    let bytes = if header & METADATA_UNCOMPRESSED != 0 {
        Cow::Borrowed(stored)
    } else {
        let decoded = compressed::decode_limited(codec, stored, METADATA_SIZE).map_err(|e| {
            error(format!(
                "Invalid SquashFS metadata block at 0x{offset:X}: {e}"
            ))
        })?;
        Cow::Owned(decoded.data)
    };
    if bytes.is_empty() {
        return Err(error(format!(
            "Invalid SquashFS metadata block at 0x{offset:X}: no data"
        )));
    }
    Ok(MetadataBlock {
        bytes,
        next: start + stored_size,
    })
}

/// Compressor options: one metadata block at offset 96 when
/// `SQUASHFS_COMP_OPT` is set. Returns a note describing them. xz BCJ
/// filters record what the builder tried, not the ISA of any file.
fn compressor_options(image: &[u8], sb: &Superblock) -> Result<Option<String>> {
    let compressor = sb.compressor;
    if sb.flags & COMP_OPT == 0 {
        let note = (compressor.id == LZ4_COMPRESSION)
            .then(|| "LZ4 image without compressor options (Linux requires them)".to_string());
        return Ok(note);
    }
    let options = metadata_block(image, SUPERBLOCK_SIZE, compressor.codec)?.bytes;
    let name = compressor.name;
    if let Some(expected) = compressor.options.size() {
        if options.len() != expected {
            return Err(error(format!(
                "Invalid SquashFS {name} compressor options: {} B, expected {expected} B",
                options.len()
            )));
        }
    }
    let note = match compressor.options {
        Options::Lzma => format!(
            "Compressor options present ({} B); {name} defines none",
            options.len()
        ),
        Options::Gzip => format!(
            "gzip options: level {}; window {}",
            le_u32(&options, 0)?,
            le_u16(&options, 4)?
        ),
        Options::Xz => format!(
            "xz options: dictionary {}; BCJ filters requested at build time: {} (not ISA evidence)",
            size_text(to_usize(le_u32(&options, 0)?.into(), "xz dictionary size")?),
            bcj_filters(le_u32(&options, 4)?)
        ),
        Options::Lzo => {
            let algorithm = le_u32(&options, 0)?;
            let algorithm = usize::try_from(algorithm)
                .ok()
                .and_then(|i| LZO_ALGORITHMS.get(i))
                .map_or_else(|| algorithm.to_string(), |name| (*name).to_string());
            format!(
                "lzo options: algorithm {algorithm}; level {}",
                le_u32(&options, 4)?
            )
        }
        Options::Lz4 => {
            let version = le_u32(&options, 0)?;
            if version != LZ4_OPTIONS_VERSION {
                return Err(error(format!(
                    "Unsupported SquashFS LZ4 options version {version}"
                )));
            }
            let high = le_u32(&options, 4)? & LZ4_HC != 0;
            format!(
                "lz4 options: version {version}{}",
                if high { "; high compression" } else { "" }
            )
        }
        Options::Zstd => format!("zstd options: level {}", le_u32(&options, 0)?),
    };
    Ok(Some(note))
}

/// The BCJ filters an xz options bitmap requests, by name.
fn bcj_filters(flags: u32) -> String {
    let requested: Vec<&str> = XZ_BCJ_FILTERS
        .iter()
        .enumerate()
        .filter(|(bit, _)| flags & (1 << bit) != 0)
        .map(|(_, filter)| *filter)
        .collect();
    if requested.is_empty() {
        "none".to_string()
    } else {
        requested.join(", ")
    }
}

/// Bytes of the index of a table whose entries take `entries_size` bytes:
/// one u64 per metadata block.
fn index_size(entries_size: u64) -> u64 {
    let metadata_size = METADATA_SIZE as u64;
    (entries_size + metadata_size - 1) / metadata_size * INDEX_ENTRY_SIZE
}

/// The little-endian u64 entries of the `size`-byte index at `start`.
fn read_index(image: &[u8], start: u64, size: u64, name: &str) -> Result<Vec<u64>> {
    let at = to_usize(start, &format!("SquashFS {name} table start"))?;
    let raw = slice(
        image,
        at,
        to_usize(size, &format!("SquashFS {name} index size"))?,
    )?;
    Ok(raw
        .chunks_exact(8)
        .map(|entry| u64::from_le_bytes(entry.try_into().expect("chunk has 8 bytes")))
        .collect())
}

/// Where an index lies and what it must satisfy (`id.c`, `export.c`,
/// `xattr_id.c`): it starts at `start` and ends exactly at `next_table`,
/// and its blocks increase by at most one metadata block each and end
/// before `blocks_end`.
struct ExactIndex<'n> {
    name: &'n str,
    start: u64,
    next_table: u64,
    blocks_end: u64,
    entries_size: u64,
}

/// Read an index that must end exactly where the next table begins.
fn exact_index(image: &[u8], index: &ExactIndex<'_>) -> Result<Vec<u64>> {
    let ExactIndex {
        name,
        start,
        next_table,
        blocks_end,
        entries_size,
    } = *index;
    let size = index_size(entries_size);
    if size == 0 || next_table.checked_sub(start) != Some(size) {
        return Err(error(format!(
            "Invalid SquashFS {name} table index at 0x{start:X}: {size} B do not end at the next table (0x{next_table:X})"
        )));
    }
    let blocks = read_index(image, start, size, name)?;
    let ordered = blocks
        .windows(2)
        .all(|pair| pair[0] < pair[1] && pair[1] - pair[0] <= MAX_METADATA_SPAN);
    let last = *blocks.last().expect("index size is not zero");
    if !ordered || last >= blocks_end || blocks_end - last > MAX_METADATA_SPAN {
        return Err(error(format!(
            "Invalid SquashFS {name} table index at 0x{start:X}: block offsets out of order"
        )));
    }
    Ok(blocks)
}

/// Where the tables lie, from the kernel's checks: each table's index ends
/// where the next table's metadata begins, so the directory table ends at
/// `directory_end`.
struct Tables {
    /// File offsets of the fragment table's metadata blocks.
    fragment_index: Vec<u64>,
    /// File offset where the directory table ends.
    directory_end: u64,
}

/// Walk the optional tables from the end of the image towards the
/// directory table, as `squashfs_fill_super` does.
fn tables(image: &[u8], sb: &Superblock) -> Result<Tables> {
    let mut next_table = sb.bytes_used as u64;
    if sb.xattr_id_table_start != INVALID_TABLE {
        next_table = xattr_table_start(image, sb)?;
    }
    if sb.no_ids == 0 {
        return Err(error("Invalid SquashFS id count 0"));
    }
    let ids = exact_index(
        image,
        &ExactIndex {
            name: "id",
            start: sb.id_table_start,
            next_table,
            blocks_end: sb.id_table_start,
            entries_size: u64::from(sb.no_ids) * ID_ENTRY_SIZE,
        },
    )?;
    next_table = ids[0];
    if sb.lookup_table_start != INVALID_TABLE {
        if sb.inodes == 0 {
            return Err(error("Invalid SquashFS inode count 0"));
        }
        let lookup = exact_index(
            image,
            &ExactIndex {
                name: "export",
                start: sb.lookup_table_start,
                next_table,
                blocks_end: sb.lookup_table_start,
                entries_size: u64::from(sb.inodes) * LOOKUP_ENTRY_SIZE,
            },
        )?;
        next_table = lookup[0];
    }
    let mut fragment_index = Vec::new();
    if sb.fragments != 0 {
        let start = sb.fragment_table_start;
        let size = index_size(u64::from(sb.fragments) * FRAGMENT_ENTRY_SIZE);
        if start.checked_add(size).map_or(true, |end| end > next_table) {
            return Err(error(format!(
                "Invalid SquashFS fragment table index at 0x{start:X}: {size} B pass the next table (0x{next_table:X})"
            )));
        }
        fragment_index = read_index(image, start, size, "fragment")?;
        if fragment_index[0] >= start {
            return Err(error(format!(
                "Invalid SquashFS fragment table index at 0x{start:X}: first block at 0x{:X}",
                fragment_index[0]
            )));
        }
        next_table = fragment_index[0];
    }
    if sb.directory_table_start > next_table {
        return Err(error(format!(
            "Invalid SquashFS directory table start 0x{:X}: past the next table (0x{next_table:X})",
            sb.directory_table_start
        )));
    }
    if sb.inode_table_start >= sb.directory_table_start {
        return Err(error(format!(
            "Invalid SquashFS inode table start 0x{:X}: not before the directory table (0x{:X})",
            sb.inode_table_start, sb.directory_table_start
        )));
    }
    Ok(Tables {
        fragment_index,
        directory_end: next_table,
    })
}

/// Xattr id table: xattr table start (u64), id count (u32), unused (u32),
/// then the index, which must end at `bytes_used`. Returns the start of
/// the xattr table, where the id table's index must end.
fn xattr_table_start(image: &[u8], sb: &Superblock) -> Result<u64> {
    let table_start = sb.xattr_id_table_start;
    let at = to_usize(table_start, "SquashFS xattr id table start")?;
    let xattr_table = le_u64(image, at)?;
    let ids = le_u32(image, at + 8)?;
    if ids == 0 {
        return Err(error("Invalid SquashFS xattr id count 0"));
    }
    // `le_u32` proved the header lies in the image, so this cannot overflow.
    let index_start = table_start + XATTR_ID_HEADER_SIZE;
    let blocks = exact_index(
        image,
        &ExactIndex {
            name: "xattr id",
            start: index_start,
            next_table: sb.bytes_used as u64,
            blocks_end: table_start,
            entries_size: u64::from(ids) * XATTR_ID_ENTRY_SIZE,
        },
    )?;
    if xattr_table >= blocks[0] {
        return Err(error(format!(
            "Invalid SquashFS xattr table start 0x{xattr_table:X}: not before its id blocks"
        )));
    }
    Ok(xattr_table)
}

/// A metadata table decoded whole: its blocks concatenated, with where
/// each block starts in the table (stored, relative to the table start)
/// and in the decoded bytes.
struct Table {
    /// Table name for messages.
    name: &'static str,
    bytes: Vec<u8>,
    blocks: Vec<TableBlock>,
}

/// One block of a [`Table`].
struct TableBlock {
    /// Stored offset relative to the table start.
    relative: u64,
    /// Start in the decoded bytes.
    position: usize,
    /// Decoded length.
    len: usize,
}

impl Table {
    /// Decode the metadata blocks that tile `start..end` (file offsets).
    fn read(image: &[u8], start: u64, end: u64, codec: Codec, name: &'static str) -> Result<Self> {
        let start = to_usize(start, &format!("SquashFS {name} table start"))?;
        let end = to_usize(end, &format!("SquashFS {name} table end"))?;
        let mut table = Self {
            name,
            bytes: Vec::new(),
            blocks: Vec::new(),
        };
        let mut pos = start;
        while pos < end {
            let block = metadata_block(image, pos, codec)?;
            if block.next > end {
                return Err(error(format!(
                    "Invalid SquashFS {name} table: metadata block at 0x{pos:X} crosses the table end 0x{end:X}"
                )));
            }
            if table.bytes.len() + block.bytes.len() > MAX_PAYLOAD {
                return Err(error(format!(
                    "Invalid SquashFS {name} table: more than {} decoded",
                    size_text(MAX_PAYLOAD)
                )));
            }
            table.blocks.push(TableBlock {
                relative: (pos - start) as u64,
                position: table.bytes.len(),
                len: block.bytes.len(),
            });
            table.bytes.extend_from_slice(&block.bytes);
            pos = block.next;
        }
        Ok(table)
    }

    /// Decoded position of `offset` in the block at table-relative
    /// `block`. The kernel rejects an offset at or past the block's end
    /// (`squashfs_read_metadata`).
    fn position(&self, block: u64, offset: usize) -> Result<usize> {
        let name = self.name;
        let found = self
            .blocks
            .binary_search_by_key(&block, |b| b.relative)
            .map_err(|_| {
                error(format!(
                    "Invalid SquashFS {name} reference: no metadata block at table offset 0x{block:X}"
                ))
            })?;
        let entry = &self.blocks[found];
        if offset >= entry.len {
            return Err(error(format!(
                "Invalid SquashFS {name} reference: offset {offset} past the {} B block at table offset 0x{block:X}",
                entry.len
            )));
        }
        Ok(entry.position + offset)
    }

    /// The `len` decoded bytes at `pos`, which may span blocks.
    fn bytes(&self, pos: usize, len: usize) -> Result<&[u8]> {
        pos.checked_add(len)
            .and_then(|end| self.bytes.get(pos..end))
            .ok_or_else(|| {
                error(format!(
                    "Truncated SquashFS {} table: 0x{pos:X} + {len} B of {} B decoded",
                    self.name,
                    self.bytes.len()
                ))
            })
    }

    fn u16(&self, pos: usize) -> Result<u16> {
        le_u16(self.bytes(pos, 2)?, 0)
    }

    fn u32(&self, pos: usize) -> Result<u32> {
        le_u32(self.bytes(pos, 4)?, 0)
    }

    fn u64(&self, pos: usize) -> Result<u64> {
        le_u64(self.bytes(pos, 8)?, 0)
    }
}

/// Where a directory's listing is in the directory table.
struct Directory {
    /// Table-relative offset of the listing's first metadata block.
    start_block: u64,
    /// Offset of the listing in that block's decoded bytes.
    offset: usize,
    /// Listing size in bytes (the inode's `file_size` minus 3).
    listing_size: usize,
}

/// A regular file inode (basic or extended).
struct RegularFile {
    /// File offset of the first data block.
    start_block: u64,
    /// Size in bytes.
    file_size: u64,
    /// Fragment table index of the tail, or [`INVALID_FRAGMENT`].
    fragment: u32,
    /// Offset of the tail in the decoded fragment block.
    fragment_offset: u32,
    /// Number of block list entries.
    blocks: usize,
    /// Decoded inode-table position of the block list (u32 entries).
    block_list: usize,
}

/// The inode type at decoded inode-table position `pos`, after checking
/// the inode number (the kernel rejects 0).
fn inode_type(inodes: &Table, pos: usize) -> Result<u16> {
    let kind = inodes.u16(pos)?;
    if inodes.u32(pos + INODE_NUMBER)? == 0 {
        return Err(error(format!(
            "Invalid SquashFS inode at decoded offset 0x{pos:X}: inode number 0"
        )));
    }
    Ok(kind)
}

/// The directory inode `reference` names. Basic (type 1): start block
/// (16), link count (20), file size (24, u16), offset (26, u16), parent
/// (28). Extended (type 8): link count (16), file size (20), start block
/// (24), parent (28), index count (32, u16), offset (34, u16), xattr (36),
/// then the index entries (40).
fn directory_inode(inodes: &Table, reference: u64) -> Result<Directory> {
    let pos = inodes.position(inode_block(reference), inode_offset(reference))?;
    let (start_block, file_size, offset) = match inode_type(inodes, pos)? {
        DIR_TYPE => (
            inodes.u32(pos + 16)?,
            u32::from(inodes.u16(pos + 24)?),
            inodes.u16(pos + 26)?,
        ),
        LDIR_TYPE => {
            let count = usize::from(inodes.u16(pos + 32)?);
            skip_directory_index(inodes, pos + 40, count)?;
            (
                inodes.u32(pos + 24)?,
                inodes.u32(pos + 20)?,
                inodes.u16(pos + 34)?,
            )
        }
        other => {
            return Err(error(format!(
                "Invalid SquashFS inode at decoded offset 0x{pos:X}: type {other}, expected a directory"
            )))
        }
    };
    let listing_size = file_size.checked_sub(DIR_SIZE_BIAS).ok_or_else(|| {
        error(format!(
            "Invalid SquashFS directory inode at decoded offset 0x{pos:X}: size {file_size} B"
        ))
    })?;
    Ok(Directory {
        start_block: u64::from(start_block),
        offset: usize::from(offset),
        listing_size: to_usize(listing_size.into(), "SquashFS directory size")?,
    })
}

/// Extended directory index entries: listing position (u32), start block
/// (u32), name size minus one (u32), name. They speed up lookups only, so
/// a linear walk checks their bounds and skips them.
fn skip_directory_index(inodes: &Table, mut pos: usize, count: usize) -> Result<()> {
    for _ in 0..count {
        let name_size = to_usize(
            u64::from(inodes.u32(pos + 8)?) + 1,
            "SquashFS index name size",
        )?;
        if name_size > NAME_MAX {
            return Err(error(format!(
                "Invalid SquashFS directory index at decoded offset 0x{pos:X}: name of {name_size} B"
            )));
        }
        inodes.bytes(pos + DIR_INDEX_SIZE, name_size)?;
        pos += DIR_INDEX_SIZE + name_size;
    }
    Ok(())
}

/// The regular file inode `reference` names. Basic (type 2): start block
/// (16, u32), fragment (20), fragment offset (24), file size (28, u32),
/// block list (32). Extended (type 9): start block (16, u64), file size
/// (24, u64), sparse bytes (32), link count (40), fragment (44), fragment
/// offset (48), xattr (52), block list (56). A file with a fragment has a
/// block per whole block of data; without one, a block per started block
/// (`unsquash-4.c`).
fn regular_inode(inodes: &Table, sb: &Superblock, reference: u64) -> Result<RegularFile> {
    let pos = inodes.position(inode_block(reference), inode_offset(reference))?;
    let (start_block, file_size, fragment, fragment_offset, block_list) =
        match inode_type(inodes, pos)? {
            REG_TYPE => (
                u64::from(inodes.u32(pos + 16)?),
                u64::from(inodes.u32(pos + 28)?),
                inodes.u32(pos + 20)?,
                inodes.u32(pos + 24)?,
                pos + 32,
            ),
            LREG_TYPE => (
                inodes.u64(pos + 16)?,
                inodes.u64(pos + 24)?,
                inodes.u32(pos + 44)?,
                inodes.u32(pos + 48)?,
                pos + 56,
            ),
            other => {
                return Err(error(format!(
                    "Invalid SquashFS inode at decoded offset 0x{pos:X}: type {other}, expected a regular file"
                )))
            }
        };
    if fragment != INVALID_FRAGMENT && fragment >= sb.fragments {
        return Err(error(format!(
            "Invalid SquashFS fragment index {fragment} at decoded offset 0x{pos:X} ({} fragments)",
            sb.fragments
        )));
    }
    let block_size = sb.block_size as u64;
    let whole = file_size / block_size;
    let started = u64::from(file_size % block_size != 0);
    let blocks = if fragment == INVALID_FRAGMENT {
        whole + started
    } else {
        whole
    };
    let available = (inodes.bytes.len().saturating_sub(block_list) / 4) as u64;
    if blocks > available {
        return Err(error(format!(
            "Invalid SquashFS file inode at decoded offset 0x{pos:X}: {blocks} blocks pass the inode table"
        )));
    }
    Ok(RegularFile {
        start_block,
        file_size,
        fragment,
        fragment_offset,
        blocks: to_usize(blocks, "SquashFS block count")?,
        block_list,
    })
}

/// A fragment table entry: where a fragment block is stored.
struct FragmentEntry {
    /// File offset of the fragment block.
    start: u64,
    /// Stored size in bytes.
    stored_size: usize,
    compressed: bool,
}

/// The last block of a kind that was decoded, kept because neighbouring
/// files share fragment blocks and fragment-table blocks.
struct CachedBlock {
    /// Fragment-table block index, or the fragment block's file offset.
    key: u64,
    bytes: Vec<u8>,
}

/// Reads regular file data: data blocks, sparse blocks and fragment tails.
struct Reader<'a, 't> {
    image: &'a [u8],
    codec: Codec,
    block_size: usize,
    inodes: &'t Table,
    fragment_index: &'t [u64],
    fragment_entries: Option<CachedBlock>,
    fragment_block: Option<CachedBlock>,
}

impl<'a> Reader<'a, '_> {
    /// Block list entry `i` of `file`.
    fn block_entry(&self, file: &RegularFile, i: usize) -> Result<u32> {
        self.inodes.u32(file.block_list + i * 4)
    }

    /// Decoded size of block `i`: a whole block, or the remainder for the
    /// last block of a file without a fragment.
    fn block_len(&self, file: &RegularFile, i: usize) -> usize {
        let block_size = self.block_size as u64;
        let before = i as u64 * block_size;
        let len = file.file_size.saturating_sub(before).min(block_size);
        usize::try_from(len).expect("at most one block, which fits in usize")
    }

    /// Size of the tail stored in a fragment.
    fn tail_size(&self, file: &RegularFile) -> usize {
        if file.fragment == INVALID_FRAGMENT {
            return 0;
        }
        let tail = file.file_size % self.block_size as u64;
        usize::try_from(tail).expect("less than one block, which fits in usize")
    }

    /// Data block `entry` stored at file offset `offset`, as `expected`
    /// bytes. Size 0 is a sparse block of zeros.
    fn data_block(&self, offset: u64, entry: u32, expected: usize) -> Result<Cow<'a, [u8]>> {
        if entry & BLOCK_RESERVED != 0 {
            return Err(error(format!(
                "Invalid SquashFS block list entry 0x{entry:08X}"
            )));
        }
        let stored_size = (entry & BLOCK_SIZE_MASK) as usize;
        if stored_size == 0 {
            return Ok(Cow::Owned(vec![0; expected]));
        }
        if stored_size > self.block_size {
            return Err(error(format!(
                "Invalid SquashFS data block at 0x{offset:X}: {stored_size} B stored, block size {} B",
                self.block_size
            )));
        }
        let stored = slice(
            self.image,
            to_usize(offset, "SquashFS data block offset")?,
            stored_size,
        )?;
        let block = if entry & BLOCK_UNCOMPRESSED != 0 {
            Cow::Borrowed(stored)
        } else {
            let decoded = compressed::decode_limited(self.codec, stored, expected)
                .map_err(|e| error(format!("Invalid SquashFS data block at 0x{offset:X}: {e}")))?;
            Cow::Owned(decoded.data)
        };
        if block.len() != expected {
            return Err(error(format!(
                "Invalid SquashFS data block at 0x{offset:X}: {} B, expected {expected} B",
                block.len()
            )));
        }
        Ok(block)
    }

    /// Fragment table entry `index`: block file offset (u64), stored size
    /// with the uncompressed bit (u32), unused (u32); 512 entries per
    /// metadata block.
    fn fragment_entry(
        &mut self,
        index: u32,
        budget: &mut Budget,
    ) -> std::result::Result<FragmentEntry, Unread> {
        let position = u64::from(index) * FRAGMENT_ENTRY_SIZE;
        let block = position / METADATA_SIZE as u64;
        let within = to_usize(position % METADATA_SIZE as u64, "SquashFS fragment index")?;
        let cached = self
            .fragment_entries
            .as_ref()
            .is_some_and(|entries| entries.key == block);
        if !cached {
            let offset = usize::try_from(block)
                .ok()
                .and_then(|i| self.fragment_index.get(i))
                .ok_or_else(|| error(format!("Invalid SquashFS fragment index {index}")))?;
            budget.charge(METADATA_SIZE)?;
            let entries = metadata_block(
                self.image,
                to_usize(*offset, "SquashFS fragment table block")?,
                self.codec,
            )?;
            self.fragment_entries = Some(CachedBlock {
                key: block,
                bytes: entries.bytes.into_owned(),
            });
        }
        let entries = &self
            .fragment_entries
            .as_ref()
            .expect("fragment table block is cached")
            .bytes;
        let start = le_u64(entries, within)?;
        let size = le_u32(entries, within + 8)?;
        let stored_size = (size & BLOCK_SIZE_MASK) as usize;
        if size & BLOCK_RESERVED != 0 || stored_size == 0 || stored_size > self.block_size {
            return Err(error(format!(
                "Invalid SquashFS fragment {index}: size field 0x{size:08X}"
            ))
            .into());
        }
        Ok(FragmentEntry {
            start,
            stored_size,
            compressed: size & BLOCK_UNCOMPRESSED == 0,
        })
    }

    /// The decoded fragment block stored at `start`, decoded once for all
    /// the files whose tails it holds.
    fn decoded_fragment_block(
        &mut self,
        start: u64,
        stored: &[u8],
        budget: &mut Budget,
    ) -> std::result::Result<&[u8], Unread> {
        let cached = self
            .fragment_block
            .as_ref()
            .is_some_and(|block| block.key == start);
        if !cached {
            budget.charge(self.block_size)?;
            let decoded =
                compressed::decode_limited(self.codec, stored, self.block_size).map_err(|e| {
                    error(format!(
                        "Invalid SquashFS fragment block at 0x{start:X}: {e}"
                    ))
                })?;
            self.fragment_block = Some(CachedBlock {
                key: start,
                bytes: decoded.data,
            });
        }
        Ok(&self
            .fragment_block
            .as_ref()
            .expect("fragment block is cached")
            .bytes)
    }

    /// The tail of `file` in its fragment block: stored bytes when the
    /// fragment is uncompressed, decoded bytes otherwise.
    fn tail(
        &mut self,
        file: &RegularFile,
        budget: &mut Budget,
    ) -> std::result::Result<Cow<'a, [u8]>, Unread> {
        if file.fragment == INVALID_FRAGMENT {
            return Ok(Cow::Borrowed(&[]));
        }
        let tail_size = self.tail_size(file);
        let entry = self.fragment_entry(file.fragment, budget)?;
        let offset = to_usize(file.fragment_offset.into(), "SquashFS fragment offset")?;
        let block_start = to_usize(entry.start, "SquashFS fragment block offset")?;
        let image = self.image;
        let stored = slice(image, block_start, entry.stored_size)?;
        let outside = || {
            error(format!(
                "Invalid SquashFS fragment {}: tail 0x{offset:X} + {tail_size} B outside the block",
                file.fragment
            ))
        };
        if !entry.compressed {
            let tail = slice(stored, offset, tail_size).map_err(|_| outside())?;
            return Ok(Cow::Borrowed(tail));
        }
        let block = self.decoded_fragment_block(entry.start, stored, budget)?;
        let tail = offset
            .checked_add(tail_size)
            .and_then(|end| block.get(offset..end))
            .ok_or_else(outside)?;
        Ok(Cow::Owned(tail.to_vec()))
    }

    /// A file stored only in a fragment: the tail at its stored location
    /// when the fragment block is uncompressed, else decoded from the whole
    /// fragment block.
    fn fragment_member(
        &mut self,
        file: &RegularFile,
        path: String,
        tail: Cow<'a, [u8]>,
        budget: &mut Budget,
    ) -> std::result::Result<Child<'a>, Unread> {
        let entry = self.fragment_entry(file.fragment, budget)?;
        let block_start = to_usize(entry.start, "SquashFS fragment block offset")?;
        Ok(match tail {
            Cow::Borrowed(stored) => {
                // `tail` found the stored tail inside the image, so the sum
                // is a file offset.
                let offset = block_start + file.fragment_offset as usize;
                Child::stored(path, offset, stored)
            }
            Cow::Owned(decoded) => Child::decoded(
                path,
                block_start,
                entry.stored_size,
                Cow::Owned(decoded),
                self.codec.name(),
            ),
        })
    }
}

impl<'a> FileReader<'a> for Reader<'a, '_> {
    type File = RegularFile;

    fn size(&self, file: &RegularFile) -> u64 {
        file.file_size
    }

    fn first_block_size(&self, file: &RegularFile) -> usize {
        if file.blocks == 0 {
            self.tail_size(file)
        } else {
            self.block_len(file, 0)
        }
    }

    fn first_block(
        &mut self,
        file: &RegularFile,
        budget: &mut Budget,
    ) -> std::result::Result<Cow<'a, [u8]>, Unread> {
        if file.blocks == 0 {
            return self.tail(file, budget);
        }
        let entry = self.block_entry(file, 0)?;
        Ok(self.data_block(file.start_block, entry, self.block_len(file, 0))?)
    }

    fn member(
        &mut self,
        file: &RegularFile,
        path: String,
        first: Cow<'a, [u8]>,
        budget: &mut Budget,
    ) -> std::result::Result<Child<'a>, Unread> {
        if file.blocks == 0 {
            return self.fragment_member(file, path, first, budget);
        }
        let start = to_usize(file.start_block, "SquashFS data block offset")?;
        let size = to_usize(file.file_size, "SquashFS file size")?;
        let mut stored_size = 0u64;
        let mut verbatim = file.fragment == INVALID_FRAGMENT;
        for i in 0..file.blocks {
            let entry = self.block_entry(file, i)?;
            let block_stored = entry & BLOCK_SIZE_MASK;
            verbatim &= entry & !BLOCK_SIZE_MASK == BLOCK_UNCOMPRESSED
                && block_stored as usize == self.block_len(file, i);
            // At most 2^24 entries of less than 2^24 B each.
            stored_size += u64::from(block_stored);
        }
        if verbatim {
            // Every block is stored as-is and whole, back to back: the
            // member is the stored bytes themselves.
            return Ok(Child::stored(path, start, slice(self.image, start, size)?));
        }
        let mut contents = Vec::with_capacity(size);
        contents.extend_from_slice(&first);
        let mut decoded = false;
        let mut offset = file.start_block;
        for i in 0..file.blocks {
            let entry = self.block_entry(file, i)?;
            if i > 0 {
                let block = self.data_block(offset, entry, self.block_len(file, i))?;
                contents.extend_from_slice(&block);
            }
            decoded |= entry & BLOCK_SIZE_MASK != 0 && entry & BLOCK_UNCOMPRESSED == 0;
            offset = offset
                .checked_add(u64::from(entry & BLOCK_SIZE_MASK))
                .ok_or_else(|| error("Invalid SquashFS block list: offset overflow"))?;
        }
        let tail = self.tail(file, budget)?;
        decoded |= matches!(tail, Cow::Owned(_)) && !tail.is_empty();
        contents.extend_from_slice(&tail);
        let transform = if decoded {
            self.codec.name()
        } else {
            ASSEMBLED
        };
        Ok(Child::decoded(
            path,
            start,
            to_usize(stored_size, "SquashFS stored file size")?,
            Cow::Owned(contents),
            transform,
        ))
    }
}

/// Walks the directory tree from the root, examining every regular file.
struct Walker<'a, 't> {
    sb: &'t Superblock,
    inodes: &'t Table,
    directories: &'t Table,
    reader: Reader<'a, 't>,
    members: Members<'a>,
    /// Listing bytes walked; more than the directory table holds means
    /// listings repeat (a directory loop).
    walked: usize,
    path: WalkPath,
}

impl Walker<'_, '_> {
    /// Walk one directory listing: headers (entry count minus one, inode
    /// table block, base inode number), each followed by its entries
    /// (inode offset, inode number delta, type, name size minus one, name).
    fn walk(&mut self, dir: &Directory, depth: usize) -> Result<()> {
        if dir.listing_size == 0 {
            return Ok(());
        }
        let directories = self.directories;
        self.walked = self
            .walked
            .checked_add(dir.listing_size)
            .filter(|walked| *walked <= directories.bytes.len())
            .ok_or_else(|| error("Invalid SquashFS directory table: listings overlap or repeat"))?;
        let start = directories.position(dir.start_block, dir.offset)?;
        directories.bytes(start, dir.listing_size)?;
        // The listing lies in the decoded table, so its end is a position.
        let end = start + dir.listing_size;
        let mut pos = start;
        while pos < end {
            if pos + DIR_HEADER_SIZE > end {
                return Err(listing_overrun(start, pos));
            }
            let count = to_usize(
                u64::from(directories.u32(pos)?) + 1,
                "SquashFS directory count",
            )?;
            if count > DIR_COUNT_MAX {
                return Err(error(format!(
                    "Invalid SquashFS directory header at decoded offset 0x{pos:X}: {count} entries"
                )));
            }
            let inode_table_block = u64::from(directories.u32(pos + 4)?);
            pos += DIR_HEADER_SIZE;
            for _ in 0..count {
                pos = self.entry(pos, start, end, inode_table_block, depth)?;
            }
        }
        Ok(())
    }

    /// Visit the directory entry at decoded position `pos` of the listing
    /// `start..end`; returns the position of the next entry.
    fn entry(
        &mut self,
        pos: usize,
        start: usize,
        end: usize,
        inode_table_block: u64,
        depth: usize,
    ) -> Result<usize> {
        let directories = self.directories;
        if pos + DIR_ENTRY_SIZE > end {
            return Err(listing_overrun(start, pos));
        }
        let offset = directories.u16(pos)?;
        let entry_type = directories.u16(pos + 4)?;
        let name_size = usize::from(directories.u16(pos + 6)?) + 1;
        if name_size > NAME_MAX || pos + DIR_ENTRY_SIZE + name_size > end {
            return Err(listing_overrun(start, pos));
        }
        if !(1..=MAX_DIR_TYPE).contains(&entry_type) {
            return Err(error(format!(
                "Invalid SquashFS directory entry at decoded offset 0x{pos:X}: type {entry_type}"
            )));
        }
        let raw_name = directories.bytes(pos + DIR_ENTRY_SIZE, name_size)?;
        let next = pos + DIR_ENTRY_SIZE + name_size;
        let Some(name) = entry_name(raw_name, pos, "SquashFS")? else {
            return Ok(next);
        };
        let reference = (inode_table_block << 16) | u64::from(offset);
        let parent_len = self.path.push(&name);
        let visited = self.visit(entry_type, reference, depth);
        self.path.restore(parent_len);
        visited?;
        Ok(next)
    }

    /// Descend into a directory entry or examine a regular file; other
    /// entry types (symlinks, devices, FIFOs, sockets) hold no code.
    fn visit(&mut self, entry_type: u16, reference: u64, depth: usize) -> Result<()> {
        match entry_type {
            DIR_TYPE => {
                let dir = directory_inode(self.inodes, reference)?;
                if is_walkable(depth + 1, self.path.as_str()) {
                    self.walk(&dir, depth + 1)?;
                } else {
                    self.members.unwalked_directories += 1;
                }
            }
            REG_TYPE => {
                let file = regular_inode(self.inodes, self.sb, reference)?;
                self.members
                    .examine(&mut self.reader, &file, self.path.as_str());
            }
            _ => {}
        }
        Ok(())
    }
}

fn listing_overrun(start: usize, pos: usize) -> ClassifierError {
    error(format!(
        "Invalid SquashFS directory listing at decoded offset 0x{start:X}: entry at 0x{pos:X} crosses the listing end"
    ))
}

/// Parse a Squashfs 4.0 image and list its recognized regular files.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let sb = superblock(data)?;
    let image = &data[..sb.bytes_used];
    let options = compressor_options(image, &sb)?;
    let tables = tables(image, &sb)?;
    expect_padding(data, sb.bytes_used, "SquashFS")?;
    let codec = sb.compressor.codec;
    let inodes = Table::read(
        image,
        sb.inode_table_start,
        sb.directory_table_start,
        codec,
        "inode",
    )?;
    let directories = Table::read(
        image,
        sb.directory_table_start,
        tables.directory_end,
        codec,
        "directory",
    )?;
    let root = directory_inode(&inodes, sb.root_inode)?;

    let mut c = Container::new(FileFormat::Squashfs, Layout::Squashfs.label(), "squashfs");
    c.consumed = sb.bytes_used;
    c.notes.push(format!(
        "SquashFS 4.0, little-endian; {} compression (ID {}); block size {}; {} inodes; {} fragments",
        sb.compressor.name,
        sb.compressor.id,
        size_text(sb.block_size),
        sb.inodes,
        sb.fragments
    ));
    if let Some(note) = options {
        c.notes.push(note);
    }
    if let Some(note) = padding_note(data, sb.bytes_used) {
        c.notes.push(note);
    }
    c.push_metadata("squashfs_version", "Version", "4.0");
    c.push_metadata("squashfs_compressor", "Compressor", sb.compressor.name);
    c.push_metadata(
        "squashfs_block_size",
        "Block size (B)",
        sb.block_size as u64,
    );
    c.push_metadata("squashfs_inodes", "Inodes", u64::from(sb.inodes));
    c.push_metadata(
        "squashfs_bytes_used",
        "Bytes used (B)",
        sb.bytes_used as u64,
    );

    let mut walker = Walker {
        sb: &sb,
        inodes: &inodes,
        directories: &directories,
        reader: Reader {
            image,
            codec,
            block_size: sb.block_size,
            inodes: &inodes,
            fragment_index: &tables.fragment_index,
            fragment_entries: None,
            fragment_block: None,
        },
        members: Members::default(),
        walked: 0,
        path: WalkPath::default(),
    };
    walker.walk(&root, 0)?;
    walker
        .members
        .finish(&mut c, "first data block or fragment tail");
    Ok(c)
}

/// Parse a Squashfs 1.x-3.x or big-endian superblock (`squashfs_compat.h`
/// `squashfs_super_block_3`, packed, in the image's byte order): inode
/// count (4), 1.x/2.x bytes used (8, u32), version (28, 30), 1.x block size
/// (32, u16), block log (34), 2.x/3.x block size (51), fragment count (55),
/// 3.x bytes used (63, u64). Members are not enumerated.
pub(super) fn parse_legacy(data: &[u8]) -> Result<Container<'_>> {
    let le = match le_u32(data, 0)? {
        SQUASHFS_MAGIC => true,
        SQUASHFS_MAGIC_SWAP => false,
        _ => return Err(error("Missing SquashFS magic")),
    };
    let order = if le { "little-endian" } else { "big-endian" };
    let major = u16_at(data, VERSION_MAJOR, le)?;
    let minor = u16_at(data, VERSION_MINOR, le)?;
    let mut c = Container::new(
        FileFormat::Squashfs,
        Layout::SquashfsLegacy.label(),
        "squashfs",
    );
    c.push_metadata("squashfs_version", "Version", format!("{major}.{minor}"));
    c.push_metadata("squashfs_byte_order", "Byte order", order);
    if major == 4 && !le {
        // Linux and squashfs-tools reject a byte-swapped 4.0 superblock;
        // vendor builds exist, but their layout is not documented.
        c.consumed = data.len();
        c.notes.push(format!(
            "Big-endian SquashFS {major}.{minor} superblock; Linux and squashfs-tools accept 4.0 only in little-endian order, so the layout is not interpreted and members are not enumerated"
        ));
        return Ok(c);
    }
    let (bytes_used, block_size, fragments) = match (major, minor) {
        (3, 0..=1) => (
            u64_at(data, LEGACY_BYTES_USED, le)?,
            u32_at(data, LEGACY_BLOCK_SIZE, le)?,
            Some(u32_at(data, LEGACY_FRAGMENTS, le)?),
        ),
        (2, 0..=1) => (
            u64::from(u32_at(data, LEGACY_BYTES_USED_2, le)?),
            u32_at(data, LEGACY_BLOCK_SIZE, le)?,
            Some(u32_at(data, LEGACY_FRAGMENTS, le)?),
        ),
        (1, 0) => (
            u64::from(u32_at(data, LEGACY_BYTES_USED_2, le)?),
            u32::from(u16_at(data, LEGACY_BLOCK_SIZE_1, le)?),
            None,
        ),
        _ => {
            return Err(error(format!(
                "Unsupported SquashFS version {major}.{minor} ({order})"
            )))
        }
    };
    let block_log = u16_at(data, LEGACY_BLOCK_LOG, le)?;
    if block_log > MAX_BLOCK_LOG || block_size != 1 << block_log {
        return Err(error(format!(
            "Invalid SquashFS block size {block_size} B (block_log {block_log})"
        )));
    }
    if bytes_used > data.len() as u64 {
        return Err(error(format!(
            "Truncated SquashFS image: bytes_used is {bytes_used} B, {} B present",
            data.len()
        )));
    }
    let bytes_used = to_usize(bytes_used, "SquashFS bytes_used")?;
    expect_padding(data, bytes_used, "SquashFS")?;
    c.consumed = bytes_used;
    let fragments = fragments.map_or_else(String::new, |n| format!("; {n} fragments"));
    c.notes.push(format!(
        "SquashFS {major}.{minor}, {order}; block size {}; {} inodes{fragments}",
        size_text(to_usize(block_size.into(), "SquashFS block size")?),
        u32_at(data, LEGACY_INODES, le)?
    ));
    c.notes.push(format!(
        "Compressor not recorded in the superblock (squashfs-tools reads {major}.x images as zlib); member enumeration is not implemented for SquashFS {major}.x"
    ));
    if let Some(note) = padding_note(data, bytes_used) {
        c.notes.push(note);
    }
    c.push_metadata("squashfs_bytes_used", "Bytes used (B)", bytes_used as u64);
    Ok(c)
}

/// Parse a streamed Squashfs image (squashfs-tools 4.7.5): the magic and a
/// zeroed placeholder up to 96 bytes; squashfs-tools reads the real
/// superblock from the last 96 bytes of the file. Members are not
/// enumerated.
pub(super) fn parse_streamed(data: &[u8]) -> Result<Container<'_>> {
    let order = match le_u32(data, 0)? {
        SQUASHFS_MAGIC_STREAMED => "little-endian",
        SQUASHFS_MAGIC_STREAMED_SWAPPED => "big-endian",
        _ => return Err(error("Missing streamed SquashFS magic")),
    };
    if !is_streamed_header(data) {
        return Err(error(
            "Invalid streamed SquashFS header: bytes after the magic are not zero",
        ));
    }
    let mut c = Container::new(
        FileFormat::Squashfs,
        Layout::SquashfsStreamed.label(),
        "squashfs",
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "Streamed SquashFS ({order} magic, squashfs-tools 4.7 and later); squashfs-tools reads the superblock from the last 96 B; members are not enumerated"
    ));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_references_split_into_block_and_offset() {
        let reference = (0x1234u64 << 16) | 0x56;
        assert_eq!(inode_block(reference), 0x1234);
        assert_eq!(inode_offset(reference), 0x56);
    }

    #[test]
    fn index_sizes_round_up_to_whole_metadata_blocks() {
        assert_eq!(index_size(4), 8);
        assert_eq!(index_size(8192), 8);
        assert_eq!(index_size(8193), 16);
    }

    #[test]
    fn metadata_blocks_reject_zero_and_oversized_lengths() {
        let mut stored = vec![0u8; 2 + 4];
        stored[..2].copy_from_slice(&(METADATA_UNCOMPRESSED | 4).to_le_bytes());
        let block = metadata_block(&stored, 0, Codec::Zlib).unwrap();
        assert_eq!((block.bytes.len(), block.next), (4, 6));
        assert!(metadata_block(&METADATA_UNCOMPRESSED.to_le_bytes(), 0, Codec::Zlib).is_err());
        // 0x2001 B is one byte more than a metadata block holds.
        let oversized = (METADATA_UNCOMPRESSED | 0x2001).to_le_bytes();
        assert!(metadata_block(&oversized, 0, Codec::Zlib).is_err());
    }

    #[test]
    fn table_references_must_name_a_block_start_and_an_offset_inside_it() {
        let mut image = Vec::new();
        for len in [8u16, 4] {
            image.extend_from_slice(&(METADATA_UNCOMPRESSED | len).to_le_bytes());
            image.extend(std::iter::repeat(0xaa).take(usize::from(len)));
        }
        let table = Table::read(&image, 0, image.len() as u64, Codec::Zlib, "inode").unwrap();
        assert_eq!(table.bytes.len(), 12);
        assert_eq!(table.position(10, 3).unwrap(), 11);
        assert!(table.position(10, 4).is_err());
        assert!(table.position(1, 0).is_err());
        assert!(Table::read(&image, 0, 9, Codec::Zlib, "inode").is_err());
    }

    #[test]
    fn exact_indexes_must_end_at_the_next_table_and_increase() {
        // Two id blocks at 0x10 and 0x20, index at 0x30.
        let mut image = vec![0u8; 0x30];
        image.extend_from_slice(&0x10u64.to_le_bytes());
        image.extend_from_slice(&0x20u64.to_le_bytes());
        let index = ExactIndex {
            name: "id",
            start: 0x30,
            next_table: 0x40,
            blocks_end: 0x30,
            entries_size: 8192 + 4,
        };
        assert_eq!(exact_index(&image, &index).unwrap(), vec![0x10, 0x20]);
        let short = ExactIndex {
            next_table: 0x48,
            ..index
        };
        assert!(exact_index(&image, &short).is_err());
        image.swap(0x30, 0x38);
        let index = ExactIndex {
            name: "id",
            start: 0x30,
            next_table: 0x40,
            blocks_end: 0x30,
            entries_size: 8192 + 4,
        };
        assert!(exact_index(&image, &index).is_err());
    }

    #[test]
    fn bcj_filter_bits_are_named_in_wrapper_order() {
        assert_eq!(bcj_filters(0), "none");
        assert_eq!(bcj_filters(0b1000_1001), "x86, arm, riscv");
    }
}
