//! UBIFS volume images: the superblock node at LEB 0 and every node in the
//! main-area LEBs (Linux v6.11 `fs/ubifs/ubifs-media.h`, `key.h`, `scan.c`,
//! `io.c`, `sb.c`, `super.c`, `file.c`).
//!
//! Nodes are little-endian, 8-byte aligned, and start with a 24-byte common
//! header whose CRC (`crc32(UBIFS_CRC32_INIT, ...)` without final
//! inversion) covers the node from byte 8. LEB `n` starts at `n *
//! leb_size`, as `mkfs.ubifs` writes an image and as a UBI volume is
//! rebuilt. The tree is rebuilt from inode, directory-entry, data and
//! truncation nodes, keeping the highest sequence number per key, as a
//! journal replay would; the index is not walked.

use super::*;
use std::ops::RangeInclusive;

/// Common header magic (`UBIFS_NODE_MAGIC`), and the header size.
const UBIFS_NODE_MAGIC: u32 = 0x0610_1831;
const UBIFS_CH_SZ: usize = 24;

/// The node CRC covers the node from this offset (after magic and CRC).
const UBIFS_CRC_START: usize = 8;

/// Node types (`enum` in `ubifs-media.h`).
const UBIFS_INO_NODE: u8 = 0;
const UBIFS_DATA_NODE: u8 = 1;
const UBIFS_DENT_NODE: u8 = 2;
const UBIFS_XENT_NODE: u8 = 3;
const UBIFS_TRUN_NODE: u8 = 4;
const UBIFS_PAD_NODE: u8 = 5;
const UBIFS_SB_NODE: u8 = 6;
const UBIFS_MST_NODE: u8 = 7;
const UBIFS_REF_NODE: u8 = 8;
const UBIFS_IDX_NODE: u8 = 9;
const UBIFS_CS_NODE: u8 = 10;
const UBIFS_ORPH_NODE: u8 = 11;
const UBIFS_AUTH_NODE: u8 = 12;
const UBIFS_SIG_NODE: u8 = 13;

/// Fixed node sizes (`UBIFS_*_NODE_SZ`).
const UBIFS_INO_NODE_SZ: usize = 160;
const UBIFS_DATA_NODE_SZ: usize = 48;
const UBIFS_DENT_NODE_SZ: usize = 56;
const UBIFS_TRUN_NODE_SZ: usize = 56;
const UBIFS_PAD_NODE_SZ: usize = 28;
const UBIFS_SB_NODE_SZ: usize = 4096;
const UBIFS_MST_NODE_SZ: usize = 512;
const UBIFS_REF_NODE_SZ: usize = 64;
const UBIFS_IDX_NODE_SZ: usize = 28;
const UBIFS_CS_NODE_SZ: usize = 32;
const UBIFS_ORPH_NODE_SZ: usize = 32;
const UBIFS_AUTH_NODE_SZ: usize = 24;
const UBIFS_SIG_NODE_SZ: usize = 64;

/// An index branch with the 8-byte simple key (`UBIFS_BRANCH_SZ` plus
/// `UBIFS_SK_LEN`).
const UBIFS_BRANCH_SZ: usize = 12 + 8;

/// An orphan node lists at least one 8-byte inode number.
const UBIFS_ORPH_ENTRY_SZ: usize = 8;

/// Largest HMAC an authentication node carries (`UBIFS_MAX_HMAC_LEN`).
const UBIFS_MAX_HMAC_LEN: usize = 64;

/// Limits (`UBIFS_MAX_NLEN`, `UBIFS_MAX_INO_DATA`, `UBIFS_BLOCK_SIZE`).
const UBIFS_MAX_NLEN: usize = 255;
const UBIFS_MAX_INO_DATA: usize = 4096;
const UBIFS_BLOCK_SIZE: usize = 4096;

/// Fill for gaps too small for a padding node (`UBIFS_PADDING_BYTE`).
const UBIFS_PADDING_BYTE: u8 = 0xCE;

/// Erased flash read as a little-endian word, where `ubifs_scan` stops.
const ERASED_WORD: u32 = 0xFFFF_FFFF;

/// Nodes and padding are 8-byte aligned.
const UBIFS_NODE_ALIGN: usize = 8;

/// Smallest LEB (`UBIFS_MIN_LEB_SZ`); the largest accepted is an own
/// bound, four times the largest common NAND erase block.
const UBIFS_MIN_LEB_SZ: usize = 15 * 1024;
const MAX_LEB_SIZE: usize = 16 << 20;

/// Fixed areas before the log, and the minimum area sizes
/// (`UBIFS_SB_LEBS`, `UBIFS_MST_LEBS`, `UBIFS_MIN_*_LEBS`).
const UBIFS_SB_LEBS: u32 = 1;
const UBIFS_MST_LEBS: u32 = 2;
const UBIFS_MIN_LOG_LEBS: u32 = 2;
const UBIFS_MIN_LPT_LEBS: u32 = 2;
const UBIFS_MIN_ORPH_LEBS: u32 = 1;

/// Index fanout lower bound (`UBIFS_MIN_FANOUT`).
const UBIFS_MIN_FANOUT: u32 = 3;

/// Format versions: the oldest the kernel mounts, the newest it writes, and
/// the read-only compatibility version newer formats must declare to be
/// mounted read-only (`validate_sb`, `UBIFS_FORMAT_VERSION`,
/// `UBIFS_RO_COMPAT_VERSION`).
const UBIFS_OLDEST_FORMAT_VERSION: u32 = 3;
const UBIFS_FORMAT_VERSION: u32 = 5;
const UBIFS_RO_COMPAT_VERSION: u32 = 0;

/// The simple key format and the two name hash functions.
const UBIFS_SIMPLE_KEY_FMT: u8 = 0;
const UBIFS_KEY_HASH_TEST: u8 = 1;

/// Key types in the top three bits of the second key word, and the block
/// number in the low 29 bits of a data key (`UBIFS_S_KEY_BLOCK_BITS`).
const UBIFS_INO_KEY: u32 = 0;
const UBIFS_DATA_KEY: u32 = 1;
const UBIFS_DENT_KEY: u32 = 2;
const UBIFS_XENT_KEY: u32 = 3;
const UBIFS_S_KEY_BLOCK_BITS: u32 = 29;
const UBIFS_S_KEY_BLOCK_MASK: u32 = 0x1FFF_FFFF;

/// Compression types (`UBIFS_COMPR_*`).
const UBIFS_COMPR_NONE: u16 = 0;
const UBIFS_COMPR_LZO: u16 = 1;
const UBIFS_COMPR_ZLIB: u16 = 2;
const UBIFS_COMPR_ZSTD: u16 = 3;

/// Inode types in directory entries (`UBIFS_ITYPE_*`), and their count.
const UBIFS_ITYPE_REG: u8 = 0;
const UBIFS_ITYPE_DIR: u8 = 1;
const UBIFS_ITYPES_CNT: u8 = 7;

/// The root directory inode (`UBIFS_ROOT_INO`).
const UBIFS_ROOT_INO: u32 = 1;

/// Inode flag: file contents and names are encrypted (`UBIFS_CRYPT_FL`).
const UBIFS_CRYPT_FL: u32 = 0x40;

/// Superblock flags (`UBIFS_FLG_ENCRYPTION`, `UBIFS_FLG_AUTHENTICATION`).
const UBIFS_FLG_ENCRYPTION: u32 = 0x10;
const UBIFS_FLG_AUTHENTICATION: u32 = 0x20;

/// Most nodes recorded from one image (own bound on memory).
const MAX_NODES: usize = 1 << 20;

/// Whether `data` starts with a UBIFS node header of the superblock type.
pub(super) fn starts_with_superblock(data: &[u8]) -> bool {
    le_u32(data, 0).is_ok_and(|magic| magic == UBIFS_NODE_MAGIC)
        && byte(data, 20).is_ok_and(|node_type| node_type == UBIFS_SB_NODE)
}

/// Superblock fields the parser uses.
#[derive(Debug)]
struct Superblock {
    flags: u32,
    min_io_size: u32,
    leb_size: usize,
    leb_cnt: u32,
    max_leb_cnt: u32,
    fanout: u32,
    fmt_version: u32,
    default_compr: u16,
    /// First LEB of the main area, after superblock, master, log, LPT and
    /// orphan areas.
    main_first: u32,
}

/// How a data node's compression type stores the block, or `None` for a
/// type this parser does not know.
fn encoding(compr_type: u16) -> Option<Encoding> {
    match compr_type {
        UBIFS_COMPR_NONE => Some(Encoding::Stored),
        UBIFS_COMPR_LZO => Some(Encoding::Codec(Codec::Lzo1x)),
        // The kernel's "deflate" crypto transform: raw DEFLATE.
        UBIFS_COMPR_ZLIB => Some(Encoding::Codec(Codec::Deflate)),
        UBIFS_COMPR_ZSTD => Some(Encoding::Codec(Codec::Zstd)),
        _ => None,
    }
}

fn compression_name(compr_type: u16) -> &'static str {
    match compr_type {
        UBIFS_COMPR_NONE => "none",
        UBIFS_COMPR_LZO => "LZO",
        UBIFS_COMPR_ZLIB => "zlib",
        UBIFS_COMPR_ZSTD => "Zstandard",
        _ => "unknown",
    }
}

/// Superblock node: common header, key hash (26), key format (27), flags
/// (28), minimum I/O size (32), LEB size (36), LEB count (40), maximum LEB
/// count (44), log, LPT and orphan LEBs (56, 60, 64), fanout (72), format
/// version (80), default compression (84), read-only compatibility version
/// (124). Checked as `validate_sb` does, except for the LEB count minimum,
/// which the kernel applies after growing the filesystem to its volume,
/// and the comparisons with the UBI device.
fn superblock(data: &[u8]) -> Result<Superblock> {
    let node =
        slice(data, 0, UBIFS_SB_NODE_SZ).map_err(|_| error("Truncated UBIFS superblock node"))?;
    let len = le_u32(node, 16)? as usize;
    if len != UBIFS_SB_NODE_SZ {
        return Err(error(format!("Invalid UBIFS superblock node length {len}")));
    }
    if crc32_ones(&node[UBIFS_CRC_START..]) != le_u32(node, 4)? {
        return Err(error("Invalid UBIFS superblock node CRC-32"));
    }
    let key_hash = node[26];
    let key_fmt = node[27];
    if key_fmt != UBIFS_SIMPLE_KEY_FMT || key_hash > UBIFS_KEY_HASH_TEST {
        return Err(error(format!(
            "Unsupported UBIFS key format {key_fmt} or hash {key_hash}"
        )));
    }
    let leb_size = le_u32(node, 36)? as usize;
    let min_io_size = le_u32(node, 32)?;
    if !(UBIFS_MIN_LEB_SZ..=MAX_LEB_SIZE).contains(&leb_size) {
        return Err(error(format!("Invalid UBIFS LEB size {leb_size} B")));
    }
    if !min_io_size.is_power_of_two() || min_io_size as usize > leb_size {
        return Err(error(format!(
            "Invalid UBIFS minimum I/O size {min_io_size} B"
        )));
    }
    let leb_cnt = le_u32(node, 40)?;
    let max_leb_cnt = le_u32(node, 44)?;
    let log_lebs = le_u32(node, 56)?;
    let lpt_lebs = le_u32(node, 60)?;
    let orph_lebs = le_u32(node, 64)?;
    if log_lebs < UBIFS_MIN_LOG_LEBS
        || lpt_lebs < UBIFS_MIN_LPT_LEBS
        || orph_lebs < UBIFS_MIN_ORPH_LEBS
    {
        return Err(error(
            "Invalid UBIFS superblock: log, LPT or orphan area too small",
        ));
    }
    let main_first = [UBIFS_MST_LEBS, log_lebs, lpt_lebs, orph_lebs]
        .iter()
        .try_fold(UBIFS_SB_LEBS, |sum, n| sum.checked_add(*n))
        .filter(|first| *first <= leb_cnt && leb_cnt <= max_leb_cnt)
        .ok_or_else(|| error("Invalid UBIFS superblock: area sizes exceed the LEB count"))?;
    let fanout = le_u32(node, 72)?;
    let fmt_version = le_u32(node, 80)?;
    let default_compr = le_u16(node, 84)?;
    let ro_compat_version = le_u32(node, 124)?;
    let max_index = UBIFS_IDX_NODE_SZ as u64 + UBIFS_BRANCH_SZ as u64 * u64::from(fanout);
    if fanout < UBIFS_MIN_FANOUT || max_index > leb_size as u64 {
        return Err(error(format!("Invalid UBIFS index fanout {fanout}")));
    }
    let too_new = fmt_version > UBIFS_FORMAT_VERSION && ro_compat_version > UBIFS_RO_COMPAT_VERSION;
    if fmt_version < UBIFS_OLDEST_FORMAT_VERSION || too_new {
        return Err(error(format!(
            "Unsupported UBIFS format version {fmt_version}"
        )));
    }
    if encoding(default_compr).is_none() {
        return Err(error(format!(
            "Invalid UBIFS default compression {default_compr}"
        )));
    }
    Ok(Superblock {
        flags: le_u32(node, 28)?,
        min_io_size,
        leb_size,
        leb_cnt,
        max_leb_cnt,
        fanout,
        fmt_version,
        default_compr,
        main_first,
    })
}

/// The valid lengths of a node type (`c->ranges` in `super.c`), or `None`
/// for a type at or above `UBIFS_NODE_TYPES_CNT`.
fn length_range(node_type: u8, sb: &Superblock) -> Option<RangeInclusive<usize>> {
    let fixed = |len: usize| len..=len;
    let range = match node_type {
        UBIFS_INO_NODE => UBIFS_INO_NODE_SZ..=UBIFS_INO_NODE_SZ + UBIFS_MAX_INO_DATA,
        UBIFS_DATA_NODE => UBIFS_DATA_NODE_SZ..=UBIFS_DATA_NODE_SZ + UBIFS_BLOCK_SIZE,
        UBIFS_DENT_NODE | UBIFS_XENT_NODE => {
            UBIFS_DENT_NODE_SZ..=UBIFS_DENT_NODE_SZ + UBIFS_MAX_NLEN + 1
        }
        UBIFS_TRUN_NODE => fixed(UBIFS_TRUN_NODE_SZ),
        UBIFS_PAD_NODE => fixed(UBIFS_PAD_NODE_SZ),
        UBIFS_SB_NODE => fixed(UBIFS_SB_NODE_SZ),
        UBIFS_MST_NODE => fixed(UBIFS_MST_NODE_SZ),
        UBIFS_REF_NODE => fixed(UBIFS_REF_NODE_SZ),
        UBIFS_CS_NODE => fixed(UBIFS_CS_NODE_SZ),
        UBIFS_IDX_NODE => {
            UBIFS_IDX_NODE_SZ + UBIFS_BRANCH_SZ
                ..=UBIFS_IDX_NODE_SZ + UBIFS_BRANCH_SZ * sb.fanout as usize
        }
        UBIFS_ORPH_NODE => UBIFS_ORPH_NODE_SZ + UBIFS_ORPH_ENTRY_SZ..=sb.leb_size,
        UBIFS_AUTH_NODE => UBIFS_AUTH_NODE_SZ..=UBIFS_AUTH_NODE_SZ + UBIFS_MAX_HMAC_LEN,
        UBIFS_SIG_NODE => UBIFS_SIG_NODE_SZ..=sb.leb_size - UBIFS_SB_NODE_SZ,
        _ => return None,
    };
    Some(range)
}

/// The newest inode node of an inode number.
#[derive(Debug)]
struct Inode {
    sqnum: u64,
    /// File size in bytes.
    size: u64,
    nlink: u32,
    flags: u32,
}

/// The newest data node of one 4 KiB block.
#[derive(Debug)]
struct DataNode<'a> {
    sqnum: u64,
    /// Decoded bytes in the block (1 to 4096); the rest of the block is
    /// zero.
    size: usize,
    compr_type: u16,
    stored: &'a [u8],
    /// Offset of the stored bytes in the image.
    offset: usize,
}

/// The newest directory entry for one parent and name.
#[derive(Debug)]
struct Dent {
    sqnum: u64,
    /// Target inode; 0 marks a deletion.
    inum: u32,
    itype: u8,
}

/// A truncation node: blocks from `new_size` on with older data are gone.
#[derive(Debug, Clone, Copy)]
struct Truncation {
    sqnum: u64,
    /// File size after the truncation, in bytes.
    new_size: u64,
}

/// The truncations of one inode by sequence number, with the smallest new
/// size among each truncation and every later one, so that one binary
/// search tells whether a data node was truncated away.
#[derive(Debug, Default)]
struct Truncations {
    sqnums: Vec<u64>,
    smallest_later_size: Vec<u64>,
}

impl Truncations {
    fn new(mut list: Vec<Truncation>) -> Self {
        list.sort_by_key(|t| t.sqnum);
        let mut smallest_later_size = vec![0; list.len()];
        let mut smallest = u64::MAX;
        for (i, truncation) in list.iter().enumerate().rev() {
            smallest = smallest.min(truncation.new_size);
            smallest_later_size[i] = smallest;
        }
        Self {
            sqnums: list.iter().map(|t| t.sqnum).collect(),
            smallest_later_size,
        }
    }

    /// Whether a truncation newer than `sqnum` cut the file at or before
    /// `block_start`.
    fn removes(&self, sqnum: u64, block_start: u64) -> bool {
        let first_newer = self.sqnums.partition_point(|s| *s <= sqnum);
        self.smallest_later_size
            .get(first_newer)
            .is_some_and(|size| *size <= block_start)
    }
}

/// Everything the scan keeps.
#[derive(Debug, Default)]
struct Nodes<'a> {
    inodes: BTreeMap<u32, Inode>,
    data: BTreeMap<(u32, u32), DataNode<'a>>,
    dents: BTreeMap<(u32, Vec<u8>), Dent>,
    truncations: BTreeMap<u32, Vec<Truncation>>,
    /// Nodes whose header and CRC checked.
    count: usize,
}

/// Insert `value` unless the map holds a node with a higher sequence
/// number for the same key. Equal sequence numbers are copies moved by
/// garbage collection; the first one scanned is kept.
fn keep_newest<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V, sqnum: impl Fn(&V) -> u64) {
    match map.get(&key) {
        Some(existing) if sqnum(existing) >= sqnum(&value) => {}
        _ => {
            map.insert(key, value);
        }
    }
}

/// Why a node that passed the header checks was not recorded.
type NodeFault = &'static str;

/// A simple key: the inode number, and the low 29 bits of the second word
/// (a block number or name hash).
struct Key {
    inum: u32,
    low: u32,
}

/// Key: inode number, then the key type in the top 3 bits and a block
/// number or name hash in the low 29 bits of the second word.
fn key(node: &[u8], expected_type: u32) -> std::result::Result<Key, NodeFault> {
    let (Ok(inum), Ok(word)) = (le_u32(node, 24), le_u32(node, 28)) else {
        return Err("truncated key");
    };
    if word >> UBIFS_S_KEY_BLOCK_BITS != expected_type {
        return Err("key type disagrees with the node type");
    }
    Ok(Key {
        inum,
        low: word & UBIFS_S_KEY_BLOCK_MASK,
    })
}

/// Record the body of a checked node. `offset` is the node's offset in the
/// image.
fn record<'a>(
    nodes: &mut Nodes<'a>,
    node: &'a [u8],
    node_type: u8,
    sqnum: u64,
    offset: usize,
) -> std::result::Result<(), NodeFault> {
    let truncated = |_| "truncated node";
    match node_type {
        UBIFS_INO_NODE => {
            let inum = key(node, UBIFS_INO_KEY)?.inum;
            let data_len = le_u32(node, 112).map_err(truncated)? as usize;
            if node.len() != UBIFS_INO_NODE_SZ + data_len {
                return Err("inode data length disagrees with the node length");
            }
            let inode = Inode {
                sqnum,
                size: le_u64(node, 48).map_err(truncated)?,
                nlink: le_u32(node, 92).map_err(truncated)?,
                flags: le_u32(node, 108).map_err(truncated)?,
            };
            keep_newest(&mut nodes.inodes, inum, inode, |i| i.sqnum);
        }
        UBIFS_DATA_NODE => {
            let Key { inum, low: block } = key(node, UBIFS_DATA_KEY)?;
            let size = le_u32(node, 40).map_err(truncated)? as usize;
            if size == 0 || size > UBIFS_BLOCK_SIZE {
                return Err("data node size out of range");
            }
            let data_node = DataNode {
                sqnum,
                size,
                compr_type: le_u16(node, 44).map_err(truncated)?,
                stored: &node[UBIFS_DATA_NODE_SZ..],
                offset: offset + UBIFS_DATA_NODE_SZ,
            };
            keep_newest(&mut nodes.data, (inum, block), data_node, |d| d.sqnum);
        }
        UBIFS_DENT_NODE => {
            let parent = key(node, UBIFS_DENT_KEY)?.inum;
            let inum = le_u64(node, 40).map_err(truncated)?;
            let itype = node[49];
            let name_len = usize::from(le_u16(node, 50).map_err(truncated)?);
            // `ubifs_validate_entry`: the node holds the name and its
            // terminating NUL.
            if name_len > UBIFS_MAX_NLEN
                || node.len() != UBIFS_DENT_NODE_SZ + name_len + 1
                || node[UBIFS_DENT_NODE_SZ + name_len] != 0
                || itype >= UBIFS_ITYPES_CNT
            {
                return Err("invalid directory entry");
            }
            let inum = u32::try_from(inum).map_err(|_| "inode number out of range")?;
            let name = node[UBIFS_DENT_NODE_SZ..UBIFS_DENT_NODE_SZ + name_len].to_vec();
            let dent = Dent { sqnum, inum, itype };
            keep_newest(&mut nodes.dents, (parent, name), dent, |d| d.sqnum);
        }
        UBIFS_XENT_NODE => {
            key(node, UBIFS_XENT_KEY)?;
        }
        UBIFS_TRUN_NODE => {
            let inum = le_u32(node, 24).map_err(truncated)?;
            let new_size = le_u64(node, 48).map_err(truncated)?;
            nodes
                .truncations
                .entry(inum)
                .or_default()
                .push(Truncation { sqnum, new_size });
        }
        _ => {}
    }
    nodes.count += 1;
    Ok(())
}

/// Where and why the scan of one LEB stopped early.
#[derive(Debug, PartialEq, Eq)]
struct ScanStop {
    /// Offset in the LEB, in bytes.
    offset: usize,
    reason: &'static str,
}

/// Scan one LEB as `ubifs_scan` does: nodes at 8-byte steps, padding nodes
/// and padding bytes skipped, and erased flash to the end. Returns where
/// scanning failed, if it did; the nodes before it are kept.
fn scan_leb<'a>(
    leb: &'a [u8],
    leb_offset: usize,
    sb: &Superblock,
    nodes: &mut Nodes<'a>,
) -> Option<ScanStop> {
    let mut offset = 0;
    let stop = |offset: usize, reason: &'static str| Some(ScanStop { offset, reason });
    while leb.len() - offset >= UBIFS_NODE_ALIGN && nodes.count < MAX_NODES {
        let rest = &leb[offset..];
        let magic = le_u32(rest, 0).ok()?;
        if magic == ERASED_WORD {
            break;
        }
        if magic != UBIFS_NODE_MAGIC {
            // `scan_padding_bytes`: a run of padding bytes shorter than a
            // padding node, ending 8-byte aligned.
            let run = rest
                .iter()
                .take(UBIFS_PAD_NODE_SZ)
                .take_while(|b| **b == UBIFS_PADDING_BYTE)
                .count();
            if run == 0 || run % UBIFS_NODE_ALIGN != 0 {
                return stop(offset, "neither a node, padding nor erased flash");
            }
            offset += run;
            continue;
        }
        if rest.len() < UBIFS_CH_SZ {
            return stop(offset, "truncated node header");
        }
        let len = le_u32(rest, 16).ok()? as usize;
        let node_type = rest[20];
        let Some(lengths) = length_range(node_type, sb) else {
            return stop(offset, "unknown node type");
        };
        if !lengths.contains(&len) || len > rest.len() {
            return stop(offset, "node length out of range");
        }
        let node = &rest[..len];
        if crc32_ones(&node[UBIFS_CRC_START..]) != le_u32(node, 4).ok()? {
            return stop(offset, "node CRC-32 fails");
        }
        if node_type == UBIFS_PAD_NODE {
            // The padding follows the 28-byte node outside its CRC.
            let pad_len = le_u32(node, 24).ok()? as usize;
            let padded = len.saturating_add(pad_len);
            if padded > rest.len() || padded % UBIFS_NODE_ALIGN != 0 {
                return stop(offset, "invalid padding node");
            }
            offset += padded;
            continue;
        }
        let sqnum = le_u64(node, 8).ok()?;
        if let Err(reason) = record(nodes, node, node_type, sqnum, leb_offset + offset) {
            return stop(offset, reason);
        }
        offset += align_up(len, UBIFS_NODE_ALIGN).ok()?.min(rest.len());
    }
    if nodes.count >= MAX_NODES {
        return None;
    }
    if !is_erased(&leb[offset..]) {
        return stop(offset, "data after the erased flash");
    }
    None
}

/// The live directory entries, in key order.
fn live_dirents(nodes: &Nodes<'_>) -> Vec<Dirent> {
    nodes
        .dents
        .iter()
        .filter(|(_, dent)| dent.inum != 0)
        .map(|((parent, name), dent)| Dirent {
            parent: *parent,
            name: name.clone(),
            inum: dent.inum,
            kind: match dent.itype {
                UBIFS_ITYPE_REG => EntryKind::RegularFile,
                UBIFS_ITYPE_DIR => EntryKind::Directory,
                _ => EntryKind::Other,
            },
        })
        .collect()
}

/// The contents of one regular file: the newest data node of each block
/// within the file size that no newer truncation removed. `None` for a
/// deleted inode.
fn file_data<'a>(
    nodes: &Nodes<'a>,
    truncations: &BTreeMap<u32, Truncations>,
    inum: u32,
) -> Option<FileData<'a>> {
    let mut file = FileData::default();
    let Some(inode) = nodes.inodes.get(&inum) else {
        file.unsupported = Some("no inode node found".into());
        return Some(file);
    };
    if inode.nlink == 0 {
        // Deleted: the newest inode node is a deletion inode.
        return None;
    }
    file.size = inode.size;
    if inode.flags & UBIFS_CRYPT_FL != 0 {
        file.unsupported = Some("encrypted".into());
        return Some(file);
    }
    let truncations = truncations.get(&inum);
    for (&(_, block), data_node) in nodes.data.range((inum, 0)..=(inum, u32::MAX)) {
        let block_start = u64::from(block) * UBIFS_BLOCK_SIZE as u64;
        let truncated = truncations.is_some_and(|t| t.removes(data_node.sqnum, block_start));
        if block_start >= inode.size || truncated {
            continue;
        }
        let Some(encoding) = encoding(data_node.compr_type) else {
            file.unsupported = Some(format!(
                "unsupported compression type {}",
                data_node.compr_type
            ));
            return Some(file);
        };
        file.extents.push(Extent {
            file_offset: block_start,
            size: data_node.size,
            stored: data_node.stored,
            offset: data_node.offset,
            encoding,
        });
    }
    Some(file)
}

/// `"3 LZO1X, 1 stored"` for the newest data node of every block.
fn data_summary(nodes: &Nodes<'_>) -> String {
    let names = nodes.data.values().map(|data_node| {
        encoding(data_node.compr_type).map_or("unknown compression", Encoding::name)
    });
    encoding_summary(names)
}

/// LEBs that `data` holds at least partly, up to the superblock's LEB
/// count. `mkfs.ubifs` does not pad the last LEB.
fn present_lebs(data: &[u8], sb: &Superblock) -> usize {
    let partial = usize::from(data.len() % sb.leb_size != 0);
    (data.len() / sb.leb_size + partial).min(sb.leb_cnt as usize)
}

/// The main-area LEBs present in `data`, scanned in order. Returns the
/// notes on LEBs whose scan stopped early.
fn scan_main_area<'a>(data: &'a [u8], sb: &Superblock, nodes: &mut Nodes<'a>) -> Vec<String> {
    let mut notes = Vec::new();
    let mut stopped = 0usize;
    for lnum in sb.main_first as usize..present_lebs(data, sb) {
        // A present LEB starts inside `data`.
        let start = lnum * sb.leb_size;
        let leb = &data[start..(start + sb.leb_size).min(data.len())];
        let Some(stop) = scan_leb(leb, start, sb, nodes) else {
            continue;
        };
        stopped += 1;
        if notes.len() < MAX_MEMBER_NOTES {
            notes.push(format!(
                "LEB {lnum}: scanning stopped at offset 0x{:X} ({}); later nodes in the LEB ignored",
                stop.offset, stop.reason
            ));
        }
    }
    if stopped > MAX_MEMBER_NOTES {
        notes.push(format!(
            "{} further LEBs stopped scanning early",
            stopped - MAX_MEMBER_NOTES
        ));
    }
    notes
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !starts_with_superblock(data) {
        return Err(error("Missing UBIFS superblock node"));
    }
    let sb = superblock(data)?;
    let main_start = (sb.main_first as usize).checked_mul(sb.leb_size);
    if main_start.map_or(true, |start| data.len() <= start) {
        return Err(error(format!(
            "Truncated UBIFS image: the main area starts at LEB {}",
            sb.main_first
        )));
    }
    let mut nodes = Nodes::default();
    let scan_notes = scan_main_area(data, &sb, &mut nodes);
    let truncations: BTreeMap<u32, Truncations> = std::mem::take(&mut nodes.truncations)
        .into_iter()
        .map(|(inum, list)| (inum, Truncations::new(list)))
        .collect();
    let tree = regular_files(&live_dirents(&nodes), UBIFS_ROOT_INO);
    let last_scanned = present_lebs(data, &sb).saturating_sub(1);

    let mut c = Container::new(FileFormat::Ubifs, Layout::Ubifs.label(), "ubifs");
    c.consumed = data.len();
    c.notes.push(format!(
        "UBIFS format version {}; LEB size {}, minimum I/O unit {}; {} of at most {} LEBs; default compression {}",
        sb.fmt_version,
        size_text(sb.leb_size),
        size_text(sb.min_io_size as usize),
        sb.leb_cnt,
        sb.max_leb_cnt,
        compression_name(sb.default_compr)
    ));
    c.notes.push(format!(
        "{} nodes with matching CRC-32 in main-area LEBs {}-{last_scanned}; the newest copy of each node is used and the index is not walked",
        nodes.count, sb.main_first
    ));
    if nodes.count >= MAX_NODES {
        c.notes
            .push(format!("Node scan stopped at {MAX_NODES} nodes"));
    }
    c.notes.extend(scan_notes);
    if sb.flags & UBIFS_FLG_ENCRYPTION != 0 {
        c.notes
            .push("Encryption enabled; encrypted files are not extracted".into());
    }
    if sb.flags & UBIFS_FLG_AUTHENTICATION != 0 {
        c.notes
            .push("Authenticated filesystem; HMACs and signatures not verified".into());
    }
    c.notes.push(tree_note(&tree));
    if !nodes.data.is_empty() {
        c.notes
            .push(format!("Data nodes: {}", data_summary(&nodes)));
    }
    c.push_metadata("ubifs_leb_size", "LEB size (B)", sb.leb_size as u64);
    c.push_metadata(
        "ubifs_min_io_size",
        "Minimum I/O unit (B)",
        u64::from(sb.min_io_size),
    );
    c.push_metadata("ubifs_leb_count", "LEB count", u64::from(sb.leb_cnt));
    c.push_metadata(
        "ubifs_format_version",
        "Format version",
        u64::from(sb.fmt_version),
    );
    c.push_metadata(
        "ubifs_default_compression",
        "Default compression",
        compression_name(sb.default_compr),
    );
    c.push_metadata(
        "ubifs_file_count",
        "Regular files",
        tree.members.len() as u64,
    );
    push_members(&mut c, &tree.members, "UBIFS file", |inum| {
        file_data(&nodes, &truncations, inum)
    });
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superblock_for_tests() -> Superblock {
        Superblock {
            flags: 0,
            min_io_size: 8,
            leb_size: UBIFS_MIN_LEB_SZ,
            leb_cnt: 20,
            max_leb_cnt: 20,
            fanout: 8,
            fmt_version: 4,
            default_compr: 0,
            main_first: 10,
        }
    }

    #[test]
    fn newest_sequence_number_wins_and_ties_keep_the_first() {
        let mut map = BTreeMap::new();
        keep_newest(&mut map, 1, (5u64, "a"), |v| v.0);
        keep_newest(&mut map, 1, (3, "b"), |v| v.0);
        keep_newest(&mut map, 1, (5, "c"), |v| v.0);
        assert_eq!(map[&1].1, "a");
        keep_newest(&mut map, 1, (9, "d"), |v| v.0);
        assert_eq!(map[&1].1, "d");
    }

    #[test]
    fn padding_bytes_must_end_eight_byte_aligned() {
        let sb = superblock_for_tests();
        let mut aligned = vec![0xffu8; 64];
        aligned[..8].fill(UBIFS_PADDING_BYTE);
        assert_eq!(scan_leb(&aligned, 0, &sb, &mut Nodes::default()), None);
        let mut unaligned = aligned.clone();
        unaligned[5..8].fill(0);
        assert_eq!(
            scan_leb(&unaligned, 0, &sb, &mut Nodes::default()),
            Some(ScanStop {
                offset: 0,
                reason: "neither a node, padding nor erased flash"
            })
        );
    }

    #[test]
    fn truncations_remove_only_older_blocks_past_the_new_size() {
        let truncations = Truncations::new(vec![
            Truncation {
                sqnum: 20,
                new_size: 8192,
            },
            Truncation {
                sqnum: 10,
                new_size: 0,
            },
        ]);
        // Written before both truncations: gone from offset 0.
        assert!(truncations.removes(5, 0));
        // Written between them: only blocks from 8192 on are gone.
        assert!(!truncations.removes(15, 4096));
        assert!(truncations.removes(15, 8192));
        // Written after both: kept.
        assert!(!truncations.removes(25, 8192));
        assert!(!Truncations::default().removes(0, 0));
    }

    #[test]
    fn every_node_type_has_a_nonempty_length_range() {
        let sb = superblock_for_tests();
        for node_type in UBIFS_INO_NODE..=UBIFS_SIG_NODE {
            let lengths = length_range(node_type, &sb).expect("a known type");
            assert!(!lengths.is_empty(), "type {node_type}");
        }
        assert_eq!(length_range(UBIFS_SIG_NODE + 1, &sb), None);
    }
}
