//! Compressed files: the map header, full and compact logical cluster
//! (lcluster) indexes, extents and physical clusters (pclusters), as
//! `fs/erofs/zmap.c` decodes them, and the decoding of each extent as
//! `fs/erofs/decompressor.c` and `decompressor_deflate.c` do.
//!
//! A file is cut into extents of variable length; each starts in a HEAD
//! (or PLAIN, for uncompressed data) lcluster at `clusterofs` and is stored
//! in one pcluster: one lcluster of blocks, or with big pclusters the
//! count of blocks in the CBLKCNT entry that follows the head. With tail
//! packing the last extent's pcluster is stored inline after the indexes.
//! Extents are decoded in full and must decode to exactly their length,
//! as the kernel requires when it decodes a whole extent; extents that
//! only reference a prefix of their pcluster (deduplication) are not
//! decoded. LZ4 pclusters hold raw LZ4 blocks, LZMA ones `MicroLZMA`
//! streams and DEFLATE ones raw DEFLATE streams; the data ends at the end
//! of the pcluster and leading zero bytes are skipped (for LZ4 only with
//! `zero_padding`). With fragments, the tail extent or the whole file is a
//! range of the packed inode, which is decoded once
//! (`z_erofs_read_fragment`). Zstandard extents and legacy LZ4 images
//! without zero padding are not decoded.

use super::inode::{FileData, Inode, StoredRun};
use super::*;
use crate::formats::compressed::{self, Codec};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;

/// `struct z_erofs_map_header`, 8-byte aligned after the inode and its
/// inline xattrs.
const MAP_HEADER_SIZE: u64 = 8;
const MAP_HEADER_ALIGNMENT: u64 = 8;

/// Full indexes start 8 bytes after the map header
/// (`Z_EROFS_FULL_INDEX_ALIGN`) and take 8 bytes per lcluster
/// (`struct z_erofs_lcluster_index`).
const FULL_INDEX_GAP: u64 = 8;
const FULL_INDEX_SIZE: u64 = 8;

/// `h_advise` bits (`Z_EROFS_ADVISE_*`).
const Z_EROFS_ADVISE_COMPACTED_2B: u16 = 0x0001;
const Z_EROFS_ADVISE_BIG_PCLUSTER_1: u16 = 0x0002;
const Z_EROFS_ADVISE_BIG_PCLUSTER_2: u16 = 0x0004;
const Z_EROFS_ADVISE_INLINE_PCLUSTER: u16 = 0x0008;
const Z_EROFS_ADVISE_INTERLACED_PCLUSTER: u16 = 0x0010;
const Z_EROFS_ADVISE_FRAGMENT_PCLUSTER: u16 = 0x0020;

/// `h_clusterbits`: bits 0-2 are the lcluster size bits above the block
/// size; bit 7 (`Z_EROFS_FRAGMENT_INODE_BIT`) moves the whole file into
/// the packed inode.
const CLUSTER_BITS_MASK: u8 = 0x07;
const Z_EROFS_FRAGMENT_INODE_BIT: u8 = 7;

/// That bit as bit 63 of the 8-byte map header read as one little-endian
/// word, whose other bits are then the fragment offset.
const WHOLE_FILE_FRAGMENT: u64 = 1 << 63;

/// `h_algorithmtype`: HEAD1 algorithm in the low nibble, HEAD2 in the high.
const ALGORITHM_NIBBLE: u8 = 0x0f;

/// `di_advise` bits: the lcluster type and, for full-index heads, a
/// partial reference to the pcluster's decoded data.
const Z_EROFS_LI_LCLUSTER_TYPE_MASK: u16 = 0x0003;
const Z_EROFS_LI_PARTIAL_REF: u16 = 1 << 15;

/// Lcluster types (`Z_EROFS_LCLUSTER_TYPE_*`).
const Z_EROFS_LCLUSTER_TYPE_PLAIN: u32 = 0;
const Z_EROFS_LCLUSTER_TYPE_HEAD1: u32 = 1;
const Z_EROFS_LCLUSTER_TYPE_NONHEAD: u32 = 2;

/// `delta[0]` bit marking the first NONHEAD lcluster of a big pcluster,
/// whose low bits are the pcluster's block count (`Z_EROFS_LI_D0_CBLKCNT`).
const Z_EROFS_LI_D0_CBLKCNT: u32 = 1 << 11;

/// Compact indexes: the first lclusters fill 4-byte entries up to a
/// 32-byte boundary, then 2-byte entries in packs of 16 when
/// `COMPACTED_2B` is set, then 4-byte entries; each pack ends with a
/// 4-byte block address. 4-byte packs hold 2 lclusters, 2-byte packs 16.
const COMPACT_ALIGNMENT: u64 = 32;
const COMPACT_4B_SHIFT: u32 = 2;
const COMPACT_2B_SHIFT: u32 = 1;
const COMPACT_4B_PER_PACK: u64 = 2;
const COMPACT_2B_PER_PACK: u64 = 16;
const COMPACT_BLKADDR_SIZE: u64 = 4;

/// Largest lcluster sizes the compact entries can encode (`unpack_compacted_index`).
const COMPACT_4B_MAX_CLUSTER_BITS: u32 = 14;
const COMPACT_2B_MAX_CLUSTER_BITS: u32 = 12;

/// Transform name for files that are wholly a fragment of the packed
/// inode.
const FRAGMENT_TRANSFORM: &str = "EROFS fragment";

/// Transform name for files whose extents use both HEAD algorithms.
const MIXED_TRANSFORM: &str = "EROFS mixed compression";

/// Transform names, by the algorithm the file's extents use (HEAD1 when
/// none is compressed).
const TRANSFORMS: [&str; 4] = [
    "EROFS LZ4",
    "EROFS LZMA",
    "EROFS DEFLATE",
    "EROFS Zstandard",
];

/// Lcluster kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// HEAD of an uncompressed extent.
    Plain,
    /// HEAD of an extent compressed with the HEAD1 algorithm.
    Head1,
    /// Continues the extent of an earlier HEAD.
    NonHead,
    /// HEAD of an extent compressed with the HEAD2 algorithm.
    Head2,
}

impl Kind {
    fn from_bits(bits: u32) -> Self {
        match bits {
            Z_EROFS_LCLUSTER_TYPE_PLAIN => Self::Plain,
            Z_EROFS_LCLUSTER_TYPE_HEAD1 => Self::Head1,
            Z_EROFS_LCLUSTER_TYPE_NONHEAD => Self::NonHead,
            _ => Self::Head2,
        }
    }
}

/// The map header (`h_fragmentoff` or `h_idata_size` at 0-3, `h_advise`
/// 4, `h_algorithmtype` 6, `h_clusterbits` 7).
struct MapHeader {
    advise: u16,
    /// HEAD1 and HEAD2 algorithms.
    algorithms: [u8; 2],
    /// Lcluster size bits.
    cluster_bits: u32,
    /// Size of the tail-packed pcluster.
    idata_size: u16,
    /// The whole file lives in the packed inode.
    in_packed_inode: bool,
    /// Offset of the file's fragment in the packed inode: `h_fragmentoff`,
    /// or for a whole-file fragment the 64-bit header without its top bit.
    /// With full indexes the tail head's block address supplies bits
    /// 32-63.
    fragment_offset: u64,
}

impl MapHeader {
    fn has(&self, bit: u16) -> bool {
        self.advise & bit != 0
    }
}

/// One lcluster index entry, decoded.
#[derive(Debug, Clone, Copy)]
struct Lcluster {
    kind: Kind,
    /// HEAD: where the extent starts in the lcluster.
    clusterofs: u64,
    /// HEAD: the pcluster's block address.
    pblk: u64,
    /// NONHEAD with CBLKCNT: the big pcluster's block count.
    compressed_blocks: Option<u64>,
    /// HEAD of a full index: the extent references part of its pcluster.
    partial_ref: bool,
    /// File offset after this entry (full) or its pack (compact), where
    /// tail-packed data starts (`nextpackoff`).
    next_pack_offset: u64,
}

/// One compact entry: `lo` bits and the type above them.
struct Packed {
    lo: u32,
    kind: Kind,
}

/// Where an extent's pcluster is.
enum Pcluster {
    /// `size` bytes at file offset `offset`: whole blocks, or the
    /// tail-packed pcluster after the indexes.
    Stored { offset: u64, size: u64 },
    /// At this offset of the packed inode's data.
    Fragment { offset: u64 },
}

/// One extent: `len` decoded bytes from file position `la`.
struct Extent {
    la: u64,
    len: u64,
    kind: Kind,
    partial_ref: bool,
    pcluster: Pcluster,
}

/// A HEAD lcluster whose extent is being collected.
struct OpenHead {
    lcn: u64,
    la: u64,
    head: Lcluster,
    /// The lcluster after the head, which holds CBLKCNT for big pclusters.
    next: Option<Lcluster>,
}

/// `z_erofs_fill_inode_lazy`: the map header and its consistency checks.
fn map_header(fs: &Filesystem<'_>, inode: &Inode) -> Result<MapHeader> {
    let at = align_up(inode.body_offset(), MAP_HEADER_ALIGNMENT)
        .ok_or_else(|| error(format!("Invalid map header of nid {}", inode.nid)))?;
    let bytes = fs.bytes(at, MAP_HEADER_SIZE)?;
    fs.charge(MAP_HEADER_SIZE)?;
    let cluster_byte = bytes[7];
    let advise = le_u16(bytes, 4)?;
    let header = MapHeader {
        advise,
        algorithms: [bytes[6] & ALGORITHM_NIBBLE, bytes[6] >> 4],
        cluster_bits: u32::from(fs.sb.block_size_bits)
            + u32::from(cluster_byte & CLUSTER_BITS_MASK),
        idata_size: le_u16(bytes, 2)?,
        in_packed_inode: cluster_byte >> Z_EROFS_FRAGMENT_INODE_BIT != 0,
        fragment_offset: u64::from(le_u32(bytes, 0)?),
    };
    if header.in_packed_inode {
        let whole = le_u64(bytes, 0)? & !WHOLE_FILE_FRAGMENT;
        return Ok(MapHeader {
            fragment_offset: whole,
            ..header
        });
    }
    for (head, &algorithm) in header.algorithms.iter().enumerate() {
        if usize::from(algorithm) >= ALGORITHM_NAMES.len() {
            return Err(error(format!(
                "Unsupported HEAD{} algorithm {algorithm} of nid {}",
                head + 1,
                inode.nid
            )));
        }
    }
    // erofs-utils always writes one-block lclusters; larger ones are not
    // exercised by any image this reader was checked against.
    if cluster_byte & CLUSTER_BITS_MASK != 0 {
        return Err(error(format!(
            "Unsupported lcluster size of nid {}: h_clusterbits {}",
            inode.nid,
            cluster_byte & CLUSTER_BITS_MASK
        )));
    }
    let big =
        header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_1) || header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_2);
    if big && !fs.sb.has_incompat(EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER) {
        return Err(error(format!(
            "Invalid map header of nid {}: big pclusters without the superblock feature",
            inode.nid
        )));
    }
    if inode.layout == super::inode::DataLayout::CompressedCompact
        && header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_1) != header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_2)
    {
        return Err(error(format!(
            "Invalid map header of nid {}: compact indexes need both or neither big pcluster flag",
            inode.nid
        )));
    }
    Ok(header)
}

/// `z_erofs_load_full_lcluster`: `di_advise` (0), `di_clusterofs` (2),
/// then the block address or `delta[0]` and `delta[1]` (4).
fn load_full(fs: &Filesystem<'_>, inode: &Inode, header: &MapHeader, lcn: u64) -> Result<Lcluster> {
    let base = align_up(inode.body_offset(), MAP_HEADER_ALIGNMENT)
        .ok_or_else(|| error(format!("Invalid indexes of nid {}", inode.nid)))?;
    let at = lcn
        .checked_mul(FULL_INDEX_SIZE)
        .and_then(|offset| offset.checked_add(base + MAP_HEADER_SIZE + FULL_INDEX_GAP))
        .ok_or_else(|| error(format!("Invalid lcluster {lcn} of nid {}", inode.nid)))?;
    let entry = fs.bytes(at, FULL_INDEX_SIZE)?;
    fs.charge(FULL_INDEX_SIZE)?;
    let advise = le_u16(entry, 0)?;
    let kind = Kind::from_bits(u32::from(advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK));
    let mut lcluster = Lcluster {
        kind,
        clusterofs: 1 << header.cluster_bits,
        pblk: 0,
        compressed_blocks: None,
        partial_ref: false,
        next_pack_offset: at + FULL_INDEX_SIZE,
    };
    if kind == Kind::NonHead {
        let delta0 = u32::from(le_u16(entry, 4)?);
        if delta0 & Z_EROFS_LI_D0_CBLKCNT != 0 {
            lcluster.compressed_blocks = Some(cblkcnt(header, delta0, inode, lcn)?);
        }
        return Ok(lcluster);
    }
    lcluster.partial_ref = advise & Z_EROFS_LI_PARTIAL_REF != 0;
    lcluster.clusterofs = u64::from(le_u16(entry, 2)?);
    if lcluster.clusterofs >= 1 << header.cluster_bits {
        return Err(error(format!(
            "Invalid lcluster {lcn} of nid {}: clusterofs {} exceeds the lcluster",
            inode.nid, lcluster.clusterofs
        )));
    }
    lcluster.pblk = u64::from(le_u32(entry, 4)?);
    Ok(lcluster)
}

/// The block count of a CBLKCNT entry, which only big pclusters have.
fn cblkcnt(header: &MapHeader, lo: u32, inode: &Inode, lcn: u64) -> Result<u64> {
    if !header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_1) && !header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_2) {
        return Err(error(format!(
            "Invalid lcluster {lcn} of nid {}: CBLKCNT without big pclusters",
            inode.nid
        )));
    }
    Ok(u64::from(lo & !Z_EROFS_LI_D0_CBLKCNT))
}

/// Entry `index` of a compact pack (`decode_compactedbits`).
fn packed(pack: &[u8], lobits: u32, encodebits: u32, index: u32) -> Result<Packed> {
    let bitpos = encodebits * index;
    let word = le_u32(pack, (bitpos / 8) as usize)? >> (bitpos % 8);
    Ok(Packed {
        lo: word & ((1 << lobits) - 1),
        kind: Kind::from_bits((word >> lobits) & u32::from(Z_EROFS_LI_LCLUSTER_TYPE_MASK)),
    })
}

/// `z_erofs_load_compact_lcluster` and `unpack_compacted_index`.
fn load_compact(
    fs: &Filesystem<'_>,
    inode: &Inode,
    header: &MapHeader,
    lcn: u64,
) -> Result<Lcluster> {
    let ebase = align_up(inode.body_offset(), MAP_HEADER_ALIGNMENT)
        .ok_or_else(|| error(format!("Invalid indexes of nid {}", inode.nid)))?
        + MAP_HEADER_SIZE;
    let total = inode::shift_up(inode.size, u32::from(fs.sb.block_size_bits));
    if lcn >= total {
        return Err(error(format!(
            "Invalid lcluster {lcn} of nid {}: beyond its {total} lclusters",
            inode.nid
        )));
    }
    // 4-byte entries up to the next 32-byte boundary (none when aligned).
    let mut initial_4b = (COMPACT_ALIGNMENT - ebase % COMPACT_ALIGNMENT) >> COMPACT_4B_SHIFT;
    if initial_4b == COMPACT_ALIGNMENT >> COMPACT_4B_SHIFT {
        initial_4b = 0;
    }
    let compacted_2b = if header.has(Z_EROFS_ADVISE_COMPACTED_2B) && initial_4b < total {
        (total - initial_4b) / COMPACT_2B_PER_PACK * COMPACT_2B_PER_PACK
    } else {
        0
    };
    let mut pos = ebase;
    let mut index = lcn;
    let shift = if index < initial_4b {
        COMPACT_4B_SHIFT
    } else {
        pos += initial_4b << COMPACT_4B_SHIFT;
        index -= initial_4b;
        if index < compacted_2b {
            COMPACT_2B_SHIFT
        } else {
            pos += compacted_2b << COMPACT_2B_SHIFT;
            index -= compacted_2b;
            COMPACT_4B_SHIFT
        }
    };
    pos += index << shift;
    unpack_compact(fs, inode, header, shift, pos)
}

/// `unpack_compacted_index` for the entry at file offset `pos`.
fn unpack_compact(
    fs: &Filesystem<'_>,
    inode: &Inode,
    header: &MapHeader,
    shift: u32,
    pos: u64,
) -> Result<Lcluster> {
    let cluster_bits = header.cluster_bits;
    let per_pack = if shift == COMPACT_4B_SHIFT && cluster_bits <= COMPACT_4B_MAX_CLUSTER_BITS {
        COMPACT_4B_PER_PACK
    } else if shift == COMPACT_2B_SHIFT && cluster_bits <= COMPACT_2B_MAX_CLUSTER_BITS {
        COMPACT_2B_PER_PACK
    } else {
        return Err(error(format!(
            "Unsupported compact indexes of nid {} for 2^{cluster_bits} B lclusters",
            inode.nid
        )));
    };
    let pack_size = per_pack << shift;
    let pack_start = pos / pack_size * pack_size;
    let pack = fs.bytes(pack_start, pack_size)?;
    fs.charge(1 << shift)?;
    let big = header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_1);
    let lobits = cluster_bits.max(Z_EROFS_LI_D0_CBLKCNT.trailing_zeros() + 1);
    let encodebits =
        u32::try_from((pack_size - COMPACT_BLKADDR_SIZE) * 8 / per_pack).expect("a small width");
    let i = u32::try_from((pos - pack_start) >> shift).expect("inside the pack");
    let entry = packed(pack, lobits, encodebits, i)?;
    let mut lcluster = Lcluster {
        kind: entry.kind,
        clusterofs: 1 << cluster_bits,
        pblk: 0,
        compressed_blocks: None,
        partial_ref: false,
        next_pack_offset: pack_start + pack_size,
    };
    if entry.kind == Kind::NonHead {
        if entry.lo & Z_EROFS_LI_D0_CBLKCNT != 0 {
            if !big {
                return Err(error(format!(
                    "Invalid compact index of nid {}: CBLKCNT without big pclusters",
                    inode.nid
                )));
            }
            lcluster.compressed_blocks = Some(u64::from(entry.lo & !Z_EROFS_LI_D0_CBLKCNT));
        }
        return Ok(lcluster);
    }
    lcluster.clusterofs = u64::from(entry.lo);
    let preceding = preceding_blocks(pack, lobits, encodebits, i, big, inode)?;
    let base_at = usize::try_from(pack_size - COMPACT_BLKADDR_SIZE).expect("a small offset");
    let base = u64::from(le_u32(pack, base_at)?);
    lcluster.pblk = base + preceding;
    Ok(lcluster)
}

/// The blocks of the pclusters before entry `i` in its pack, which the
/// pack's base address does not include (the `nblk` loops of
/// `unpack_compacted_index`). Without big pclusters each head is one
/// block and the count starts at 1.
fn preceding_blocks(
    pack: &[u8],
    lobits: u32,
    encodebits: u32,
    i: u32,
    big: bool,
    inode: &Inode,
) -> Result<u64> {
    let mut i = i64::from(i);
    if !big {
        let mut blocks = 1u64;
        while i > 0 {
            i -= 1;
            let entry = packed(pack, lobits, encodebits, entry_index(i))?;
            if entry.kind == Kind::NonHead {
                i -= i64::from(entry.lo);
            }
            if i >= 0 {
                blocks += 1;
            }
        }
        return Ok(blocks);
    }
    let mut blocks = 0u64;
    while i > 0 {
        i -= 1;
        let entry = packed(pack, lobits, encodebits, entry_index(i))?;
        if entry.kind != Kind::NonHead {
            blocks += 1;
            continue;
        }
        if entry.lo & Z_EROFS_LI_D0_CBLKCNT != 0 {
            i -= 1;
            blocks += u64::from(entry.lo & !Z_EROFS_LI_D0_CBLKCNT);
            continue;
        }
        // A big pcluster's NONHEAD entries after CBLKCNT have delta0 >= 2.
        if entry.lo <= 1 {
            return Err(error(format!(
                "Invalid compact index of nid {}: delta0 {} in a big pcluster",
                inode.nid, entry.lo
            )));
        }
        i -= i64::from(entry.lo) - 2;
    }
    Ok(blocks)
}

/// A pack entry index that the loops above keep non-negative.
fn entry_index(i: i64) -> u32 {
    u32::try_from(i).expect("loop index is non-negative")
}

/// `z_erofs_load_lcluster_from_disk`.
fn load(fs: &Filesystem<'_>, inode: &Inode, header: &MapHeader, lcn: u64) -> Result<Lcluster> {
    match inode.layout {
        super::inode::DataLayout::CompressedFull => load_full(fs, inode, header, lcn),
        _ => load_compact(fs, inode, header, lcn),
    }
}

/// The pcluster of the extent at `open` (`z_erofs_get_extent_compressedlen`):
/// one lcluster, or with a big pcluster the CBLKCNT block count of the
/// next lcluster (one lcluster when the next lcluster is another head).
fn pcluster(
    fs: &Filesystem<'_>,
    inode: &Inode,
    header: &MapHeader,
    open: &OpenHead,
) -> Result<Pcluster> {
    let cluster_size = 1u64 << header.cluster_bits;
    let big = match open.head.kind {
        Kind::Head1 => header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_1),
        Kind::Head2 => header.has(Z_EROFS_ADVISE_BIG_PCLUSTER_2),
        Kind::Plain | Kind::NonHead => false,
    };
    let offset = fs.block_offset(open.head.pblk);
    if !big {
        return Ok(Pcluster::Stored {
            offset,
            size: cluster_size,
        });
    }
    let blocks = match open.next {
        Some(next) if next.kind != Kind::NonHead => cluster_size >> fs.sb.block_size_bits,
        Some(Lcluster {
            compressed_blocks: Some(blocks),
            ..
        }) if blocks > 0 => blocks,
        _ => {
            return Err(error(format!(
                "Invalid big pcluster at lcluster {} of nid {}: no CBLKCNT entry",
                open.lcn, inode.nid
            )))
        }
    };
    Ok(Pcluster::Stored {
        offset,
        size: blocks << fs.sb.block_size_bits,
    })
}

/// The extents that cover the first `len` bytes, from a scan of the
/// lcluster indexes in order. The tail extent is the one that holds the
/// file's last byte (`z_tailextent_headlcn`); a head at or after the end of
/// the file in the last lcluster only ends it. Its tail-packed pcluster
/// starts after the index entry or pack of the last lcluster
/// (`z_idataoff`).
fn extents(
    fs: &Filesystem<'_>,
    inode: &Inode,
    header: &MapHeader,
    len: u64,
) -> Result<Vec<Extent>> {
    let total = inode::shift_up(inode.size, header.cluster_bits);
    let mut out = Vec::new();
    let mut open: Option<OpenHead> = None;
    let mut last_next_pack = 0;
    for lcn in 0..total {
        let lcluster = load(fs, inode, header, lcn)?;
        last_next_pack = lcluster.next_pack_offset;
        if lcluster.kind == Kind::NonHead {
            match open.as_mut() {
                Some(current) if current.next.is_none() => current.next = Some(lcluster),
                Some(_) => {}
                None => {
                    return Err(error(format!(
                        "Invalid lcluster 0 of nid {}: NONHEAD without a head",
                        inode.nid
                    )))
                }
            }
            continue;
        }
        let la = (lcn << header.cluster_bits) | lcluster.clusterofs;
        if lcn == 0 && la != 0 {
            return Err(error(format!(
                "Invalid lcluster 0 of nid {}: the first extent starts at {la}",
                inode.nid
            )));
        }
        // Only the last lcluster can hold a head at or after the end.
        let at_end = la >= inode.size;
        if let Some(mut current) = open.take() {
            if current.next.is_none() {
                current.next = Some(lcluster);
            }
            let tail = at_end.then_some(lcluster.next_pack_offset);
            out.push(close(
                fs,
                inode,
                header,
                &current,
                la.min(inode.size),
                tail,
            )?);
        }
        if at_end || la >= len {
            return Ok(out);
        }
        open = Some(OpenHead {
            lcn,
            la,
            head: lcluster,
            next: None,
        });
    }
    if let Some(current) = open {
        out.push(close(
            fs,
            inode,
            header,
            &current,
            inode.size,
            Some(last_next_pack),
        )?);
    }
    Ok(out)
}

/// The extent of `open`, ending at `end`. `tail` is the file offset after
/// the last lcluster's indexes when `open` is the file's last extent.
fn close(
    fs: &Filesystem<'_>,
    inode: &Inode,
    header: &MapHeader,
    open: &OpenHead,
    end: u64,
    tail: Option<u64>,
) -> Result<Extent> {
    let pcluster = match tail {
        Some(offset) if header.has(Z_EROFS_ADVISE_INLINE_PCLUSTER) => Pcluster::Stored {
            offset,
            size: u64::from(header.idata_size),
        },
        Some(_) if header.has(Z_EROFS_ADVISE_FRAGMENT_PCLUSTER) => {
            let high = if inode.layout == super::inode::DataLayout::CompressedFull {
                open.head.pblk << 32
            } else {
                0
            };
            Pcluster::Fragment {
                offset: header.fragment_offset | high,
            }
        }
        _ => pcluster(fs, inode, header, open)?,
    };
    Ok(Extent {
        la: open.la,
        len: end - open.la,
        kind: open.head.kind,
        partial_ref: open.head.partial_ref,
        pcluster,
    })
}

/// The codec for an algorithm, if this reader decodes it.
fn codec(algorithm: u8) -> Option<Codec> {
    match algorithm {
        Z_EROFS_COMPRESSION_LZ4 => Some(Codec::Lz4Block),
        Z_EROFS_COMPRESSION_LZMA => Some(Codec::MicroLzma),
        Z_EROFS_COMPRESSION_DEFLATE => Some(Codec::Deflate),
        // Zstandard extents are not decoded: no image was available to
        // check the framing against.
        _ => None,
    }
}

/// `z_erofs_fixup_insize`: the compressed data after the leading zero
/// bytes of the pcluster's first block.
fn strip_zero_padding<'a>(
    input: &'a [u8],
    offset: u64,
    block_size: u64,
    inode: &Inode,
) -> Result<&'a [u8]> {
    let first_block = usize::try_from(block_size - offset % block_size)
        .expect("at most a block")
        .min(input.len());
    let Some(start) = input[..first_block].iter().position(|&b| b != 0) else {
        return Err(error(format!(
            "Invalid pcluster at 0x{offset:X} of nid {}: its first block is all padding",
            inode.nid
        )));
    };
    Ok(&input[start..])
}

/// `z_erofs_transform_plain`: an uncompressed extent copied in order, or
/// rotated by its offset in the block when the pclusters are interlaced.
fn plain(
    input: &[u8],
    extent: &Extent,
    interlaced: bool,
    block_size: u64,
    inode: &Inode,
) -> Result<Vec<u8>> {
    let len = usize::try_from(extent.len).expect("checked against the pcluster");
    if !interlaced {
        return Ok(input[..len].to_vec());
    }
    let rotation = usize::try_from(block_size - extent.la % block_size).expect("at most a block");
    let Some(rotated_at) = input.len().checked_sub(rotation) else {
        return Err(error(format!(
            "Unsupported interlaced pcluster of nid {}: {} B for a {rotation} B rotation",
            inode.nid,
            input.len()
        )));
    };
    let first = rotation.min(len);
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&input[rotated_at..rotated_at + first]);
    out.extend_from_slice(&input[..len - first]);
    Ok(out)
}

/// The algorithm of a HEAD1 or HEAD2 extent; plain extents have none.
fn extent_algorithm(header: &MapHeader, kind: Kind) -> Option<u8> {
    match kind {
        Kind::Head1 => Some(header.algorithms[0]),
        Kind::Head2 => Some(header.algorithms[1]),
        Kind::Plain | Kind::NonHead => None,
    }
}

/// Decode one extent into exactly `extent.len` bytes.
fn decode(
    fs: &Filesystem<'_>,
    inode: &Inode,
    header: &MapHeader,
    extent: &Extent,
) -> Result<Vec<u8>> {
    let (offset, size) = match extent.pcluster {
        Pcluster::Stored { offset, size } => (offset, size),
        Pcluster::Fragment { offset } => {
            return Ok(fragment(fs, inode, offset, extent.len)?.to_vec());
        }
    };
    let block_size = fs.sb.block_size as u64;
    if size == 0 {
        return Err(error(format!(
            "Invalid empty pcluster of nid {} at 0x{offset:X}",
            inode.nid
        )));
    }
    let input = fs.bytes(offset, size)?;
    if extent.kind == Kind::Plain {
        if extent.len > size {
            return Err(error(format!(
                "Invalid plain extent of nid {}: {} B in a {size} B pcluster",
                inode.nid, extent.len
            )));
        }
        let interlaced = header.has(Z_EROFS_ADVISE_INTERLACED_PCLUSTER);
        return plain(input, extent, interlaced, block_size, inode);
    }
    let algorithm = extent_algorithm(header, extent.kind).expect("a compressed head");
    let name = ALGORITHM_NAMES[usize::from(algorithm)];
    if fs.sb.available_algorithms & (1 << algorithm) == 0 {
        return Err(error(format!(
            "Invalid extent of nid {}: {name} is not an available algorithm",
            inode.nid
        )));
    }
    let Some(codec) = codec(algorithm) else {
        return Err(error(format!(
            "Unsupported {name} extent of nid {}: not decoded",
            inode.nid
        )));
    };
    if extent.partial_ref {
        return Err(error(format!(
            "Unsupported extent of nid {}: a partial reference to a shared pcluster is not decoded",
            inode.nid
        )));
    }
    let zero_padding = fs.sb.has_incompat(EROFS_FEATURE_INCOMPAT_ZERO_PADDING);
    if algorithm == Z_EROFS_COMPRESSION_LZ4 && !zero_padding {
        return Err(error(format!(
            "Unsupported LZ4 extent of nid {}: images without zero padding are decoded partially by the kernel, which this reader does not do",
            inode.nid
        )));
    }
    let stream = strip_zero_padding(input, offset, block_size, inode)?;
    let limit = usize::try_from(extent.len).unwrap_or(usize::MAX);
    let decoded = compressed::decode_limited(codec, stream, limit).map_err(|e| {
        error(format!(
            "Invalid {name} extent at 0x{:X} of nid {}: {e}",
            extent.la, inode.nid
        ))
    })?;
    if decoded.data.len() as u64 != extent.len {
        return Err(error(format!(
            "Invalid {name} extent at 0x{:X} of nid {}: {} B decoded, {} B expected",
            extent.la,
            inode.nid,
            decoded.data.len(),
            extent.len
        )));
    }
    Ok(decoded.data)
}

/// A stored pcluster and the file position where its decoded data starts.
#[derive(Debug, Clone, Copy)]
struct PclusterRun {
    la: u64,
    run: StoredRun,
}

/// A decoded file prefix and the pclusters it came from.
struct DecodedFile {
    bytes: Vec<u8>,
    /// Stored pclusters in file order.
    runs: Vec<PclusterRun>,
    transform: &'static str,
}

/// The packed inode's data, decoded once: the fragments of other files.
pub(super) struct PackedData {
    bytes: Vec<u8>,
    /// Where the packed inode's data is stored, reported as the stored
    /// location of fragments.
    runs: Vec<PclusterRun>,
}

impl PackedData {
    /// The stored pcluster that holds packed-inode position `offset`.
    fn run_at(&self, offset: u64) -> Option<StoredRun> {
        self.runs
            .iter()
            .rev()
            .find(|run| run.la <= offset)
            .map(|run| run.run)
    }
}

/// Read the packed inode (`packed_nid`), which may not itself use
/// fragments.
fn read_packed(fs: &Filesystem<'_>) -> std::result::Result<PackedData, String> {
    if !fs.sb.has_incompat(EROFS_FEATURE_INCOMPAT_FRAGMENTS) || fs.sb.packed_nid == 0 {
        return Err("the image has no packed inode".to_string());
    }
    let inode = fs.inode(fs.sb.packed_nid).map_err(message)?;
    if !inode.is_regular() || inode.size > MAX_PAYLOAD as u64 {
        return Err(format!(
            "the packed inode (nid {}, {} B) is not a regular file of at most {}",
            inode.nid,
            inode.size,
            size_text(MAX_PAYLOAD as u64)
        ));
    }
    fs.reading_packed.set(true);
    let data = read_packed_inode(fs, &inode).map_err(message);
    fs.reading_packed.set(false);
    data
}

/// The whole packed inode: decoded, or read as stored when it is not
/// compressed.
fn read_packed_inode(fs: &Filesystem<'_>, inode: &Inode) -> Result<PackedData> {
    if inode.layout.is_compressed() {
        let header = map_header(fs, inode)?;
        if header.in_packed_inode {
            return Err(error(format!(
                "Invalid packed inode nid {}: it is itself a fragment",
                inode.nid
            )));
        }
        let file = decode_file(fs, inode, &header, inode.size)?;
        return Ok(PackedData {
            bytes: file.bytes,
            runs: file.runs,
        });
    }
    let data = fs.read(inode, inode.size)?;
    Ok(PackedData {
        runs: data
            .first_run
            .map(|run| PclusterRun { la: 0, run })
            .into_iter()
            .collect(),
        bytes: data.bytes.into_owned(),
    })
}

/// The text of an EROFS error without the family prefix.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::ErofsParseError { message } => message,
        other => other.to_string(),
    }
}

/// The packed inode's data, decoded on first use.
fn packed_data<'f>(fs: &'f Filesystem<'_>, inode: &Inode) -> Result<&'f PackedData> {
    if fs.reading_packed.get() {
        return Err(error(format!(
            "Invalid packed inode: nid {} refers to fragments while the packed inode is read",
            inode.nid
        )));
    }
    fs.packed
        .get_or_init(|| read_packed(fs))
        .as_ref()
        .map_err(|reason| {
            error(format!(
                "Unsupported fragment of nid {}: {reason}",
                inode.nid
            ))
        })
}

/// `len` bytes at `offset` of the packed inode's data.
fn fragment<'f>(fs: &'f Filesystem<'_>, inode: &Inode, offset: u64, len: u64) -> Result<&'f [u8]> {
    let data = &packed_data(fs, inode)?.bytes;
    let range = usize::try_from(offset)
        .ok()
        .zip(usize::try_from(len).ok())
        .and_then(|(start, len)| Some(start..start.checked_add(len)?));
    range.and_then(|range| data.get(range)).ok_or_else(|| {
        error(format!(
            "Invalid fragment of nid {}: 0x{offset:X} + {len} B beyond the {} B packed inode",
            inode.nid,
            data.len()
        ))
    })
}

/// The stored pcluster of `extent`: its own blocks or inline data, or the
/// packed-inode pcluster that holds its fragment.
fn extent_run(fs: &Filesystem<'_>, inode: &Inode, extent: &Extent) -> Result<Option<StoredRun>> {
    match extent.pcluster {
        Pcluster::Stored { offset, size } => Ok(Some(StoredRun {
            offset: usize::try_from(offset).expect("the pcluster lies in the image"),
            size: usize::try_from(size).expect("the pcluster lies in the image"),
        })),
        Pcluster::Fragment { offset } => Ok(packed_data(fs, inode)?.run_at(offset)),
    }
}

/// Decode the extents that cover the first `len` bytes.
fn decode_file(
    fs: &Filesystem<'_>,
    inode: &Inode,
    header: &MapHeader,
    len: u64,
) -> Result<DecodedFile> {
    let extents = extents(fs, inode, header, len)?;
    let mut bytes = Vec::new();
    let mut runs = Vec::with_capacity(extents.len());
    // Bit n set: an extent compressed with algorithm n was decoded.
    let mut algorithms_used = 0u8;
    for extent in &extents {
        fs.charge_decoded(extent.len)?;
        bytes.extend_from_slice(&decode(fs, inode, header, extent)?);
        if let Some(algorithm) = extent_algorithm(header, extent.kind) {
            algorithms_used |= 1 << algorithm;
        }
        if let Some(run) = extent_run(fs, inode, extent)? {
            runs.push(PclusterRun { la: extent.la, run });
        }
    }
    bytes.truncate(usize::try_from(len).unwrap_or(usize::MAX));
    if (bytes.len() as u64) < len {
        return Err(error(format!(
            "Invalid compressed file of nid {}: extents end at {} B of {len} B",
            inode.nid,
            bytes.len()
        )));
    }
    let transform = match algorithms_used.count_ones() {
        0 => TRANSFORMS[usize::from(header.algorithms[0])],
        1 => TRANSFORMS[algorithms_used.trailing_zeros() as usize],
        _ => MIXED_TRANSFORM,
    };
    Ok(DecodedFile {
        bytes,
        runs,
        transform,
    })
}

/// The first `len` bytes of a compressed file, decoded.
pub(super) fn read<'a>(fs: &Filesystem<'a>, inode: &Inode, len: u64) -> Result<FileData<'a>> {
    let header = map_header(fs, inode)?;
    if header.in_packed_inode {
        let bytes = fragment(fs, inode, header.fragment_offset, len)?.to_vec();
        return Ok(FileData {
            bytes: Cow::Owned(bytes),
            first_run: packed_data(fs, inode)?.run_at(header.fragment_offset),
            transform: FRAGMENT_TRANSFORM,
        });
    }
    let file = decode_file(fs, inode, &header, len)?;
    Ok(FileData {
        bytes: Cow::Owned(file.bytes),
        first_run: file.runs.first().map(|run| run.run),
        transform: file.transform,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_entries_split_lo_bits_and_type() {
        // A 4-byte pack (two 16-bit entries, then a block address): entry
        // 0 is a HEAD1 at clusterofs 0x123, entry 1 a NONHEAD with delta 1.
        let mut pack = [0u8; 8];
        let entry0: u16 = 0x123 | (1 << 12);
        let entry1: u16 = 1 | (2 << 12);
        pack[..2].copy_from_slice(&entry0.to_le_bytes());
        pack[2..4].copy_from_slice(&entry1.to_le_bytes());
        let first = packed(&pack, 12, 16, 0).unwrap();
        assert_eq!((first.lo, first.kind), (0x123, Kind::Head1));
        let second = packed(&pack, 12, 16, 1).unwrap();
        assert_eq!((second.lo, second.kind), (1, Kind::NonHead));
    }

    #[test]
    fn interlaced_plain_extents_rotate_by_their_block_offset() {
        let inode = Inode {
            nid: 0,
            offset: 0,
            record_size: 32,
            xattr_size: 0,
            layout: super::super::inode::DataLayout::CompressedCompact,
            mode: 0o100_644,
            size: 8,
            union: 0,
        };
        let extent = Extent {
            la: 6,
            len: 4,
            kind: Kind::Plain,
            partial_ref: false,
            pcluster: Pcluster::Fragment { offset: 0 },
        };
        // Block of 8: the extent's first 2 bytes are the block's last 2.
        let input = *b"cdefghab";
        assert_eq!(plain(&input, &extent, true, 8, &inode).unwrap(), b"abcd");
        assert_eq!(plain(&input, &extent, false, 8, &inode).unwrap(), b"cdef");
    }
}
