//! JFFS2 images: a sequence of nodes with the 16-bit magic `0x1985`, in the
//! image's byte order, 4-byte aligned, with erased flash (`0xFF`) between
//! them (Linux v6.11 `include/uapi/linux/jffs2.h`, `fs/jffs2/scan.c`,
//! `readinode.c`, `nodelist.c`, `compr_zlib.c`; `OpenWrt` v24.10.0
//! `530-jffs2_make_lzma_available.patch` for LZMA).
//!
//! There is no superblock and the erase block size is not recorded. Every
//! CRC is `crc32(0, ...)` without final inversion. The header CRC is
//! computed with the `JFFS2_NODE_ACCURATE` bit set, because obsoleting a
//! node clears that bit in place. Because the magic is only 16 bits, an
//! image is recognized only when every node's header, node, name and data
//! CRCs match and only erased or zeroed (dirty) flash lies between nodes.

use super::*;

/// Node magic (`JFFS2_MAGIC_BITMASK`).
const JFFS2_MAGIC_BITMASK: u16 = 0x1985;

/// Set in every valid node type; cleared to obsolete a node
/// (`JFFS2_NODE_ACCURATE`).
const JFFS2_NODE_ACCURATE: u16 = 0x2000;

/// What a reader must do with an unknown node type (`JFFS2_COMPAT_MASK`,
/// `JFFS2_FEATURE_INCOMPAT`).
const JFFS2_COMPAT_MASK: u16 = 0xC000;
const JFFS2_FEATURE_INCOMPAT: u16 = 0xC000;

/// Node types (`JFFS2_NODETYPE_*`).
const JFFS2_NODETYPE_DIRENT: u16 = 0xE001;
const JFFS2_NODETYPE_INODE: u16 = 0xE002;
const JFFS2_NODETYPE_CLEANMARKER: u16 = 0x2003;
const JFFS2_NODETYPE_PADDING: u16 = 0x2004;
const JFFS2_NODETYPE_SUMMARY: u16 = 0x2006;
const JFFS2_NODETYPE_XATTR: u16 = 0xE008;
const JFFS2_NODETYPE_XREF: u16 = 0xE009;

/// Nodes are 4-byte aligned (`PAD()`), and the scan reads 4-byte words.
const WORD_SIZE: usize = 4;

/// Erased and zeroed (dirty) flash words.
const ERASED_WORD: [u8; WORD_SIZE] = [0xff; WORD_SIZE];
const DIRTY_WORD: [u8; WORD_SIZE] = [0; WORD_SIZE];

/// Common node header (`struct jffs2_unknown_node`); its CRC covers the
/// first 8 bytes.
const NODE_HEADER_SIZE: usize = 12;
const NODE_HEADER_CRC_SIZE: usize = 8;

/// `struct jffs2_raw_inode` and the bytes its node CRC covers
/// (`sizeof(*ri) - 8`).
const INODE_NODE_SIZE: usize = 68;
const INODE_NODE_CRC_SIZE: usize = 60;

/// `struct jffs2_raw_dirent` and the bytes its node CRC covers.
const DIRENT_NODE_SIZE: usize = 40;
const DIRENT_NODE_CRC_SIZE: usize = 32;

/// Compression types (`JFFS2_COMPR_*`; LZMA from the `OpenWrt` patch).
const JFFS2_COMPR_NONE: u8 = 0x00;
const JFFS2_COMPR_ZERO: u8 = 0x01;
const JFFS2_COMPR_RTIME: u8 = 0x02;
const JFFS2_COMPR_RUBINMIPS: u8 = 0x03;
const JFFS2_COMPR_DYNRUBIN: u8 = 0x05;
const JFFS2_COMPR_ZLIB: u8 = 0x06;
const JFFS2_COMPR_LZO: u8 = 0x07;
const JFFS2_COMPR_LZMA: u8 = 0x08;

/// The root directory inode (`jffs2_iget(sb, 1)`).
const ROOT_INO: u32 = 1;

/// Directory entry types (`DT_REG`, `DT_DIR`: `S_IFMT >> 12`).
const DT_REG: u8 = 8;
const DT_DIR: u8 = 4;

/// Largest decoded size accepted for a compressed node (own bound: the
/// largest Linux page size; `mkfs.jffs2` writes one page per node).
const MAX_NODE_DATA: usize = 64 << 10;

/// zlib header fields `compr_zlib.c` tests (`Z_DEFLATED`, `PRESET_DICT`).
const Z_DEFLATED: u8 = 8;
const PRESET_DICT: u8 = 0x20;

/// The `OpenWrt` encoder's LZMA properties: `lc = lp = pb = 0` (property
/// byte 0) and an 8 KiB dictionary (`LZMA_BEST_DICT(0x2000)`).
const LZMA_PROPERTIES: u8 = 0;
const LZMA_DICT_SIZE: u32 = 0x2000;

/// An LZMA-alone header: properties (1), dictionary size (4), decoded size
/// (8).
const LZMA_ALONE_HEADER_SIZE: usize = 13;

fn u16_at(data: &[u8], at: usize, le: bool) -> Result<u16> {
    let bytes = array(data, at)?;
    Ok(if le {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn u32_at(data: &[u8], at: usize, le: bool) -> Result<u32> {
    let bytes = array(data, at)?;
    Ok(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

/// The node byte order from the first word that is neither erased nor
/// zero: `true` for little-endian.
fn byte_order(data: &[u8]) -> Option<bool> {
    let first = data
        .chunks_exact(WORD_SIZE)
        .find(|word| *word != ERASED_WORD && *word != DIRTY_WORD)?;
    match first[..2] {
        [0x85, 0x19] => Some(true),
        [0x19, 0x85] => Some(false),
        _ => None,
    }
}

/// An inode node: one run of file data and the file size after it.
#[derive(Debug)]
struct InodeNode<'a> {
    ino: u32,
    version: u32,
    /// File size after this node, in bytes.
    isize: u32,
    /// File offset of the data, in bytes.
    offset: u32,
    /// Decoded size of the data, in bytes.
    dsize: u32,
    compr: u8,
    /// The `csize` stored bytes.
    data: &'a [u8],
    /// Image offset of the stored bytes.
    data_offset: usize,
}

/// A directory entry node.
#[derive(Debug)]
struct DirentNode {
    pino: u32,
    version: u32,
    /// Target inode; 0 marks an unlink.
    ino: u32,
    dtype: u8,
    /// The name up to its first NUL, as the kernel reads it.
    name: Vec<u8>,
}

/// Node counts for the notes.
#[derive(Debug, Default)]
struct Counts {
    cleanmarkers: usize,
    obsolete: usize,
    /// Padding and summary nodes.
    padding: usize,
    /// Extended-attribute and xattr-reference nodes.
    xattrs: usize,
    /// Nodes of unknown compatible types.
    unknown: usize,
    /// Zeroed (dirty) 4-byte words.
    dirty_words: usize,
}

/// Every valid inode and directory entry node, in image order.
#[derive(Debug, Default)]
struct Scan<'a> {
    inodes: Vec<InodeNode<'a>>,
    dirents: Vec<DirentNode>,
    counts: Counts,
}

impl Scan<'_> {
    fn node_count(&self) -> usize {
        let c = &self.counts;
        self.inodes.len()
            + self.dirents.len()
            + c.cleanmarkers
            + c.obsolete
            + c.padding
            + c.xattrs
            + c.unknown
    }
}

/// Inode node: header, inode (12), version (16), mode (20), owner (24),
/// size (28), times (32), data offset (44), stored size (48), decoded size
/// (52), compression (56), user compression (57), flags (58), data CRC
/// (60), node CRC (64), data (68). Checked as `read_dnode` does.
fn inode_node(data: &[u8], pos: usize, totlen: usize, le: bool) -> Result<InodeNode<'_>> {
    let invalid = |what: &str| error(format!("Invalid JFFS2 inode node at 0x{pos:X}: {what}"));
    if totlen < INODE_NODE_SIZE {
        return Err(invalid("shorter than its header"));
    }
    let node = slice(data, pos, INODE_NODE_SIZE)?;
    if crc32_zero(&node[..INODE_NODE_CRC_SIZE]) != u32_at(node, 64, le)? {
        return Err(invalid("node CRC-32 fails"));
    }
    let csize = u32_at(node, 48, le)? as usize;
    let padded = align_up(INODE_NODE_SIZE.saturating_add(csize), WORD_SIZE)?;
    if padded != align_up(totlen, WORD_SIZE)? {
        return Err(invalid("stored size disagrees with the node length"));
    }
    let data_offset = pos + INODE_NODE_SIZE;
    let stored = slice(data, data_offset, csize)?;
    if crc32_zero(stored) != u32_at(node, 60, le)? {
        return Err(invalid("data CRC-32 fails"));
    }
    let inode = InodeNode {
        ino: u32_at(node, 12, le)?,
        version: u32_at(node, 16, le)?,
        isize: u32_at(node, 28, le)?,
        offset: u32_at(node, 44, le)?,
        dsize: u32_at(node, 52, le)?,
        compr: node[56],
        data: stored,
        data_offset,
    };
    if inode.offset > inode.isize {
        return Err(invalid("data offset beyond the file size"));
    }
    Ok(inode)
}

/// Directory entry node: header, parent inode (12), version (16), target
/// inode (20), time (24), name length (28), type (29), node CRC (32), name
/// CRC (36), name (40). Checked as `jffs2_scan_dirent_node` and
/// `read_direntry` do.
fn dirent_node(data: &[u8], pos: usize, totlen: usize, le: bool) -> Result<DirentNode> {
    let invalid = |what: &str| {
        error(format!(
            "Invalid JFFS2 directory entry at 0x{pos:X}: {what}"
        ))
    };
    if totlen < DIRENT_NODE_SIZE {
        return Err(invalid("shorter than its header"));
    }
    let node = slice(data, pos, DIRENT_NODE_SIZE)?;
    if crc32_zero(&node[..DIRENT_NODE_CRC_SIZE]) != u32_at(node, 32, le)? {
        return Err(invalid("node CRC-32 fails"));
    }
    let nsize = usize::from(node[28]);
    if align_up(DIRENT_NODE_SIZE + nsize, WORD_SIZE)? != align_up(totlen, WORD_SIZE)? {
        return Err(invalid("name length disagrees with the node length"));
    }
    let name = slice(data, pos + DIRENT_NODE_SIZE, nsize)?;
    // The kernel stops the name at a NUL and checks the CRC of what is left.
    let name = &name[..name.iter().position(|b| *b == 0).unwrap_or(nsize)];
    if crc32_zero(name) != u32_at(node, 36, le)? {
        return Err(invalid("name CRC-32 fails"));
    }
    Ok(DirentNode {
        pino: u32_at(node, 12, le)?,
        version: u32_at(node, 16, le)?,
        ino: u32_at(node, 20, le)?,
        dtype: node[29],
        name: name.to_vec(),
    })
}

/// The header CRC: magic, node type with the accurate bit set, and total
/// length, in the image's byte order.
fn header_crc(header: &[u8], nodetype: u16, le: bool) -> u32 {
    let mut covered = [0u8; NODE_HEADER_CRC_SIZE];
    covered.copy_from_slice(&header[..NODE_HEADER_CRC_SIZE]);
    let accurate = nodetype | JFFS2_NODE_ACCURATE;
    let accurate = if le {
        accurate.to_le_bytes()
    } else {
        accurate.to_be_bytes()
    };
    covered[2..4].copy_from_slice(&accurate);
    crc32_zero(&covered)
}

/// Scan the whole image as `jffs2_scan_eraseblock` does, but strictly:
/// anything other than a valid node, erased flash or zeroed (dirty) words
/// is an error.
fn scan(data: &[u8], le: bool) -> Result<Scan<'_>> {
    let mut scan = Scan::default();
    let mut pos = 0;
    while pos < data.len() {
        let Some(word) = data.get(pos..pos + WORD_SIZE) else {
            if !is_padding(&data[pos..]) {
                return Err(error(format!("Truncated JFFS2 node at 0x{pos:X}")));
            }
            break;
        };
        if word == ERASED_WORD {
            // Skip the erased run to the word holding its first other byte;
            // the run is at least this word long, so the scan advances.
            match data[pos..].iter().position(|b| *b != 0xff) {
                Some(run) => pos = (pos + run) / WORD_SIZE * WORD_SIZE,
                None => break,
            }
            continue;
        }
        if word == DIRTY_WORD {
            scan.counts.dirty_words += 1;
            pos += WORD_SIZE;
            continue;
        }
        if u16_at(data, pos, le)? != JFFS2_MAGIC_BITMASK {
            return Err(error(format!(
                "Invalid JFFS2 data at 0x{pos:X}: neither a node nor erased flash"
            )));
        }
        let header = slice(data, pos, NODE_HEADER_SIZE)
            .map_err(|_| error(format!("Truncated JFFS2 node header at 0x{pos:X}")))?;
        let nodetype = u16_at(header, 2, le)?;
        let totlen = u32_at(header, 4, le)? as usize;
        if header_crc(header, nodetype, le) != u32_at(header, 8, le)? {
            return Err(error(format!(
                "Invalid JFFS2 node header CRC-32 at 0x{pos:X}"
            )));
        }
        if totlen < NODE_HEADER_SIZE {
            return Err(error(format!(
                "Invalid JFFS2 node length {totlen} at 0x{pos:X}"
            )));
        }
        let end = pos
            .checked_add(totlen)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                error(format!(
                    "Truncated JFFS2 node at 0x{pos:X}: {totlen} B declared"
                ))
            })?;
        record_node(data, pos, nodetype, totlen, le, &mut scan)?;
        pos = align_up(end, WORD_SIZE)?;
    }
    Ok(scan)
}

/// Interpret one node whose header checked.
fn record_node<'a>(
    data: &'a [u8],
    pos: usize,
    nodetype: u16,
    totlen: usize,
    le: bool,
    scan: &mut Scan<'a>,
) -> Result<()> {
    if nodetype & JFFS2_NODE_ACCURATE == 0 {
        scan.counts.obsolete += 1;
        return Ok(());
    }
    match nodetype {
        JFFS2_NODETYPE_INODE => scan.inodes.push(inode_node(data, pos, totlen, le)?),
        JFFS2_NODETYPE_DIRENT => scan.dirents.push(dirent_node(data, pos, totlen, le)?),
        JFFS2_NODETYPE_CLEANMARKER => scan.counts.cleanmarkers += 1,
        JFFS2_NODETYPE_PADDING | JFFS2_NODETYPE_SUMMARY => scan.counts.padding += 1,
        JFFS2_NODETYPE_XATTR | JFFS2_NODETYPE_XREF => scan.counts.xattrs += 1,
        other if other & JFFS2_COMPAT_MASK == JFFS2_FEATURE_INCOMPAT => {
            return Err(error(format!(
                "Unsupported JFFS2 node type 0x{other:04X} at 0x{pos:X}"
            )));
        }
        _ => scan.counts.unknown += 1,
    }
    Ok(())
}

pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let le = byte_order(data)?;
    let scan = scan(data, le).ok()?;
    (scan.node_count() > 0).then_some(Layout::Jffs2 { big_endian: !le })
}

/// JFFS2 zlib (`jffs2_zlib_decompress`): when the stream starts with a
/// zlib header without a preset dictionary, the kernel skips the two header
/// bytes and inflates raw DEFLATE, so the Adler-32 is not checked;
/// otherwise it inflates a zlib stream.
pub(super) fn zlib(stored: &[u8], size: usize) -> Result<Vec<u8>> {
    let header_skipped = match stored {
        [cmf, flg, _, ..] => {
            flg & PRESET_DICT == 0
                && cmf & 0x0f == Z_DEFLATED
                && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0
        }
        _ => false,
    };
    let decoded = if header_skipped {
        compressed::decode_limited(Codec::Deflate, &stored[2..], size)?
    } else {
        compressed::decode_limited(Codec::Zlib, stored, size)?
    };
    Ok(decoded.data)
}

/// `OpenWrt` JFFS2 LZMA (`jffs2_lzma_decompress`): raw LZMA without a
/// header or end mark, with the encoder's fixed properties. Decoded as an
/// LZMA-alone stream with that header and `size` as the decoded size.
pub(super) fn lzma(stored: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut stream = Vec::with_capacity(LZMA_ALONE_HEADER_SIZE + stored.len());
    stream.push(LZMA_PROPERTIES);
    stream.extend_from_slice(&LZMA_DICT_SIZE.to_le_bytes());
    stream.extend_from_slice(&(size as u64).to_le_bytes());
    stream.extend_from_slice(stored);
    Ok(compressed::decode_limited(Codec::Lzma, &stream, size)?.data)
}

/// The live directory entries: the newest entry for each parent and name
/// (on equal versions the later node replaces the earlier, as in
/// `jffs2_add_fd_to_list`), without unlinks.
fn live_dirents(nodes: &[DirentNode]) -> Vec<Dirent> {
    let mut newest: BTreeMap<(u32, &[u8]), &DirentNode> = BTreeMap::new();
    for node in nodes {
        let key = (node.pino, node.name.as_slice());
        match newest.get(&key) {
            Some(previous) if node.version < previous.version => {}
            _ => {
                newest.insert(key, node);
            }
        }
    }
    newest
        .into_values()
        .filter(|node| node.ino != 0)
        .map(|node| Dirent {
            parent: node.pino,
            name: node.name.clone(),
            inum: node.ino,
            kind: match node.dtype {
                DT_REG => EntryKind::RegularFile,
                DT_DIR => EntryKind::Directory,
                _ => EntryKind::Other,
            },
        })
        .collect()
}

/// How a compression type stores a node's data, or `None` for a type this
/// parser does not decode.
fn encoding(compr: u8) -> Option<Encoding> {
    match compr {
        JFFS2_COMPR_NONE => Some(Encoding::Stored),
        JFFS2_COMPR_ZERO => Some(Encoding::Zeros),
        JFFS2_COMPR_RTIME => Some(Encoding::Codec(Codec::Rtime)),
        JFFS2_COMPR_RUBINMIPS => Some(Encoding::Codec(Codec::RubinMips)),
        JFFS2_COMPR_DYNRUBIN => Some(Encoding::Codec(Codec::DynRubin)),
        JFFS2_COMPR_ZLIB => Some(Encoding::Jffs2Zlib),
        JFFS2_COMPR_LZO => Some(Encoding::Codec(Codec::Lzo1x)),
        JFFS2_COMPR_LZMA => Some(Encoding::Jffs2Lzma),
        _ => None,
    }
}

/// The extent of one node's data, or why it is not extracted. Zero-fill
/// nodes may cover any range (they extend files); a node that must be
/// decoded is limited to [`MAX_NODE_DATA`].
fn extent<'a>(node: &InodeNode<'a>) -> std::result::Result<Extent<'a>, String> {
    let Some(encoding) = encoding(node.compr) else {
        return Err(format!("unsupported compression type 0x{:02X}", node.compr));
    };
    let size = node.dsize as usize;
    let decoded = !matches!(encoding, Encoding::Stored | Encoding::Zeros);
    if decoded && size > MAX_NODE_DATA {
        return Err(format!(
            "a compressed node decodes to {}, more than {}",
            size_text(size),
            size_text(MAX_NODE_DATA)
        ));
    }
    Ok(Extent {
        file_offset: u64::from(node.offset),
        size,
        stored: node.data,
        offset: node.data_offset,
        encoding,
    })
}

/// One regular file from its inode nodes, already in version order (the
/// later node on equal versions); the size is the newest node's.
fn file_data<'a>(nodes: Option<&Vec<&InodeNode<'a>>>) -> FileData<'a> {
    let mut file = FileData::default();
    let Some(nodes) = nodes else {
        file.unsupported = Some("no inode node found".into());
        return file;
    };
    file.size = nodes.last().map_or(0, |node| u64::from(node.isize));
    for node in nodes.iter().filter(|node| node.dsize > 0) {
        match extent(node) {
            Ok(extent) => file.extents.push(extent),
            Err(reason) => {
                file.unsupported = Some(reason);
                return file;
            }
        }
    }
    file
}

/// `"3 zlib, 1 stored"` for every inode node that carries data.
fn data_summary(nodes: &[InodeNode<'_>]) -> String {
    let names = nodes
        .iter()
        .filter(|node| node.dsize > 0)
        .map(|node| encoding(node.compr).map_or("unknown compression", Encoding::name));
    encoding_summary(names)
}

pub(super) fn parse(data: &[u8], le: bool) -> Result<Container<'_>> {
    if byte_order(data) != Some(le) {
        return Err(error("Missing JFFS2 node magic"));
    }
    let scan = scan(data, le)?;
    let mut by_inode: BTreeMap<u32, Vec<&InodeNode<'_>>> = BTreeMap::new();
    for node in &scan.inodes {
        by_inode.entry(node.ino).or_default().push(node);
    }
    for nodes in by_inode.values_mut() {
        // A stable sort keeps image order for equal versions.
        nodes.sort_by_key(|node| node.version);
    }
    let tree = regular_files(&live_dirents(&scan.dirents), ROOT_INO);

    let layout = Layout::Jffs2 { big_endian: !le };
    let mut c = Container::new(FileFormat::Jffs2, layout.label(), "jffs2");
    c.consumed = data.len();
    let counts = &scan.counts;
    c.notes.push(format!(
        "{} nodes in {}-endian order: {} inode, {} directory entry, {} cleanmarker, {} obsolete; header, node, name and data CRC-32 values verified",
        scan.node_count(),
        if le { "little" } else { "big" },
        scan.inodes.len(),
        scan.dirents.len(),
        counts.cleanmarkers,
        counts.obsolete
    ));
    c.notes.push(
        "The erase block size is not recorded; nodes are not checked against erase-block boundaries"
            .into(),
    );
    if counts.padding + counts.xattrs + counts.unknown > 0 {
        c.notes.push(format!(
            "{} padding or summary, {} extended-attribute and {} unknown compatible nodes not interpreted",
            counts.padding, counts.xattrs, counts.unknown
        ));
    }
    if counts.dirty_words > 0 {
        c.notes.push(format!(
            "{} of zeroed (dirty) flash between nodes",
            size_text(counts.dirty_words * WORD_SIZE)
        ));
    }
    c.notes.push(tree_note(&tree));
    if scan.inodes.iter().any(|node| node.dsize > 0) {
        c.notes
            .push(format!("Data nodes: {}", data_summary(&scan.inodes)));
    }
    c.push_metadata(
        "jffs2_byte_order",
        "Node byte order",
        if le { "little-endian" } else { "big-endian" },
    );
    c.push_metadata("jffs2_node_count", "Nodes", scan.node_count() as u64);
    c.push_metadata(
        "jffs2_file_count",
        "Regular files",
        tree.members.len() as u64,
    );
    push_members(&mut c, &tree.members, "JFFS2 file", |inum| {
        Some(file_data(by_inode.get(&inum)))
    });
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian cleanmarker: magic, type 0x2003, length 12, CRC.
    fn cleanmarker() -> Vec<u8> {
        let mut node = vec![0x85, 0x19, 0x03, 0x20, 12, 0, 0, 0];
        let crc = crc32_zero(&node);
        node.extend_from_slice(&crc.to_le_bytes());
        node
    }

    #[test]
    fn byte_order_comes_from_the_first_node_magic() {
        assert_eq!(byte_order(&cleanmarker()), Some(true));
        assert_eq!(
            byte_order(&[0xff, 0xff, 0xff, 0xff, 0x19, 0x85, 0, 0]),
            Some(false)
        );
        assert_eq!(byte_order(&[0x7f, b'E', b'L', b'F']), None);
    }

    #[test]
    fn erased_runs_and_dirty_words_are_skipped() {
        let mut image = vec![0u8; 8];
        image.extend_from_slice(&[0xff; 37]);
        image.resize(48, 0xff);
        image.extend_from_slice(&cleanmarker());
        image.extend_from_slice(&[0xff; 3]);
        let scan = scan(&image, true).unwrap();
        assert_eq!(scan.counts.cleanmarkers, 1);
        assert_eq!(scan.counts.dirty_words, 2);
        let mut garbage = image.clone();
        garbage[20] = 0x12;
        assert!(super::scan(&garbage, true).is_err());
    }

    #[test]
    fn obsolete_nodes_keep_a_valid_header_crc() {
        let mut node = cleanmarker();
        // Clear the accurate bit in place, as obsoleting does.
        node[3] &= !0x20;
        let scan = scan(&node, true).unwrap();
        assert_eq!(scan.counts.obsolete, 1);
    }

    #[test]
    fn zlib_nodes_skip_the_header_and_ignore_the_adler32() {
        let payload = b"jffs2 zlib jffs2 zlib jffs2 zlib";
        let mut stream = miniz_oxide::deflate::compress_to_vec_zlib(payload, 6);
        let last = stream.len() - 1;
        stream[last] ^= 0xff;
        assert_eq!(zlib(&stream, payload.len()).unwrap(), payload);
    }
}
