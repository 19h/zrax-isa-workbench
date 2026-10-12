//! Flash filesystems on raw MTD: JFFS2 in both byte orders (versions,
//! unlinks, obsolete nodes, every codec), UBIFS node scans (newest copies,
//! deletions, truncation, encryption) and UBI images (PEB size discovery,
//! volume table copies, static and dynamic volumes, LEB copies, NAND spare
//! areas), with mtd-utils 2.2.1 fixtures, truncation and mutation sweeps.

use zrax::formats::checksum::crc32_update;
use zrax::formats::{self, container, mtd, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

/// ELF machine numbers used in the synthetic payloads.
const EM_X86_64: u16 = 62;
const EM_MIPS: u16 = 8;

/// `crc32(UBI_CRC32_INIT, ...)` without final inversion: UBI and UBIFS.
fn crc_ones(bytes: &[u8]) -> u32 {
    crc32_update(!0, bytes)
}

/// `crc32(0, ...)` without final inversion: JFFS2.
fn crc_zero(bytes: &[u8]) -> u32 {
    crc32_update(0, bytes)
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn notes(p: &DetectionPayload) -> Vec<&str> {
    p.notes.iter().map(|n| n.message.as_str()).collect()
}

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture is committed")
}

/// A 64-byte ELF header: class (1 = 32-bit, 2 = 64-bit), data encoding
/// (1 = little-endian, 2 = big-endian), version 1, type 2 (executable) and
/// the machine, in the header's byte order.
fn elf(class: u8, big_endian: bool, machine: u16) -> Vec<u8> {
    let half = |v: u16| {
        if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = class;
    data[5] = if big_endian { 2 } else { 1 };
    data[6] = 1;
    data[16..18].copy_from_slice(&half(2));
    data[18..20].copy_from_slice(&half(machine));
    data
}

/// `len` bytes that are not a recognized format.
fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// The MTD layout `detect_format` reports, if any.
fn mtd_layout(data: &[u8]) -> Option<mtd::Layout> {
    match formats::detect_format(data) {
        DetectedFormat::Container {
            kind: container::Kind::Mtd(layout),
        } => Some(layout),
        _ => None,
    }
}

/// One child of a parsed image.
#[derive(Debug, PartialEq, Eq)]
struct Listed {
    label: String,
    data: Vec<u8>,
    opaque: bool,
}

fn listed(label: &str, data: Vec<u8>) -> Listed {
    Listed {
        label: label.to_string(),
        data,
        opaque: false,
    }
}

/// The children of `data` parsed as the layout `detect_format` reports.
fn children(data: &[u8]) -> Vec<Listed> {
    let layout = mtd_layout(data).expect("an MTD layout");
    let c = mtd::parse_container(data, layout).expect("parses");
    c.children
        .iter()
        .map(|child| Listed {
            label: child.label.clone(),
            data: child.data.to_vec(),
            opaque: child.opaque,
        })
        .collect()
}

/// The labels of `data`'s children.
fn labels(data: &[u8]) -> Vec<String> {
    children(data).into_iter().map(|c| c.label).collect()
}

/// Run `check` on copies of `data` with byte `at` set to 0x00, set to 0xFF
/// and with its low bit flipped, for each position.
fn for_each_mutation(
    data: &[u8],
    positions: impl Iterator<Item = usize>,
    mut check: impl FnMut(&[u8]),
) {
    let mut copy = data.to_vec();
    for at in positions {
        let original = copy[at];
        for value in [0x00, 0xff, original ^ 0x01] {
            copy[at] = value;
            check(&copy);
        }
        copy[at] = original;
    }
}

// ---------------------------------------------------------------------------
// JFFS2

const JFFS2_MAGIC_BITMASK: u16 = 0x1985;
const JFFS2_NODETYPE_DIRENT: u16 = 0xE001;
const JFFS2_NODETYPE_INODE: u16 = 0xE002;
const JFFS2_NODETYPE_CLEANMARKER: u16 = 0x2003;
const JFFS2_NODE_ACCURATE: u16 = 0x2000;
/// Unassigned node types with the incompatible and the read-write
/// compatible feature bits.
const JFFS2_UNKNOWN_INCOMPAT: u16 = 0xE00A;
const JFFS2_UNKNOWN_COMPAT: u16 = 0x200A;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const JFFS2_COMPR_NONE: u8 = 0;
const JFFS2_COMPR_ZERO: u8 = 1;
const JFFS2_COMPR_COPY: u8 = 4;
const JFFS2_COMPR_DYNRUBIN: u8 = 5;
const JFFS2_COMPR_ZLIB: u8 = 6;
const JFFS2_COMPR_LZO: u8 = 7;
const JFFS2_COMPR_LZMA: u8 = 8;
/// `sizeof(struct jffs2_raw_inode)`, `sizeof(struct jffs2_raw_dirent)` and
/// the cleanmarker (a bare header).
const JFFS2_INODE_SIZE: usize = 68;
const JFFS2_DIRENT_SIZE: usize = 40;
const JFFS2_HEADER_SIZE: usize = 12;

/// The fields of a JFFS2 inode node.
#[derive(Clone, Copy)]
struct InodeNode<'a> {
    ino: u32,
    version: u32,
    /// `st_mode`.
    mode: u32,
    /// File size after this node.
    isize: u32,
    /// File offset of the data.
    offset: u32,
    /// Decoded size of the data.
    dsize: u32,
    compr: u8,
    /// The stored data.
    data: &'a [u8],
}

/// A regular-file inode node with `data` stored uncompressed at `offset`.
fn stored_inode(ino: u32, version: u32, isize: u32, offset: u32, data: &[u8]) -> InodeNode<'_> {
    InodeNode {
        ino,
        version,
        mode: S_IFREG | 0o755,
        isize,
        offset,
        dsize: data.len() as u32,
        compr: JFFS2_COMPR_NONE,
        data,
    }
}

/// JFFS2 nodes in one byte order, each padded to 4 bytes with 0xFF.
struct Jffs2 {
    le: bool,
    image: Vec<u8>,
    /// Where each node starts and ends (unpadded).
    nodes: Vec<(usize, usize)>,
}

impl Jffs2 {
    fn new(le: bool) -> Self {
        Self {
            le,
            image: Vec::new(),
            nodes: Vec::new(),
        }
    }

    fn u16(&self, v: u16) -> [u8; 2] {
        if self.le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    }

    fn u32(&self, v: u32) -> [u8; 4] {
        if self.le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    }

    /// Common header: magic 0x1985, node type, total length, and the header
    /// CRC over the first 8 bytes computed with the accurate bit (0x2000)
    /// set.
    fn header(&self, nodetype: u16, totlen: usize) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend(self.u16(JFFS2_MAGIC_BITMASK));
        header.extend(self.u16(nodetype | JFFS2_NODE_ACCURATE));
        header.extend(self.u32(totlen as u32));
        let crc = crc_zero(&header);
        header[2..4].copy_from_slice(&self.u16(nodetype));
        header.extend(self.u32(crc));
        header
    }

    fn push(&mut self, node: Vec<u8>) {
        let start = self.image.len();
        self.image.extend_from_slice(&node);
        self.nodes.push((start, self.image.len()));
        while self.image.len() % 4 != 0 {
            self.image.push(0xff);
        }
    }

    /// A cleanmarker: a bare 12-byte header.
    fn cleanmarker(&mut self) {
        let node = self.header(JFFS2_NODETYPE_CLEANMARKER, JFFS2_HEADER_SIZE);
        self.push(node);
    }

    /// Inode node: header; inode (12), version (16), mode (20), uid and gid
    /// (24), file size after this node (28), three times (32), data offset
    /// (44), stored size (48), decoded size (52), compression (56), user
    /// compression (57), flags (58), data CRC (60), node CRC over bytes
    /// 0..60 (64); then the stored data.
    fn inode(&mut self, fields: InodeNode<'_>) {
        let mut node = self.header(JFFS2_NODETYPE_INODE, JFFS2_INODE_SIZE + fields.data.len());
        node.extend(self.u32(fields.ino));
        node.extend(self.u32(fields.version));
        node.extend(self.u32(fields.mode));
        node.extend([0; 4]);
        node.extend(self.u32(fields.isize));
        node.extend([0; 12]);
        node.extend(self.u32(fields.offset));
        node.extend(self.u32(fields.data.len() as u32));
        node.extend(self.u32(fields.dsize));
        node.extend([fields.compr, 0, 0, 0]);
        node.extend(self.u32(crc_zero(fields.data)));
        let crc = crc_zero(&node[..60]);
        node.extend(self.u32(crc));
        node.extend_from_slice(fields.data);
        self.push(node);
    }

    /// A directory inode node: no data.
    fn directory(&mut self, ino: u32) {
        self.inode(InodeNode {
            mode: S_IFDIR | 0o755,
            ..stored_inode(ino, 1, 0, 0, &[])
        });
    }

    /// Directory entry: header; parent (12), version (16), target inode
    /// (20; 0 unlinks), time (24), name length (28), type (29), two unused
    /// bytes, node CRC over bytes 0..32 (32), name CRC (36); then the name.
    fn dirent(&mut self, pino: u32, version: u32, ino: u32, dtype: u8, name: &str) {
        let mut node = self.header(JFFS2_NODETYPE_DIRENT, JFFS2_DIRENT_SIZE + name.len());
        node.extend(self.u32(pino));
        node.extend(self.u32(version));
        node.extend(self.u32(ino));
        node.extend([0; 4]);
        node.extend([name.len() as u8, dtype, 0, 0]);
        let crc = crc_zero(&node);
        node.extend(self.u32(crc));
        node.extend(self.u32(crc_zero(name.as_bytes())));
        node.extend_from_slice(name.as_bytes());
        self.push(node);
    }

    /// Erased flash.
    fn erased(&mut self, len: usize) {
        self.image.resize(self.image.len() + len, 0xff);
    }
}

/// `/bin/app` (inode 3): an ELF header block stored as-is and a zlib
/// block; `/notes.txt` (inode 4): text, not a recognized format. Returns
/// the image and the contents of `/bin/app`.
fn jffs2_image(le: bool, header: &[u8]) -> (Jffs2, Vec<u8>) {
    let mut first = header.to_vec();
    first.extend(filler(4096 - header.len(), 1));
    let second = filler(1500, 2);
    let mut app = first.clone();
    app.extend_from_slice(&second);
    let size = app.len() as u32;
    let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&second, 6);

    let mut image = Jffs2::new(le);
    image.cleanmarker();
    image.dirent(1, 1, 2, DT_DIR, "bin");
    image.directory(2);
    image.dirent(2, 1, 3, DT_REG, "app");
    image.inode(stored_inode(3, 1, 4096, 0, &first));
    image.inode(InodeNode {
        dsize: second.len() as u32,
        compr: JFFS2_COMPR_ZLIB,
        ..stored_inode(3, 2, size, 4096, &zlib)
    });
    image.dirent(1, 2, 4, DT_REG, "notes.txt");
    image.inode(stored_inode(4, 1, 13, 0, b"no code here\n"));
    image.erased(64);
    (image, app)
}

#[test]
fn jffs2_little_endian_files_are_listed_with_full_paths() {
    let (image, app) = jffs2_image(true, &elf(2, false, EM_X86_64));
    assert_eq!(
        mtd_layout(&image.image),
        Some(mtd::Layout::Jffs2 { big_endian: false })
    );
    let p = classify(&image.image);
    assert_eq!(p.format.format, FileFormat::Jffs2);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("JFFS2 image (little-endian)")
    );
    // No ISA field: the ISA comes from the listed file.
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 1, "only the recognized file is listed");
    let slice = &p.slices[0];
    assert_eq!(slice.label.as_deref(), Some("/bin/app"));
    let decoded = slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "JFFS2 file");
    assert_eq!(decoded.size, app.len() as u64);
    // Stored coordinates: from the first data node's data to the end of the
    // last one.
    let first_data = image.nodes[4].0 + JFFS2_INODE_SIZE;
    assert_eq!(slice.offset, first_data as u64);
    assert_eq!(slice.offset + slice.size, image.nodes[5].1 as u64);
    assert!(
        has_note(&p, "Data nodes: 2 stored, 1 zlib"),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(
        &p,
        "2 regular files, 1 directories, 0 other entries"
    ));
    assert_eq!(children(&image.image), vec![listed("/bin/app", app)]);
}

#[test]
fn jffs2_big_endian_nodes_are_decoded_in_their_byte_order() {
    let (image, app) = jffs2_image(false, &elf(1, true, EM_MIPS));
    assert_eq!(
        mtd_layout(&image.image),
        Some(mtd::Layout::Jffs2 { big_endian: true })
    );
    let p = classify(&image.image);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("JFFS2 image (big-endian)")
    );
    // The ISA and code byte order come from the ELF, not from the nodes.
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Mips, Endianness::Big)
    );
    assert_eq!(children(&image.image), vec![listed("/bin/app", app)]);
}

#[test]
fn jffs2_newer_versions_overwrite_older_data_and_set_the_size() {
    let (mut image, app) = jffs2_image(true, &elf(2, false, EM_X86_64));
    // Version 3 rewrites the header with a big-endian MIPS ELF; version 4
    // truncates the file to 5000 bytes; version 5 punches a zero hole.
    let mips = elf(1, true, EM_MIPS);
    image.inode(stored_inode(3, 3, app.len() as u32, 0, &mips));
    image.inode(stored_inode(3, 4, 5000, 0, &[]));
    image.inode(InodeNode {
        dsize: 50,
        compr: JFFS2_COMPR_ZERO,
        ..stored_inode(3, 5, 5000, 100, &[])
    });
    let mut expected = app[..5000].to_vec();
    expected[..64].copy_from_slice(&mips);
    expected[100..150].fill(0);
    let p = classify(&image.image);
    assert_eq!(p.primary.isa, Isa::Mips);
    assert_eq!(children(&image.image), vec![listed("/bin/app", expected)]);
}

#[test]
fn jffs2_unlinked_and_obsolete_entries_are_not_listed() {
    let (mut unlinked, _) = jffs2_image(true, &elf(2, false, EM_X86_64));
    unlinked.dirent(2, 2, 0, DT_REG, "app");
    let p = classify(&unlinked.image);
    assert_eq!(p.format.format, FileFormat::Jffs2);
    assert!(p.slices.is_empty());
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    assert_eq!(p.primary.confidence, 0.0);

    // Obsoleting clears the accurate bit in place; the header CRC still
    // matches because it is computed with the bit set.
    let (mut obsolete, _) = jffs2_image(true, &elf(2, false, EM_X86_64));
    let (start, _) = obsolete.nodes[3];
    let nodetype_high_byte = start + 3;
    obsolete.image[nodetype_high_byte] &= !0x20;
    let p = classify(&obsolete.image);
    assert_eq!(p.format.format, FileFormat::Jffs2);
    assert!(p.slices.is_empty());
    assert!(has_note(&p, "1 obsolete"));

    // A rename: a newer entry for the same name names another inode.
    let (mut renamed, _) = jffs2_image(true, &elf(2, false, EM_X86_64));
    renamed.dirent(2, 3, 4, DT_REG, "app");
    assert!(classify(&renamed.image).slices.is_empty());
}

#[test]
fn jffs2_hard_links_list_each_path() {
    let (mut image, app) = jffs2_image(true, &elf(2, false, EM_X86_64));
    image.dirent(1, 3, 3, DT_REG, "app-link");
    assert_eq!(
        children(&image.image),
        vec![listed("/app-link", app.clone()), listed("/bin/app", app)]
    );
}

/// Port of the kernel's rubin encoder (`fs/jffs2/compr_rubin.c`:
/// `init_rubin`, `encode`, `out_byte`, `end_rubin`) for the dynamic model:
/// eight probability bytes, then the coded bits, most significant first.
fn dynrubin(data: &[u8], table: [u8; 8]) -> Vec<u8> {
    const UPPER: u64 = 1 << 15;
    const LOWER: u64 = UPPER - 1;
    const DIVIDER: u64 = 256;
    let mut bits: Vec<bool> = Vec::new();
    let mut p = 2 * UPPER;
    let mut q = 0u64;
    for &byte in data {
        for (i, &one) in table.iter().enumerate() {
            while q >= UPPER || p + q <= UPPER {
                bits.push(q & UPPER != 0);
                q = (q & LOWER) << 1;
                p <<= 1;
            }
            let zero = DIVIDER - u64::from(one);
            let mut split = (zero * p / DIVIDER).max(1);
            if split >= p {
                split = p - 1;
            }
            if (byte >> i) & 1 == 1 {
                p -= split;
                q += split;
            } else {
                p = split;
            }
        }
    }
    for _ in 0..16 {
        bits.push(q & UPPER != 0);
        q = (q & LOWER) << 1;
    }
    let mut out = table.to_vec();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, bit) in chunk.iter().enumerate() {
            byte |= u8::from(*bit) << (7 - i);
        }
        out.push(byte);
    }
    out
}

/// A raw LZO1X stream of literals only: a first byte of 17 plus the count
/// (4 to 238), the literals, and the end-of-stream marker `11 00 00`.
fn lzo1x_literals(data: &[u8]) -> Vec<u8> {
    assert!((4..=238).contains(&data.len()));
    let mut stream = vec![17 + data.len() as u8];
    stream.extend_from_slice(data);
    stream.extend_from_slice(&[0x11, 0, 0]);
    stream
}

/// The ELF header of `elf(2, false, EM_X86_64)` followed by 64 bytes of
/// `jffs2 lzma node ` text.
fn lzma_payload() -> Vec<u8> {
    let mut payload = elf(2, false, EM_X86_64);
    payload.extend(b"jffs2 lzma node ".repeat(4));
    payload
}

/// `lzma_payload()` compressed by Python 3.14 `lzma.compress(payload,
/// format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size":
/// 8192, "lc": 0, "lp": 0, "pb": 0}])`: the `OpenWrt` JFFS2 LZMA
/// properties, with no header. liblzma appends an end marker, which the
/// `OpenWrt` encoder does not write; decoding stops at the declared size
/// either way.
const LZMA_NODE: [u8; 44] = [
    0x00, 0x3f, 0x91, 0xd6, 0xd5, 0xfd, 0x3e, 0x12, 0x2a, 0xc7, 0xbb, 0x3a, 0x02, 0x08, 0xa8, 0x82,
    0x62, 0x85, 0xab, 0x40, 0xa9, 0x34, 0x78, 0xf1, 0xe7, 0x5d, 0x13, 0xc1, 0xf4, 0xb0, 0x57, 0xde,
    0xb0, 0x45, 0xb2, 0xd0, 0x48, 0x67, 0xff, 0xff, 0xae, 0x38, 0x00, 0x00,
];

#[test]
fn jffs2_lzo_lzma_and_dynrubin_nodes_decode() {
    let lzo = elf(2, false, EM_X86_64);
    let lzo_stream = lzo1x_literals(&lzo);
    let mut rubin = elf(1, true, EM_MIPS);
    rubin.extend(b"dynrubin dynrubin ".repeat(5));
    let packed = dynrubin(&rubin, [40, 90, 120, 60, 200, 10, 128, 30]);

    let mut image = Jffs2::new(true);
    image.dirent(1, 1, 10, DT_REG, "lzo.elf");
    image.inode(InodeNode {
        compr: JFFS2_COMPR_LZO,
        dsize: 64,
        ..stored_inode(10, 1, 64, 0, &lzo_stream)
    });
    image.dirent(1, 2, 11, DT_REG, "lzma.elf");
    image.inode(InodeNode {
        compr: JFFS2_COMPR_LZMA,
        dsize: 128,
        ..stored_inode(11, 1, 128, 0, &LZMA_NODE)
    });
    image.dirent(1, 3, 12, DT_REG, "rubin.elf");
    image.inode(InodeNode {
        compr: JFFS2_COMPR_DYNRUBIN,
        dsize: rubin.len() as u32,
        ..stored_inode(12, 1, rubin.len() as u32, 0, &packed)
    });
    let p = classify(&image.image);
    assert!(
        has_note(&p, "Data nodes: 1 LZMA, 1 LZO1X, 1 dynrubin"),
        "{:?}",
        notes(&p)
    );
    assert_eq!(
        children(&image.image),
        vec![
            listed("/lzma.elf", lzma_payload()),
            listed("/lzo.elf", lzo),
            listed("/rubin.elf", rubin),
        ]
    );
}

#[test]
fn jffs2_unsupported_compression_is_noted_not_extracted() {
    let header = elf(2, false, EM_X86_64);
    let mut image = Jffs2::new(true);
    image.dirent(1, 1, 5, DT_REG, "copy.bin");
    image.inode(InodeNode {
        compr: JFFS2_COMPR_COPY,
        ..stored_inode(5, 1, 64, 0, &header)
    });
    let p = classify(&image.image);
    assert_eq!(p.format.format, FileFormat::Jffs2);
    assert!(p.slices.is_empty());
    assert!(has_note(
        &p,
        "/copy.bin: unsupported compression type 0x04; not extracted"
    ));
}

#[test]
fn jffs2_corrupt_lzo_data_is_noted_not_extracted() {
    // An LZO1X stream with a byte after its end marker: the kernel requires
    // the whole input to be consumed.
    let header = elf(2, false, EM_X86_64);
    let mut stream = lzo1x_literals(&header);
    stream.push(0);
    let mut image = Jffs2::new(true);
    image.dirent(1, 1, 5, DT_REG, "bad.elf");
    image.inode(InodeNode {
        compr: JFFS2_COMPR_LZO,
        dsize: 64,
        ..stored_inode(5, 1, 64, 0, &stream)
    });
    let p = classify(&image.image);
    assert!(p.slices.is_empty());
    assert!(
        has_note(&p, "/bad.elf: data does not decode"),
        "{:?}",
        notes(&p)
    );
}

#[test]
fn jffs2_requires_every_crc_and_rejects_unknown_incompatible_nodes() {
    let (image, _) = jffs2_image(true, &elf(2, false, EM_X86_64));
    assert!(mtd_layout(&image.image).is_some());
    let (dirent_start, _) = image.nodes[3];
    let (inode_start, _) = image.nodes[4];
    let corruptions = [
        dirent_start + 8,  // header CRC
        dirent_start + 33, // dirent node CRC
        dirent_start + 37, // name CRC
        dirent_start + 41, // a name byte
        inode_start + 64,  // inode node CRC
        inode_start + 100, // a data byte
    ];
    for at in corruptions {
        let mut corrupt = image.image.clone();
        corrupt[at] ^= 0x10;
        assert_eq!(mtd_layout(&corrupt), None, "corruption at 0x{at:X}");
        let e = mtd::parse_container(&corrupt, mtd::Layout::Jffs2 { big_endian: false })
            .expect_err("a strict parse fails");
        assert!(
            e.to_string()
                .starts_with("Flash filesystem parse error: Invalid JFFS2"),
            "{e}"
        );
    }
    let mut garbage = image.image.clone();
    let end = garbage.len();
    garbage[end - 8] = 0x42;
    assert_eq!(mtd_layout(&garbage), None, "garbage between nodes");

    let mut incompat = Jffs2::new(true);
    incompat.cleanmarker();
    let node = incompat.header(JFFS2_UNKNOWN_INCOMPAT, JFFS2_HEADER_SIZE);
    incompat.push(node);
    assert_eq!(mtd_layout(&incompat.image), None);
    let mut compatible = Jffs2::new(true);
    compatible.cleanmarker();
    let node = compatible.header(JFFS2_UNKNOWN_COMPAT, JFFS2_HEADER_SIZE);
    compatible.push(node);
    let p = classify(&compatible.image);
    assert_eq!(p.format.format, FileFormat::Jffs2);
    assert!(has_note(&p, "1 unknown compatible nodes not interpreted"));
}

#[test]
fn jffs2_prefixes_are_recognized_only_at_node_boundaries() {
    let (image, _) = jffs2_image(true, &elf(2, false, EM_X86_64));
    let data = &image.image;
    for end in 0..data.len() {
        let prefix = &data[..end];
        // Valid exactly when the prefix ends at a node's end or in the
        // erased padding after it.
        let at_boundary = image.nodes.iter().any(|&(_, node_end)| {
            node_end <= end && data[node_end..end].iter().all(|b| *b == 0xff)
        });
        assert_eq!(
            mtd_layout(prefix).is_some(),
            at_boundary && end > 0,
            "prefix of {end} B"
        );
    }
}

#[test]
fn jffs2_mutations_never_panic() {
    let (image, _) = jffs2_image(false, &elf(1, true, EM_MIPS));
    let layout = mtd::Layout::Jffs2 { big_endian: true };
    for_each_mutation(&image.image, 0..image.image.len(), |mutated| {
        let _ = mtd::parse_container(mutated, layout);
        let _ = mtd_layout(mutated);
    });
    for_each_mutation(
        &image.image,
        (0..image.image.len()).step_by(97),
        |mutated| {
            let _ = detect_payload(mutated, &ClassifierOptions::new());
        },
    );
}

/// The files mtd-utils packed into every fixture (see
/// `tests/fixtures/mtd/README.md`): an ELF header followed by `AArch64`
/// code.
fn tool_elf() -> Vec<u8> {
    let mut tool = fixture("compressed/payload.elf");
    tool.extend(fixture("transforms/aarch64.text.bin"));
    tool
}

/// Two copies of the ELF fixture with a hole between them.
fn sparse_elf() -> Vec<u8> {
    let payload = fixture("compressed/payload.elf");
    let mut sparse = payload.clone();
    sparse.resize(3 * 4096, 0);
    sparse.extend_from_slice(&payload);
    sparse
}

/// The four recognized files of the fixture tree, in path order.
fn fixture_tree() -> Vec<Listed> {
    vec![
        listed("/bin/tool-link.elf", tool_elf()),
        listed("/bin/tool.elf", tool_elf()),
        listed("/boot/sparse.elf", sparse_elf()),
        listed("/lib/payload.elf", fixture("compressed/payload.elf")),
    ]
}

#[test]
fn mkfs_jffs2_images_decode_in_both_byte_orders_and_every_codec() {
    for (name, big_endian, codecs) in [
        (
            "rootfs-le-zlib.jffs2",
            false,
            "Data nodes: 7 zlib, 2 stored",
        ),
        (
            "rootfs-le-rtime.jffs2",
            false,
            "Data nodes: 5 rtime, 4 stored",
        ),
        ("rootfs-be-lzo.jffs2", true, "Data nodes: 7 LZO1X, 2 stored"),
    ] {
        let data = fixture(&format!("mtd/{name}"));
        assert_eq!(
            mtd_layout(&data),
            Some(mtd::Layout::Jffs2 { big_endian }),
            "{name}"
        );
        let p = classify(&data);
        assert_eq!(p.primary.isa, Isa::X86_64, "{name}");
        assert!(has_note(&p, codecs), "{name}: {:?}", notes(&p));
        assert!(
            has_note(&p, "6 regular files, 5 directories, 1 other entries"),
            "{name}"
        );
        assert_eq!(children(&data), fixture_tree(), "{name}");
    }
}

#[test]
fn mkfs_jffs2_mutations_never_panic() {
    let data = fixture("mtd/rootfs-le-rtime.jffs2");
    let layout = mtd_layout(&data).expect("JFFS2");
    for_each_mutation(&data, (0..data.len()).step_by(3), |mutated| {
        let _ = mtd::parse_container(mutated, layout);
        let _ = mtd_layout(mutated);
    });
}

// ---------------------------------------------------------------------------
// UBIFS

const UBIFS_NODE_MAGIC: u32 = 0x0610_1831;
const UBIFS_LEB: usize = 15 * 1024;
/// Superblock, two master LEBs, two log LEBs, two LPT LEBs, one orphan LEB.
const UBIFS_MAIN_FIRST: usize = 8;
const UBIFS_INO_NODE: u8 = 0;
const UBIFS_DATA_NODE: u8 = 1;
const UBIFS_DENT_NODE: u8 = 2;
const UBIFS_TRUN_NODE: u8 = 4;
const UBIFS_PAD_NODE: u8 = 5;
const UBIFS_SB_NODE: u8 = 6;
const UBIFS_INO_KEY: u32 = 0;
const UBIFS_DATA_KEY: u32 = 1;
const UBIFS_DENT_KEY: u32 = 2;
const UBIFS_ITYPE_REG: u8 = 0;
const UBIFS_ITYPE_DIR: u8 = 1;
const UBIFS_COMPR_NONE: u16 = 0;
const UBIFS_COMPR_LZO: u16 = 1;
const UBIFS_COMPR_ZLIB: u16 = 2;
const UBIFS_COMPR_ZSTD: u16 = 3;
const UBIFS_CRYPT_FL: u32 = 0x40;
const UBIFS_FLG_ENCRYPTION: u32 = 0x10;
const UBIFS_CH_SZ: usize = 24;
const UBIFS_INO_NODE_SZ: usize = 160;
const UBIFS_DATA_NODE_SZ: usize = 48;
const UBIFS_SB_NODE_SZ: usize = 4096;

/// A UBIFS image: the superblock in LEB 0, empty master, log, LPT and
/// orphan LEBs, and main-area LEBs filled node by node.
struct Ubifs {
    main: Vec<Vec<u8>>,
    sqnum: u64,
    /// Image offset of the last node.
    last_node: usize,
}

impl Ubifs {
    fn new() -> Self {
        Self {
            main: vec![Vec::new()],
            sqnum: 100,
            last_node: 0,
        }
    }

    /// Common header: magic, CRC over bytes 8 to the end of the node,
    /// sequence number, length, node type, group type 0, padding; then the
    /// body.
    fn node(node_type: u8, sqnum: u64, body: &[u8]) -> Vec<u8> {
        let mut node = Vec::new();
        node.extend(UBIFS_NODE_MAGIC.to_le_bytes());
        node.extend([0; 4]);
        node.extend(sqnum.to_le_bytes());
        node.extend(((UBIFS_CH_SZ + body.len()) as u32).to_le_bytes());
        node.extend([node_type, 0, 0, 0]);
        node.extend_from_slice(body);
        let crc = crc_ones(&node[8..]);
        node[4..8].copy_from_slice(&crc.to_le_bytes());
        node
    }

    /// Append `bytes` (a node and anything that belongs after it), 8-byte
    /// aligned with zero fill, starting a new LEB when it does not fit.
    fn append(&mut self, bytes: &[u8]) {
        let fits = self.main.last().expect("one LEB").len() + bytes.len() <= UBIFS_LEB;
        if !fits {
            self.main.push(Vec::new());
        }
        let lnum = UBIFS_MAIN_FIRST + self.main.len() - 1;
        let leb = self.main.last_mut().expect("one LEB");
        self.last_node = lnum * UBIFS_LEB + leb.len();
        leb.extend_from_slice(bytes);
        while leb.len() % 8 != 0 {
            leb.push(0);
        }
    }

    /// Append a node with the next sequence number, or `sqnum`.
    fn push(&mut self, node_type: u8, sqnum: Option<u64>, body: &[u8]) {
        let sqnum = sqnum.unwrap_or_else(|| {
            self.sqnum += 1;
            self.sqnum
        });
        let node = Self::node(node_type, sqnum, body);
        self.append(&node);
    }

    /// Simple key: inode number, then the key type in the top 3 bits and a
    /// block number or name hash below; 8 zero bytes.
    fn key(inum: u32, key_type: u32, low: u32) -> Vec<u8> {
        let mut key = inum.to_le_bytes().to_vec();
        key.extend(((key_type << 29) | low).to_le_bytes());
        key.extend([0; 8]);
        key
    }

    /// Inode node body: key, creation sqnum (40), size (48), times, nlink
    /// (92), uid, gid, mode (104), flags (108), data length 0 (112), xattr
    /// fields, compression (132), padding to 160.
    fn ino(&mut self, inum: u32, size: u64, nlink: u32, mode: u32, flags: u32) {
        let mut node = [0u8; UBIFS_INO_NODE_SZ];
        node[24..40].copy_from_slice(&Self::key(inum, UBIFS_INO_KEY, 0));
        node[48..56].copy_from_slice(&size.to_le_bytes());
        node[92..96].copy_from_slice(&nlink.to_le_bytes());
        node[104..108].copy_from_slice(&mode.to_le_bytes());
        node[108..112].copy_from_slice(&flags.to_le_bytes());
        self.push(UBIFS_INO_NODE, None, &node[UBIFS_CH_SZ..]);
    }

    /// Data node body: key (inode, block), decoded size (40), compression
    /// (44), compressed size (46, encryption only), data (48).
    fn data(
        &mut self,
        inum: u32,
        block: u32,
        size: usize,
        compr: u16,
        stored: &[u8],
        sqnum: Option<u64>,
    ) {
        let mut body = Self::key(inum, UBIFS_DATA_KEY, block);
        body.extend((size as u32).to_le_bytes());
        body.extend(compr.to_le_bytes());
        body.extend([0; 2]);
        body.extend_from_slice(stored);
        self.push(UBIFS_DATA_NODE, sqnum, &body);
    }

    /// Directory entry body: key (parent, name hash), target inode (40, 0
    /// deletes), padding, type (49), name length (50), cookie (52), name
    /// and NUL (56). The hash is arbitrary; the parser does not check it.
    fn dent(&mut self, parent: u32, name: &str, inum: u64, itype: u8) {
        let hash = name
            .bytes()
            .fold(7u32, |h, b| h.wrapping_mul(31) ^ u32::from(b))
            & 0x1FFF_FFFF;
        let mut body = Self::key(parent, UBIFS_DENT_KEY, hash.max(3));
        body.extend(inum.to_le_bytes());
        body.extend([0, itype]);
        body.extend((name.len() as u16).to_le_bytes());
        body.extend([0; 4]);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        self.push(UBIFS_DENT_NODE, None, &body);
    }

    /// Truncation node body: inode (24), padding, old size (40), new size
    /// (48).
    fn trun(&mut self, inum: u32, old_size: u64, new_size: u64) {
        let mut body = inum.to_le_bytes().to_vec();
        body.extend([0; 12]);
        body.extend(old_size.to_le_bytes());
        body.extend(new_size.to_le_bytes());
        self.push(UBIFS_TRUN_NODE, None, &body);
    }

    /// A padding node (`ubifs_pad`): the 28-byte node holding `pad_len`,
    /// then `pad_len` zero bytes outside the node and its CRC; together a
    /// multiple of 8.
    fn pad(&mut self, pad_len: usize) {
        self.sqnum += 1;
        let mut bytes = Self::node(UBIFS_PAD_NODE, self.sqnum, &(pad_len as u32).to_le_bytes());
        bytes.resize(bytes.len() + pad_len, 0);
        self.append(&bytes);
    }

    /// Superblock node (4096 bytes): key hash 0 and simple key format (26,
    /// 27), flags (28), minimum I/O 8 (32), LEB size (36), LEB count (40),
    /// maximum LEB count 64 (44), journal size (48), log, LPT and orphan
    /// LEBs 2, 2, 1 (56-64), journal heads 1 (68), fanout 8 (72), LPT saves
    /// (76), format version 4 (80), default compression LZO (84), time
    /// granularity (104).
    fn superblock(leb_cnt: u32, flags: u32) -> Vec<u8> {
        let mut node = vec![0u8; UBIFS_SB_NODE_SZ];
        let fields: [(usize, &[u8]); 14] = [
            (28, &flags.to_le_bytes()),
            (32, &8u32.to_le_bytes()),
            (36, &(UBIFS_LEB as u32).to_le_bytes()),
            (40, &leb_cnt.to_le_bytes()),
            (44, &64u32.to_le_bytes()),
            (48, &(3 * UBIFS_LEB as u64).to_le_bytes()),
            (56, &2u32.to_le_bytes()),
            (60, &2u32.to_le_bytes()),
            (64, &1u32.to_le_bytes()),
            (68, &1u32.to_le_bytes()),
            (72, &8u32.to_le_bytes()),
            (76, &256u32.to_le_bytes()),
            (80, &4u32.to_le_bytes()),
            (84, &UBIFS_COMPR_LZO.to_le_bytes()),
        ];
        for (at, bytes) in fields {
            node[at..at + bytes.len()].copy_from_slice(bytes);
        }
        node[104..108].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        Self::node(UBIFS_SB_NODE, 1, &node[UBIFS_CH_SZ..])
    }

    /// The image: superblock LEB, erased master, log, LPT and orphan LEBs,
    /// then the main area with each LEB erased after its nodes.
    fn image(&self, flags: u32) -> Vec<u8> {
        let leb_cnt = (UBIFS_MAIN_FIRST + self.main.len()) as u32;
        let mut image = vec![0xffu8; UBIFS_MAIN_FIRST * UBIFS_LEB];
        image[..UBIFS_SB_NODE_SZ].copy_from_slice(&Self::superblock(leb_cnt, flags));
        for leb in &self.main {
            let mut leb = leb.clone();
            leb.resize(UBIFS_LEB, 0xff);
            image.extend(leb);
        }
        image
    }
}

/// `/bin/app` (inode 65): an ELF block in zlib (raw DEFLATE) and a second
/// block in Zstandard, with a hole at block 2 and a stored block 3;
/// `/etc/lzo.elf` (inode 66): one LZO1X block; `/etc/text` (inode 67): not
/// a recognized format. Returns the builder and `/bin/app`'s contents.
fn ubifs_tree(header: &[u8]) -> (Ubifs, Vec<u8>) {
    let mut first = header.to_vec();
    first.extend(filler(4096 - header.len(), 3));
    let second = filler(4096, 4);
    let fourth = filler(1000, 5);
    let mut app = first.clone();
    app.extend_from_slice(&second);
    app.resize(3 * 4096, 0);
    app.extend_from_slice(&fourth);
    let deflate = miniz_oxide::deflate::compress_to_vec(&first, 6);
    let zstd =
        ruzstd::encoding::compress_to_vec(&second[..], ruzstd::encoding::CompressionLevel::Fastest);

    let mut fs = Ubifs::new();
    fs.ino(1, 160, 3, 0o040_755, 0);
    fs.dent(1, "bin", 64, UBIFS_ITYPE_DIR);
    fs.ino(64, 160, 2, 0o040_755, 0);
    fs.dent(64, "app", 65, UBIFS_ITYPE_REG);
    fs.ino(65, app.len() as u64, 1, 0o100_755, 0);
    fs.data(65, 0, 4096, UBIFS_COMPR_ZLIB, &deflate, None);
    fs.data(65, 1, 4096, UBIFS_COMPR_ZSTD, &zstd, None);
    fs.data(65, 3, fourth.len(), UBIFS_COMPR_NONE, &fourth, None);
    fs.dent(1, "etc", 70, UBIFS_ITYPE_DIR);
    fs.ino(70, 160, 2, 0o040_755, 0);
    fs.dent(70, "lzo.elf", 66, UBIFS_ITYPE_REG);
    fs.ino(66, 64, 1, 0o100_644, 0);
    let lzo = lzo1x_literals(&elf(1, true, EM_MIPS));
    fs.data(66, 0, 64, UBIFS_COMPR_LZO, &lzo, None);
    fs.dent(70, "text", 67, UBIFS_ITYPE_REG);
    fs.ino(67, 6, 1, 0o100_644, 0);
    fs.data(67, 0, 6, UBIFS_COMPR_NONE, b"hello\n", None);
    fs.pad(36);
    (fs, app)
}

#[test]
fn ubifs_files_are_rebuilt_from_data_nodes_with_holes() {
    let (fs, app) = ubifs_tree(&elf(2, false, EM_X86_64));
    let image = fs.image(0);
    assert_eq!(mtd_layout(&image), Some(mtd::Layout::Ubifs));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Ubifs);
    assert_eq!(p.format.variant_name.as_deref(), Some("UBIFS image"));
    assert_eq!(p.primary.isa, Isa::X86_64);
    let slice_labels: Vec<_> = p.slices.iter().filter_map(|s| s.label.clone()).collect();
    assert_eq!(slice_labels, ["/bin/app", "/etc/lzo.elf"]);
    assert_eq!(p.slices[1].isa, Isa::Mips);
    let decoded = p.slices[0].decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "UBIFS file");
    assert_eq!(decoded.size, app.len() as u64);
    assert!(
        has_note(&p, "Data nodes: 2 stored, 1 DEFLATE, 1 LZO1X, 1 Zstandard"),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(
        &p,
        "3 regular files, 2 directories, 0 other entries"
    ));
    assert!(!has_note(&p, "scanning stopped"), "{:?}", notes(&p));
    assert_eq!(
        children(&image),
        vec![
            listed("/bin/app", app),
            listed("/etc/lzo.elf", elf(1, true, EM_MIPS)),
        ]
    );
}

#[test]
fn ubifs_newest_sequence_numbers_win_over_flash_order() {
    let (mut fs, mut app) = ubifs_tree(&elf(2, false, EM_X86_64));
    // A copy of block 0 with a lower sequence number, written later (as
    // garbage collection can leave it), is ignored.
    let stale = elf(1, true, EM_MIPS);
    fs.data(65, 0, 64, UBIFS_COMPR_NONE, &stale, Some(1));
    assert_eq!(children(&fs.image(0))[0], listed("/bin/app", app.clone()));
    // A newer block 0 replaces the whole block: bytes past its size are
    // zero.
    fs.data(65, 0, 64, UBIFS_COMPR_NONE, &stale, None);
    app[..64].copy_from_slice(&stale);
    app[64..4096].fill(0);
    let image = fs.image(0);
    assert_eq!(children(&image)[0], listed("/bin/app", app));
    assert_eq!(classify(&image).primary.isa, Isa::Mips);
}

#[test]
fn ubifs_deletions_and_truncations_are_applied() {
    let (mut deleted, _) = ubifs_tree(&elf(2, false, EM_X86_64));
    deleted.dent(64, "app", 0, UBIFS_ITYPE_REG);
    assert_eq!(labels(&deleted.image(0)), ["/etc/lzo.elf"]);

    let (mut unlinked, _) = ubifs_tree(&elf(2, false, EM_X86_64));
    unlinked.ino(65, 0, 0, 0o100_755, 0);
    assert_eq!(labels(&unlinked.image(0)), ["/etc/lzo.elf"]);

    // Truncated to one block, then extended again: blocks past the
    // truncation point read as holes.
    let (mut truncated, app) = ubifs_tree(&elf(2, false, EM_X86_64));
    truncated.trun(65, app.len() as u64, 4096);
    truncated.ino(65, app.len() as u64, 1, 0o100_755, 0);
    let mut expected = app[..4096].to_vec();
    expected.resize(app.len(), 0);
    assert_eq!(
        children(&truncated.image(0))[0],
        listed("/bin/app", expected)
    );
}

#[test]
fn ubifs_encrypted_files_are_noted_not_extracted() {
    let (mut fs, app) = ubifs_tree(&elf(2, false, EM_X86_64));
    fs.ino(65, app.len() as u64, 1, 0o100_755, UBIFS_CRYPT_FL);
    let p = classify(&fs.image(UBIFS_FLG_ENCRYPTION));
    assert!(
        has_note(&p, "/bin/app: encrypted; not extracted"),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(
        &p,
        "Encryption enabled; encrypted files are not extracted"
    ));
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.primary.isa, Isa::Mips);
}

#[test]
fn ubifs_superblock_faults_are_errors_and_node_faults_stop_the_leb() {
    let (fs, _) = ubifs_tree(&elf(2, false, EM_X86_64));
    let image = fs.image(0);
    let mut bad_sb = image.clone();
    bad_sb[200] ^= 1;
    let e = detect_payload(&bad_sb, &ClassifierOptions::new()).unwrap_err();
    assert!(
        e.to_string()
            .contains("Invalid UBIFS superblock node CRC-32"),
        "{e}"
    );
    let short = &image[..UBIFS_MAIN_FIRST * UBIFS_LEB];
    let e = detect_payload(short, &ClassifierOptions::new()).unwrap_err();
    assert!(e.to_string().contains("Truncated UBIFS image"), "{e}");

    // A corrupt node ends the scan of its LEB; the nodes before it count.
    let mut bad_node = image.clone();
    bad_node[fs.last_node - 40] ^= 0x55;
    let p = classify(&bad_node);
    assert_eq!(p.format.format, FileFormat::Ubifs);
    assert!(
        has_note(&p, "LEB 8: scanning stopped at offset"),
        "{:?}",
        notes(&p)
    );
}

#[test]
fn ubifs_prefixes_never_claim_the_last_file() {
    let (mut fs, _) = ubifs_tree(&elf(2, false, EM_X86_64));
    // The last node is the only data node of /etc/late.elf.
    fs.dent(70, "late.elf", 68, UBIFS_ITYPE_REG);
    fs.ino(68, 64, 1, 0o100_644, 0);
    fs.data(68, 0, 64, UBIFS_COMPR_NONE, &elf(2, false, EM_X86_64), None);
    let image = fs.image(0);
    let lists_late = |data: &[u8]| {
        mtd::parse_container(data, mtd::Layout::Ubifs)
            .ok()
            .is_some_and(|c| c.children.iter().any(|ch| ch.label == "/etc/late.elf"))
    };
    assert!(lists_late(&image));
    let node_end = fs.last_node + UBIFS_DATA_NODE_SZ + 64;
    for end in 0..node_end {
        assert!(!lists_late(&image[..end]), "prefix of {end} B");
    }
}

#[test]
fn ubifs_mutations_never_panic() {
    let (fs, _) = ubifs_tree(&elf(2, false, EM_X86_64));
    let image = fs.image(0);
    let main = UBIFS_MAIN_FIRST * UBIFS_LEB;
    let used = fs.main[0].len();
    let positions = (0..128).chain(main..main + used);
    for_each_mutation(&image, positions, |mutated| {
        let _ = mtd::parse_container(mutated, mtd::Layout::Ubifs);
    });
    for_each_mutation(&image, (main..main + used).step_by(97), |mutated| {
        let _ = detect_payload(mutated, &ClassifierOptions::new());
    });
}

#[test]
fn mkfs_ubifs_image_lists_the_fixture_tree() {
    let data = fixture("mtd/rootfs-lzo.ubifs");
    assert_eq!(mtd_layout(&data), Some(mtd::Layout::Ubifs));
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(has_note(
        &p,
        "UBIFS format version 4; LEB size 15 KiB, minimum I/O unit 512 B"
    ));
    assert!(has_note(
        &p,
        "6 regular files, 5 directories, 1 other entries"
    ));
    assert!(!has_note(&p, "scanning stopped"), "{:?}", notes(&p));
    assert_eq!(children(&data), fixture_tree());
}

// ---------------------------------------------------------------------------
// UBI

const UBI_EC_HDR_MAGIC: &[u8; 4] = b"UBI#";
const UBI_VID_HDR_MAGIC: &[u8; 4] = b"UBI!";
const UBI_VERSION: u8 = 1;
const UBI_VID_DYNAMIC: u8 = 1;
const UBI_VID_STATIC: u8 = 2;
const UBI_LAYOUT_VOLUME_ID: u32 = 0x7FFF_EFFF;
const UBI_COMPAT_REJECT: u8 = 5;
const UBI_HDR_SIZE_CRC: usize = 60;
const UBI_VTBL_RECORD_SIZE: usize = 172;
const UBI_VTBL_RECORD_SIZE_CRC: usize = 168;
const UBI_MAX_VOLUMES: usize = 128;

/// One volume-identifier header.
#[derive(Clone, Copy)]
struct Vid {
    vol_type: u8,
    copy_flag: u8,
    compat: u8,
    vol_id: u32,
    lnum: u32,
    data_size: u32,
    used_ebs: u32,
    data_crc: u32,
    sqnum: u64,
}

/// A dynamic-volume VID header for `lnum` of `vol_id`.
fn dynamic_vid(vol_id: u32, lnum: u32, sqnum: u64) -> Vid {
    Vid {
        vol_type: UBI_VID_DYNAMIC,
        copy_flag: 0,
        compat: 0,
        vol_id,
        lnum,
        data_size: 0,
        used_ebs: 0,
        data_crc: 0,
        sqnum,
    }
}

/// A UBI image: PEBs of `peb_size` bytes, each with an erase-counter
/// header, a VID header at `vid_hdr_offset` and LEB data at `data_offset`.
struct Ubi {
    peb_size: usize,
    vid_hdr_offset: usize,
    data_offset: usize,
    image_seq: u32,
    pebs: Vec<Vec<u8>>,
    sqnum: u64,
}

impl Ubi {
    fn new(peb_size: usize, vid_hdr_offset: usize, data_offset: usize) -> Self {
        Self {
            peb_size,
            vid_hdr_offset,
            data_offset,
            image_seq: 0x1234_5678,
            pebs: Vec::new(),
            sqnum: 0,
        }
    }

    fn leb_size(&self) -> usize {
        self.peb_size - self.data_offset
    }

    /// Erase-counter header: magic `UBI#`, version 1, padding, erase
    /// counter 3 (8), VID header offset (16), data offset (20), image
    /// sequence (24), padding, CRC over 60 bytes (60).
    fn ec_header(&self) -> Vec<u8> {
        let mut header = UBI_EC_HDR_MAGIC.to_vec();
        header.extend([UBI_VERSION, 0, 0, 0]);
        header.extend(3u64.to_be_bytes());
        header.extend((self.vid_hdr_offset as u32).to_be_bytes());
        header.extend((self.data_offset as u32).to_be_bytes());
        header.extend(self.image_seq.to_be_bytes());
        header.resize(UBI_HDR_SIZE_CRC, 0);
        let crc = crc_ones(&header);
        header.extend(crc.to_be_bytes());
        header
    }

    /// VID header: magic `UBI!`, version 1, volume type (5), copy flag (6),
    /// compat (7), volume ID (8), LEB number (12), padding, data size (20),
    /// used LEBs (24), data padding 0 (28), data CRC (32), padding,
    /// sequence number (40), padding, CRC over 60 bytes (60).
    fn vid_header(vid: &Vid) -> Vec<u8> {
        let mut header = UBI_VID_HDR_MAGIC.to_vec();
        header.extend([UBI_VERSION, vid.vol_type, vid.copy_flag, vid.compat]);
        header.extend(vid.vol_id.to_be_bytes());
        header.extend(vid.lnum.to_be_bytes());
        header.extend([0; 4]);
        header.extend(vid.data_size.to_be_bytes());
        header.extend(vid.used_ebs.to_be_bytes());
        header.extend([0; 4]);
        header.extend(vid.data_crc.to_be_bytes());
        header.extend([0; 4]);
        header.extend(vid.sqnum.to_be_bytes());
        header.resize(UBI_HDR_SIZE_CRC, 0);
        let crc = crc_ones(&header);
        header.extend(crc.to_be_bytes());
        header
    }

    /// Append a PEB: the erase-counter header, an optional VID header and
    /// LEB data; the rest is erased. Returns the PEB's file offset.
    fn peb(&mut self, vid: Option<Vid>, leb: &[u8]) -> usize {
        let mut peb = vec![0xffu8; self.peb_size];
        peb[..64].copy_from_slice(&self.ec_header());
        if let Some(vid) = vid {
            let at = self.vid_hdr_offset;
            peb[at..at + 64].copy_from_slice(&Self::vid_header(&vid));
        }
        peb[self.data_offset..self.data_offset + leb.len()].copy_from_slice(leb);
        self.pebs.push(peb);
        (self.pebs.len() - 1) * self.peb_size
    }

    fn next_sqnum(&mut self) -> u64 {
        self.sqnum += 1;
        self.sqnum
    }

    /// Volume table record: reserved PEBs, alignment 1, data padding 0,
    /// volume type (12), update marker (13), name length (14), name (16),
    /// flags (144), padding, CRC over 168 bytes (168).
    fn record(reserved_pebs: u32, vol_type: u8, upd_marker: u8, name: &str) -> Vec<u8> {
        let mut record = reserved_pebs.to_be_bytes().to_vec();
        record.extend(1u32.to_be_bytes());
        record.extend(0u32.to_be_bytes());
        record.extend([vol_type, upd_marker]);
        record.extend((name.len() as u16).to_be_bytes());
        record.extend_from_slice(name.as_bytes());
        record.resize(UBI_VTBL_RECORD_SIZE_CRC, 0);
        let crc = crc_ones(&record);
        record.extend(crc.to_be_bytes());
        record
    }

    /// An unused volume table slot: all zero, with the CRC of the zeros.
    fn empty_record() -> Vec<u8> {
        let mut record = vec![0u8; UBI_VTBL_RECORD_SIZE_CRC];
        let crc = crc_ones(&record);
        record.extend(crc.to_be_bytes());
        record
    }

    /// The two layout-volume PEBs, each a copy of the volume table: one
    /// record per slot.
    fn layout_volume(&mut self, records: &[Vec<u8>]) {
        let slots = (self.leb_size() / UBI_VTBL_RECORD_SIZE).min(UBI_MAX_VOLUMES);
        let mut table = Vec::new();
        for slot in 0..slots {
            match records.get(slot) {
                Some(record) => table.extend_from_slice(record),
                None => table.extend(Self::empty_record()),
            }
        }
        for lnum in 0..2 {
            let vid = Vid {
                compat: UBI_COMPAT_REJECT,
                ..dynamic_vid(UBI_LAYOUT_VOLUME_ID, lnum, self.next_sqnum())
            };
            self.peb(Some(vid), &table);
        }
    }

    /// The LEBs of a static volume, `order` giving the LEB number of each
    /// PEB in flash order. Each LEB carries its data size and data CRC.
    fn static_volume(&mut self, vol_id: u32, contents: &[u8], order: &[usize]) {
        let chunks: Vec<&[u8]> = contents.chunks(self.leb_size()).collect();
        for &lnum in order {
            let chunk = chunks[lnum];
            let vid = Vid {
                vol_type: UBI_VID_STATIC,
                copy_flag: 0,
                compat: 0,
                vol_id,
                lnum: lnum as u32,
                data_size: chunk.len() as u32,
                used_ebs: chunks.len() as u32,
                data_crc: crc_ones(chunk),
                sqnum: self.next_sqnum(),
            };
            self.peb(Some(vid), chunk);
        }
    }

    /// One LEB of a dynamic volume.
    fn dynamic_leb(&mut self, vol_id: u32, lnum: u32, leb: &[u8]) -> usize {
        let vid = dynamic_vid(vol_id, lnum, self.next_sqnum());
        self.peb(Some(vid), leb)
    }

    fn image(&self) -> Vec<u8> {
        self.pebs.concat()
    }
}

/// Volume 0 "kernel": static, an x86-64 ELF over two LEBs written in
/// reverse order. Volume 1 "rootfs": dynamic, LEBs 0 and 2 mapped (a
/// big-endian MIPS ELF at LEB 0). Volume 2 "spare": dynamic, empty. Then a
/// free PEB. Returns the builder and the expected volume contents.
fn ubi_image() -> (Ubi, Vec<u8>, Vec<u8>) {
    let mut ubi = Ubi::new(4096, 64, 128);
    let leb = ubi.leb_size();
    let mut kernel = elf(2, false, EM_X86_64);
    kernel.extend(filler(leb + 300 - 64, 6));
    let mut rootfs_0 = elf(1, true, EM_MIPS);
    rootfs_0.extend(filler(leb - 64, 7));
    let rootfs_2 = filler(leb, 8);
    let mut rootfs = rootfs_0.clone();
    rootfs.extend(vec![0xff; leb]);
    rootfs.extend_from_slice(&rootfs_2);

    ubi.layout_volume(&[
        Ubi::record(4, UBI_VID_STATIC, 0, "kernel"),
        Ubi::record(8, UBI_VID_DYNAMIC, 0, "rootfs"),
        Ubi::record(2, UBI_VID_DYNAMIC, 0, "spare"),
    ]);
    ubi.static_volume(0, &kernel, &[1, 0]);
    ubi.dynamic_leb(1, 0, &rootfs_0);
    ubi.dynamic_leb(1, 2, &rootfs_2);
    ubi.peb(None, &[]);
    (ubi, kernel, rootfs)
}

#[test]
fn ubi_static_and_dynamic_volumes_are_rebuilt_in_lnum_order() {
    let (ubi, kernel, rootfs) = ubi_image();
    let image = ubi.image();
    assert_eq!(mtd_layout(&image), Some(mtd::Layout::Ubi));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Ubi);
    assert_eq!(p.format.variant_name.as_deref(), Some("UBI image"));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(
        has_note(
            &p,
            "7 PEBs of 4 KiB; VID headers at 0x40, LEB data at 0x80; image sequence 0x12345678"
        ),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(
        &p,
        "Volume 0 \"kernel\": static, 2 of 4 reserved LEBs mapped; 4268 B; data CRC-32 verified"
    ));
    assert!(has_note(
        &p,
        "Volume 1 \"rootfs\": dynamic, 2 of 8 reserved LEBs mapped; 11904 B"
    ));
    assert!(has_note(
        &p,
        "Volume 2 \"spare\": dynamic, 2 LEBs reserved, none mapped"
    ));
    assert!(has_note(&p, "1 free PEBs, 0 erased PEBs"));
    assert_eq!(p.slices.len(), 2);
    let kernel_slice = &p.slices[0];
    assert_eq!(kernel_slice.label.as_deref(), Some("kernel"));
    // Stored range: from LEB 1's PEB (written first) to the end of LEB 0's
    // data in the next PEB.
    assert_eq!(kernel_slice.offset, 2 * 4096 + 128);
    assert_eq!(
        kernel_slice.offset + kernel_slice.size,
        3 * 4096 + 128 + 3968
    );
    let decoded = kernel_slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "UBI volume");
    assert_eq!(decoded.size, kernel.len() as u64);
    assert_eq!(p.slices[1].isa, Isa::Mips);
    assert_eq!(
        children(&image),
        vec![listed("kernel", kernel), listed("rootfs", rootfs)]
    );
}

#[test]
fn ubi_leb_copies_resolve_by_sequence_number_and_copy_crc() {
    let (mut ubi, _, rootfs) = ubi_image();
    let leb = ubi.leb_size();
    // An older copy of rootfs LEB 0 written later in flash is superseded.
    let stale = filler(leb, 9);
    let older = dynamic_vid(1, 0, 4);
    ubi.peb(Some(older), &stale);
    let image = ubi.image();
    assert_eq!(children(&image)[1], listed("rootfs", rootfs.clone()));
    let p = classify(&image);
    assert!(has_note(&p, "1 superseded LEB copies ignored"));

    // A newer wear-levelling copy whose data CRC fails loses to the older.
    let bad_copy = Vid {
        copy_flag: 1,
        data_size: leb as u32,
        data_crc: crc_ones(&stale) ^ 1,
        sqnum: 1000,
        ..older
    };
    ubi.peb(Some(bad_copy), &stale);
    assert_eq!(children(&ubi.image())[1], listed("rootfs", rootfs));
    let good_copy = Vid {
        data_crc: crc_ones(&stale),
        sqnum: 1001,
        ..bad_copy
    };
    ubi.peb(Some(good_copy), &stale);
    assert_eq!(children(&ubi.image())[1].data[..leb], stale[..]);

    let equal = Vid {
        sqnum: 1001,
        ..good_copy
    };
    ubi.peb(Some(equal), &stale);
    let e = detect_payload(&ubi.image(), &ClassifierOptions::new()).unwrap_err();
    assert!(
        e.to_string().contains("with the same sequence number"),
        "{e}"
    );
}

#[test]
fn ubi_corrupt_headers_are_skipped_and_volume_table_copies_fall_back() {
    let (ubi, _, _) = ubi_image();
    let image = ubi.image();
    // A corrupt VID header CRC in rootfs LEB 2 (PEB 5): the PEB is skipped.
    let mut bad_vid = image.clone();
    bad_vid[5 * 4096 + 64 + 20] ^= 1;
    let p = classify(&bad_vid);
    assert!(
        has_note(&p, "1 PEBs with a corrupt header skipped (first at 0x5000)"),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(
        &p,
        "Volume 1 \"rootfs\": dynamic, 1 of 8 reserved LEBs mapped"
    ));

    // Volume table copy 0 corrupt: copy 1 is used.
    let mut bad_copy = image.clone();
    bad_copy[128 + 10] ^= 1;
    let p = classify(&bad_copy);
    assert!(has_note(
        &p,
        "Volume table copy 0 is missing or corrupt; copy 1 used"
    ));
    assert_eq!(p.slices.len(), 2);
    let mut both = bad_copy.clone();
    both[4096 + 128 + 10] ^= 1;
    let e = detect_payload(&both, &ClassifierOptions::new()).unwrap_err();
    assert!(e.to_string().contains("no copy is intact"), "{e}");

    // PEB 0's erase-counter header must be valid.
    let mut bad_ec = image.clone();
    bad_ec[30] ^= 1;
    let e = detect_payload(&bad_ec, &ClassifierOptions::new()).unwrap_err();
    assert!(
        e.to_string()
            .contains("Flash filesystem parse error: Invalid UBI erase-counter header CRC-32"),
        "{e}"
    );
}

#[test]
fn ubi_image_sequence_numbers_must_agree() {
    let (mut ubi, _, _) = ubi_image();
    ubi.image_seq = 0x0BAD_5EED;
    ubi.peb(None, &[]);
    let e = detect_payload(&ubi.image(), &ClassifierOptions::new()).unwrap_err();
    assert!(
        e.to_string()
            .contains("Invalid UBI image sequence 0x0BAD5EED at 0x7000"),
        "{e}"
    );
    // An image sequence of zero (older ubiformat) matches any.
    let (mut ubi, _, _) = ubi_image();
    ubi.image_seq = 0;
    ubi.peb(None, &[]);
    assert_eq!(classify(&ubi.image()).format.format, FileFormat::Ubi);
}

#[test]
fn ubi_static_volume_faults_make_the_volume_opaque() {
    let (ubi, _, _) = ubi_image();
    let mut bad_data = ubi.image();
    bad_data[3 * 4096 + 128 + 100] ^= 1;
    let p = classify(&bad_data);
    assert!(
        has_note(&p, "data CRC-32 of LEB 0 fails; not analyzed"),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(&p, "kernel: opaque; payload ISA analysis skipped"));
    assert_eq!(
        p.primary.isa,
        Isa::Mips,
        "the dynamic volume still classifies"
    );

    let mut upd = Ubi::new(4096, 64, 128);
    upd.layout_volume(&[Ubi::record(2, UBI_VID_STATIC, 1, "partial")]);
    upd.static_volume(0, &elf(2, false, EM_X86_64), &[0]);
    let p = classify(&upd.image());
    assert!(has_note(
        &p,
        "update marker set, so the contents are incomplete"
    ));
    assert_eq!(p.primary.isa, Isa::Unknown(0));
}

#[test]
fn ubi_volume_ids_must_fit_the_volume_table() {
    let (mut ubi, _, _) = ubi_image();
    // A LEB of an unused slot is the remnant of a removed volume.
    ubi.dynamic_leb(5, 0, &filler(100, 1));
    let p = classify(&ubi.image());
    assert!(has_note(
        &p,
        "1 LEBs of volumes missing from the volume table ignored"
    ));
    // The 4 KiB PEB's table has 23 slots.
    ubi.dynamic_leb(40, 0, &filler(100, 1));
    let e = detect_payload(&ubi.image(), &ClassifierOptions::new()).unwrap_err();
    assert!(e.to_string().contains("Invalid UBI volume ID 40"), "{e}");
}

#[test]
fn ubi_empty_device_has_no_volumes() {
    let mut ubi = Ubi::new(4096, 64, 128);
    for _ in 0..3 {
        ubi.peb(None, &[]);
    }
    let p = classify(&ubi.image());
    assert_eq!(p.format.format, FileFormat::Ubi);
    assert!(has_note(&p, "No volumes: the UBI device is empty"));
    assert!(p.slices.is_empty());
    assert_eq!(p.primary.isa, Isa::Unknown(0));
}

#[test]
fn ubi_nand_dump_with_spare_areas_parses_after_spare_removal() {
    // Small-page NAND: 512-byte pages with 16 spare bytes, 16 KiB blocks,
    // VID headers in the second page.
    let mut ubi = Ubi::new(16384, 512, 1024);
    ubi.layout_volume(&[Ubi::record(2, UBI_VID_STATIC, 0, "kernel")]);
    let mut kernel = elf(2, false, EM_X86_64);
    kernel.extend(filler(2000, 3));
    ubi.static_volume(0, &kernel, &[0]);
    let image = ubi.image();
    let mut dump = Vec::new();
    for page in image.chunks(512) {
        dump.extend_from_slice(page);
        dump.extend_from_slice(&[0xff; 16]);
    }
    let p = classify(&dump);
    assert_eq!(p.format.format, FileFormat::Ubi);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(
        has_note(&p, "Parsed after NAND spare removal (512+16 B pages)"),
        "{:?}",
        notes(&p)
    );
    // Without transforms the stored dump does not parse.
    assert!(detect_payload(&dump, &ClassifierOptions::fast()).is_err());
}

#[test]
fn ubi_prefixes_error_or_lose_the_last_volume() {
    let (ubi, kernel, _) = ubi_image();
    let image = ubi.image();
    for end in 0..image.len() {
        let Ok(c) = mtd::parse_container(&image[..end], mtd::Layout::Ubi) else {
            continue;
        };
        assert_eq!(end % 4096, 0, "only whole PEBs parse (prefix of {end} B)");
        let complete = c
            .children
            .iter()
            .any(|ch| ch.label == "kernel" && !ch.opaque && ch.data.as_ref() == kernel.as_slice());
        assert_eq!(complete, end >= 4 * 4096, "prefix of {end} B");
    }
}

#[test]
fn ubi_mutations_never_panic() {
    let (ubi, _, _) = ubi_image();
    let image = ubi.image();
    let positions = (0..image.len()).filter(|at| at % 4096 < 600);
    for_each_mutation(&image, positions, |mutated| {
        let _ = mtd::parse_container(mutated, mtd::Layout::Ubi);
    });
    for_each_mutation(&image, (0..image.len()).step_by(61), |mutated| {
        let _ = detect_payload(mutated, &ClassifierOptions::new());
    });
}

#[test]
fn ubinize_image_holds_a_ubifs_volume_and_a_static_volume() {
    let data = fixture("mtd/image.ubi");
    assert_eq!(mtd_layout(&data), Some(mtd::Layout::Ubi));
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(
        has_note(
            &p,
            "18 PEBs of 16 KiB; VID headers at 0x200, LEB data at 0x400; image sequence 0x5A524448"
        ),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(&p, "rootfs: x86_64 (contained UBIFS)"));
    assert!(has_note(&p, "kernel: x86_64 (contained ELF)"));
    assert!(has_note(
        &p,
        "Volume 2 \"data\": dynamic, 5 LEBs reserved, none mapped"
    ));
    let volumes = children(&data);
    assert_eq!(volumes.len(), 2);
    let mut kernel = fixture("compressed/payload.elf");
    for _ in 0..6 {
        kernel.extend(fixture("transforms/aarch64.text.bin"));
    }
    assert_eq!(volumes[1], listed("kernel", kernel));
    // The rootfs volume is the zstd UBIFS image; its files are the tree.
    let rootfs = &volumes[0].data;
    assert_eq!(volumes[0].label, "rootfs");
    assert_eq!(mtd_layout(rootfs), Some(mtd::Layout::Ubifs));
    assert_eq!(children(rootfs), fixture_tree());
    let inner = classify(rootfs);
    assert!(has_note(&inner, "default compression Zstandard"));
}

#[test]
fn ubinize_image_mutations_never_panic() {
    let data = fixture("mtd/image.ubi");
    // Headers of every PEB and the start of each LEB.
    let positions =
        (0..data.len()).filter(|at| at % 16384 < 64 || (512..576).contains(&(at % 16384)));
    for_each_mutation(&data, positions, |mutated| {
        let _ = mtd::parse_container(mutated, mtd::Layout::Ubi);
    });
}
