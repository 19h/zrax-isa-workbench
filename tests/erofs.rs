//! EROFS images: mkfs.erofs fixtures (flat, chunk-based, LZ4 with big
//! pclusters and tail packing, LZ4 with full indexes, DEFLATE, MicroLZMA
//! fragments) whose members must decode to the bytes of the source tree,
//! synthetic images built from the `erofs_fs.h` layouts for cycles, hard
//! links, extended inodes, holes and deep trees, superblock and member
//! damage, an Android sparse image of an EROFS partition, and truncation
//! and mutation sweeps.

use zrax::formats::checksum::crc32c_update;
use zrax::formats::container::{self, Child, Container, Kind};
use zrax::formats::erofs::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(image: &[u8]) -> Container<'_> {
    container::parse(image, Kind::Erofs(Layout::Erofs)).expect("parses")
}

fn parse_error(image: &[u8]) -> String {
    container::parse(image, Kind::Erofs(Layout::Erofs))
        .expect_err("is a parse error")
        .to_string()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("member {label} in {:?}", labels(c)))
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|n| n.contains(text))
}

fn notes(c: &Container<'_>) -> String {
    c.notes.join("\n")
}

fn le_u16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn le_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn le_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// The fixture tree (tests/fixtures/erofs/README.md)
// ---------------------------------------------------------------------------

/// The fixture images and the transform each reports for `/lib/big.elf`
/// (`None` when it is stored contiguously).
const IMAGES: [(&str, Option<&str>); 6] = [
    ("erofs/plain.img", Some("EROFS tail packing")),
    ("erofs/chunk.img", None),
    ("erofs/lz4.img", Some("EROFS LZ4")),
    ("erofs/lz4-full.img", Some("EROFS LZ4")),
    ("erofs/deflate.img", Some("EROFS DEFLATE")),
    ("erofs/lzma-fragments.img", Some("EROFS fragment")),
];

/// The recognized members, in walk order.
const MEMBERS: [&str; 4] = [
    "/payload.elf",
    "/boot/payload.elf.gz",
    "/lib/big.elf",
    "/lib/mixed.elf",
];

/// The fixture UUID (`mkfs.erofs -U`).
const UUID: &str = "5a524158-6572-6f66-8000-000000000000";

/// `x(n+1) = (x(n) * 1103515245 + 12345) mod 2^31`; each byte is bits
/// 16-23 of `x(n+1)` (the generator's Perl one-liner).
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = (x * 1_103_515_245 + 12345) % 2_147_483_648;
            u8::try_from((x >> 16) & 0xff).unwrap()
        })
        .collect()
}

/// The bytes of a member of the fixture tree, rebuilt from the generator's
/// description.
fn source(path: &str) -> Vec<u8> {
    let elf = fixture("compressed/payload.elf");
    match path {
        "/payload.elf" => elf,
        "/boot/payload.elf.gz" => fixture("compressed/payload.elf.gz"),
        "/lib/big.elf" => {
            let mut data = elf;
            for i in 0..1000 {
                data.extend_from_slice(format!("zrax erofs filler line {i:03}\n").as_bytes());
            }
            data
        }
        "/lib/mixed.elf" => {
            let mut data = elf;
            data.extend(noise(1, 8192));
            for i in 0..600 {
                data.extend_from_slice(format!("mixed text line {i:03}\n").as_bytes());
            }
            data.extend(noise(7, 4096));
            data
        }
        other => panic!("no source for {other}"),
    }
}

/// Superblock fields at file offset 1024: `checksum` (4),
/// `feature_compat` (8), `blkszbits` (12), `root_nid` (14), `blocks` (36),
/// `meta_blkaddr` (40), `volume_name` (64), `feature_incompat` (80),
/// `dirblkbits` (90).
const SB: usize = 1024;

/// Recompute the superblock checksum as `erofs_superblock_csum_verify`
/// does: CRC32C (seed `~0`, no final inversion) of bytes 1024..4096 with
/// the checksum field zeroed.
fn resum(image: &mut [u8]) {
    put32(image, SB + 4, 0);
    let crc = crc32c_update(!0, &image[SB..4096]);
    put32(image, SB + 4, crc);
}

/// File offset of inode `nid`: `meta_blkaddr * 4096 + nid * 32`.
fn inode_offset(image: &[u8], nid: u64) -> usize {
    let meta = u64::from(le_u32(image, SB + 40));
    usize::try_from(meta * 4096 + nid * 32).unwrap()
}

/// The entries of an uncompressed directory, read from the documented
/// layout: a flat-plain (layout 0) directory's data at `raw_blkaddr`
/// (`i_u`, 16), or a flat-inline (layout 2) one-block directory's data
/// after the 32-byte compact inode and its inline xattrs (`i_xattr_icount`,
/// 2). Each block holds 12-byte dirents (`nid` u64, `nameoff` u16) then
/// the names.
fn dirents(image: &[u8], nid: u64) -> Vec<(String, u64)> {
    let (data_at, size) = dir_data(image, nid);
    let block = &image[data_at..data_at + size];
    let count = usize::from(le_u16(block, 8)) / 12;
    (0..count)
        .map(|k| {
            let start = usize::from(le_u16(block, k * 12 + 8));
            let end = if k + 1 < count {
                usize::from(le_u16(block, (k + 1) * 12 + 8))
            } else {
                block[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(size, |n| start + n)
            };
            let name = String::from_utf8(block[start..end].to_vec()).unwrap();
            (name, le_u64(block, k * 12))
        })
        .collect()
}

/// File offset and size of the data of an uncompressed one-block
/// directory, as [`dirents`] describes it.
fn dir_data(image: &[u8], nid: u64) -> (usize, usize) {
    let at = inode_offset(image, nid);
    let format = le_u16(image, at);
    let size = le_u32(image, at + 8) as usize;
    let icount = le_u16(image, at + 2);
    let xattrs = if icount == 0 {
        0
    } else {
        12 + 4 * (usize::from(icount) - 1)
    };
    let data_at = match (format >> 1) & 7 {
        0 => le_u32(image, at + 16) as usize * 4096,
        2 if size < 4096 => at + 32 + xattrs,
        other => panic!("directory layout {other}"),
    };
    (data_at, size)
}

/// The nid of `name` in directory `nid`.
fn lookup(image: &[u8], nid: u64, name: &str) -> u64 {
    dirents(image, nid)
        .into_iter()
        .find(|(entry, _)| entry == name)
        .unwrap_or_else(|| panic!("{name} in nid {nid}"))
        .1
}

fn root_nid(image: &[u8]) -> u64 {
    u64::from(le_u16(image, SB + 14))
}

// ---------------------------------------------------------------------------
// mkfs.erofs fixtures
// ---------------------------------------------------------------------------

#[test]
fn mkfs_images_list_their_recognized_members_and_take_the_isa_from_them() {
    for (name, _) in IMAGES {
        let image = fixture(name);
        assert_eq!(erofs::detect(&image), Some(Layout::Erofs), "{name}");
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::Erofs, "{name}");
        assert_eq!(p.format.variant_name.as_deref(), Some("EROFS"), "{name}");
        assert_eq!(p.primary.isa, Isa::X86_64, "{name}");
        let slices: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
        assert_eq!(slices, MEMBERS, "{name}");
        assert!(p.slices.iter().all(|s| s.isa == Isa::X86_64), "{name}");
    }
}

#[test]
fn members_decode_to_the_source_tree_in_every_layout() {
    for (name, transform) in IMAGES {
        let image = fixture(name);
        let c = parse(&image);
        assert_eq!(labels(&c), MEMBERS, "{name}");
        for path in MEMBERS {
            assert_eq!(
                &child(&c, path).data[..],
                &source(path)[..],
                "{name}: {path}"
            );
        }
        assert_eq!(child(&c, "/lib/big.elf").transform, transform, "{name}");
        assert!(
            has_note(&c, "Directory walk: 4 directories, 5 regular files"),
            "{name}: {}",
            notes(&c)
        );
        assert!(has_note(&c, "members in a recognized format: 4"), "{name}");
        assert_eq!(c.consumed, image.len(), "{name}");
    }
}

#[test]
fn stored_offsets_locate_the_member_bytes_or_their_pcluster() {
    let plain = fixture("erofs/plain.img");
    let c = parse(&plain);
    let elf = child(&c, "/payload.elf");
    assert_eq!(elf.transform, None);
    assert_eq!(
        &plain[elf.offset..elf.offset + elf.stored_size],
        &source("/payload.elf")[..]
    );
    // Six whole blocks at the start of the file's data, then a tail after
    // the inode.
    let big = child(&c, "/lib/big.elf");
    assert_eq!(big.stored_size, 6 * 4096);
    assert_eq!(
        &plain[big.offset..big.offset + big.stored_size],
        &source("/lib/big.elf")[..6 * 4096]
    );

    let lz4 = fixture("erofs/lz4.img");
    let c = parse(&lz4);
    let big = child(&c, "/lib/big.elf");
    // The first extent's big pcluster: whole blocks, block aligned.
    assert_eq!((big.offset % 4096, big.stored_size % 4096), (0, 0));
    assert!(
        big.stored_size > 4096,
        "a big pcluster: {}",
        big.stored_size
    );
    // A tail-packed file: its pcluster follows its inode, inside a block.
    let elf = child(&c, "/payload.elf");
    assert_eq!(elf.transform, Some("EROFS LZ4"));
    assert!(elf.stored_size < 256);
    assert!(elf.offset % 4096 + elf.stored_size <= 4096);
}

#[test]
fn notes_and_metadata_describe_the_superblock_and_the_walk() {
    let image = fixture("erofs/lz4.img");
    let c = parse(&image);
    assert!(
        has_note(&c, "EROFS filesystem: 7 blocks of 4 KiB"),
        "{}",
        notes(&c)
    );
    assert!(has_note(&c, "Superblock checksum verified (CRC32C)"));
    assert!(has_note(&c, "Compression algorithms: LZ4"));
    assert!(has_note(&c, "the format names no CPU"));
    let p = classify(&image);
    let metadata = |key: &str| {
        p.metadata
            .iter()
            .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
            .map(|m| m.value.to_string())
            .unwrap_or_else(|| panic!("metadata {key}"))
    };
    assert_eq!(metadata("erofs_block_size"), "4096");
    assert_eq!(metadata("erofs_uuid"), UUID);
    assert_eq!(metadata("erofs_member_count"), "4");
    assert_eq!(metadata("erofs_compressed_file_count"), "3");
    assert!(metadata("erofs_incompat_features").contains("ztailpacking"));
    assert!(metadata("erofs_component_2").contains("decoded (EROFS LZ4)"));
}

#[test]
fn superblock_damage_is_a_parse_error() {
    let image = fixture("erofs/plain.img");
    let mut checksum = image.clone();
    checksum[SB + 4] ^= 1;
    assert!(parse_error(&checksum).contains("EROFS parse error: Invalid superblock checksum"));

    let mut incompat = image.clone();
    put32(&mut incompat, SB + 80, 0x80);
    resum(&mut incompat);
    assert!(parse_error(&incompat).contains("Unsupported incompatible features 0x80"));

    let mut dirblkbits = image.clone();
    dirblkbits[SB + 90] = 1;
    resum(&mut dirblkbits);
    assert!(parse_error(&dirblkbits).contains("Unsupported dirblkbits 1"));

    let mut name = image.clone();
    name[SB + 64..SB + 80].fill(b'z');
    resum(&mut name);
    assert!(parse_error(&name).contains("Invalid volume name: no NUL terminator"));

    let mut blocks = image.clone();
    put32(&mut blocks, SB + 36, 15);
    resum(&mut blocks);
    assert!(parse_error(&blocks).contains("Truncated filesystem: 15 blocks of 4 KiB"));

    let mut block_size = image.clone();
    block_size[SB + 12] = 8;
    assert_eq!(erofs::detect(&block_size), None);
    assert!(parse_error(&block_size).contains("Unsupported block size: blkszbits 8"));

    let mut trailing = image.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing).contains("Invalid trailing data: 4 B after the filesystem"));
    let mut padded = image.clone();
    padded.resize(image.len() + 4096, 0xff);
    assert_eq!(labels(&parse(&padded)), MEMBERS);

    let mut root = image.clone();
    let payload_nid = lookup(&image, root_nid(&image), "payload.elf");
    put16(&mut root, SB + 14, u16::try_from(payload_nid).unwrap());
    resum(&mut root);
    assert!(parse_error(&root).contains(&format!("Invalid root inode {payload_nid}")));
}

/// Append the hashtree placeholder, a vbmeta placeholder and the 64-byte
/// `AvbFooter` (big-endian: magic `AVBf`, version 1.0, original image
/// size, vbmeta offset and size) that `avbtool add_hashtree_footer` puts
/// after a filesystem.
fn with_avb_footer(mut image: Vec<u8>) -> Vec<u8> {
    let original = image.len() as u64;
    image.extend(vec![0x5a; 4096]);
    let vbmeta_offset = image.len() as u64;
    image.extend_from_slice(b"AVB0");
    image.resize(image.len() + 252, 0);
    image.resize(image.len() + 4096 - 64 - 256, 0);
    let mut footer = vec![0u8; 64];
    footer[..4].copy_from_slice(b"AVBf");
    footer[4..8].copy_from_slice(&1u32.to_be_bytes());
    footer[12..20].copy_from_slice(&original.to_be_bytes());
    footer[20..28].copy_from_slice(&vbmeta_offset.to_be_bytes());
    footer[28..36].copy_from_slice(&256u64.to_be_bytes());
    image.extend_from_slice(&footer);
    image
}

#[test]
fn an_avb_footer_after_the_filesystem_is_noted() {
    let image = with_avb_footer(fixture("erofs/plain.img"));
    let c = parse(&image);
    assert_eq!(labels(&c), MEMBERS);
    assert_eq!(c.consumed, 57344);
    assert!(
        has_note(
            &c,
            "AVB footer: 8 KiB after the filesystem (original image size 57344 B)"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(&c, "hashtree and signatures not verified"));
}

#[test]
fn damage_below_the_root_skips_the_member_with_a_note() {
    let image = fixture("erofs/plain.img");
    let root = root_nid(&image);
    let mut format = image.clone();
    let payload = inode_offset(&image, lookup(&image, root, "payload.elf"));
    put16(&mut format, payload, 0x0010);
    // Block 0 holds the inodes too, so the superblock checksum covers them.
    resum(&mut format);
    let c = parse(&format);
    assert!(
        has_note(&c, "Skipped /payload.elf: Unsupported i_format 0x10"),
        "{}",
        notes(&c)
    );
    assert_eq!(labels(&c), &MEMBERS[1..]);

    // A directory whose first nameoff points into its dirents.
    let mut directory = image.clone();
    let (data_at, _) = dir_data(&image, lookup(&image, root, "lib"));
    put16(&mut directory, data_at + 8, 4);
    resum(&mut directory);
    let c = parse(&directory);
    assert!(
        has_note(
            &c,
            "Skipped the rest of /lib from directory block 0: invalid de[0].nameoff 4"
        ),
        "{}",
        notes(&c)
    );
    assert_eq!(labels(&c), &MEMBERS[..2]);

    // A compressed pcluster that does not decode.
    let lz4 = fixture("erofs/lz4.img");
    let big = parse(&lz4).children[2].offset;
    let mut pcluster = lz4.clone();
    pcluster[big..big + 4096].fill(0xa5);
    let c = parse(&pcluster);
    assert!(
        c.notes
            .iter()
            .any(|n| n.starts_with("Skipped /lib/big.elf: Invalid LZ4 extent at 0x0")),
        "{}",
        notes(&c)
    );
}

#[test]
fn every_prefix_of_a_fixture_is_an_error() {
    for (name, _) in IMAGES {
        let image = fixture(name);
        for end in 0..image.len() {
            assert!(
                container::parse(&image[..end], Kind::Erofs(Layout::Erofs)).is_err(),
                "{name}: prefix {end}"
            );
        }
    }
}

/// Every byte of the first three blocks (superblock, inodes, directories,
/// indexes and tail-packed data) and every 61st byte after them.
fn mutation_positions(len: usize) -> impl Iterator<Item = usize> {
    (0..len).filter(|&i| i < 3 * 4096 || i % 61 == 0)
}

#[test]
fn fixture_mutations_never_panic() {
    let options = ClassifierOptions::new();
    for (name, _) in IMAGES {
        let image = fixture(name);
        for i in mutation_positions(image.len()) {
            for value in [0x00, 0xff, image[i] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[i] = value;
                let _ = container::parse(&mutated, Kind::Erofs(Layout::Erofs));
                // The superblock checksum covers block 0; with it fixed the
                // mutation reaches the inodes and directories stored there.
                let checksum = SB + 4..SB + 8;
                if (SB..4096).contains(&i) && !checksum.contains(&i) {
                    resum(&mut mutated);
                    let _ = container::parse(&mutated, Kind::Erofs(Layout::Erofs));
                }
                if i % 97 == 0 {
                    let _ = detect_payload(&mutated, &options);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Synthetic images (erofs_fs.h layouts)
// ---------------------------------------------------------------------------

const BLOCK: usize = 4096;

/// `i_mode` file types.
const S_IFDIR: u16 = 0o040_755;
const S_IFREG: u16 = 0o100_644;

/// Dirent `file_type` values (`EROFS_FT_REG_FILE`, `EROFS_FT_DIR`).
const FT_REG_FILE: u8 = 1;
const FT_DIR: u8 = 2;

/// `feature_compat` `SB_CHKSUM` and `feature_incompat` `CHUNKED_FILE`.
const COMPAT_SB_CHKSUM: u32 = 1;
const INCOMPAT_CHUNKED_FILE: u32 = 4;

/// An inode of a synthetic image.
enum Node<'a> {
    /// A directory with `(name, nid, file_type)` entries, in this order.
    Dir(Vec<(String, u64, u8)>),
    /// A flat-plain file in a compact inode.
    File(&'a [u8]),
    /// A flat-plain file in a 64-byte extended inode.
    Extended(&'a [u8]),
    /// A chunk-based file of one-block chunks with a 4-byte block map
    /// (`i_u.c.format` 0) after the inode; `None` is a hole
    /// (`EROFS_NULL_ADDR`). The map takes the slots after the inode.
    Chunks(Vec<Option<&'a [u8]>>),
}

/// A synthetic image of 4 KiB blocks: the superblock at 1024 in block 0,
/// inodes from block 1 (`meta_blkaddr` 1, 32-byte slots, `inode_blocks`
/// blocks), then every inode's data in whole blocks.
///
/// Compact inode: `i_format` (0: bit 0 version, bits 1-3 layout),
/// `i_xattr_icount` (2), `i_mode` (4), `i_nlink` (6), `i_size` u32 (8),
/// `i_u` (16: `raw_blkaddr` or the chunk format), `i_ino` (20). Extended
/// inode: the same first fields with `i_size` u64 at 8 and `i_nlink` u32
/// at 44. Superblock: magic, checksum, `feature_compat` `sb_csum`,
/// `blkszbits` 12, `root_nid`, `inos`, `blocks`, `meta_blkaddr` 1, UUID,
/// volume name `zrax`, `feature_incompat`.
fn synthetic(nodes: &[(u64, Node<'_>)], root: u64, inode_blocks: usize) -> Vec<u8> {
    let mut image = vec![0u8; (1 + inode_blocks) * BLOCK];
    let mut incompat = 0;
    for (nid, node) in nodes {
        let at = BLOCK + usize::try_from(*nid).unwrap() * 32;
        let (format, mode, data): (u16, u16, Vec<u8>) = match node {
            Node::Dir(entries) => (0, S_IFDIR, dir_block(entries)),
            Node::File(bytes) => (0, S_IFREG, bytes.to_vec()),
            Node::Extended(bytes) => (1, S_IFREG, bytes.to_vec()),
            Node::Chunks(chunks) => {
                incompat |= INCOMPAT_CHUNKED_FILE;
                let size = chunks.len() * BLOCK;
                put16(&mut image, at, 4 << 1);
                put16(&mut image, at + 4, S_IFREG);
                put32(&mut image, at + 8, u32::try_from(size).unwrap());
                put32(&mut image, at + 16, 0);
                for (k, chunk) in chunks.iter().enumerate() {
                    let address = match chunk {
                        Some(bytes) => {
                            let block = image.len() / BLOCK;
                            image.extend_from_slice(bytes);
                            pad_to_block(&mut image);
                            u32::try_from(block).unwrap()
                        }
                        None => u32::MAX,
                    };
                    put32(&mut image, at + 32 + 4 * k, address);
                }
                continue;
            }
        };
        let block = image.len() / BLOCK;
        put16(&mut image, at, format);
        put16(&mut image, at + 4, mode);
        put32(&mut image, at + 16, u32::try_from(block).unwrap());
        if format & 1 == 0 {
            put16(&mut image, at + 6, 1);
            put32(&mut image, at + 8, u32::try_from(data.len()).unwrap());
        } else {
            put64(&mut image, at + 8, data.len() as u64);
            put32(&mut image, at + 44, 1);
        }
        image.extend_from_slice(&data);
        pad_to_block(&mut image);
    }
    put32(&mut image, SB, 0xe0f5_e1e2);
    put32(&mut image, SB + 8, COMPAT_SB_CHKSUM);
    image[SB + 12] = 12;
    put16(&mut image, SB + 14, u16::try_from(root).unwrap());
    put64(&mut image, SB + 16, nodes.len() as u64);
    let blocks = u32::try_from(image.len() / BLOCK).unwrap();
    put32(&mut image, SB + 36, blocks);
    put32(&mut image, SB + 40, 1);
    image[SB + 48..SB + 64].copy_from_slice(b"ZRAXerofs-synth!");
    image[SB + 64..SB + 68].copy_from_slice(b"zrax");
    put32(&mut image, SB + 80, incompat);
    resum(&mut image);
    image
}

/// Zero bytes up to the next block boundary.
fn pad_to_block(image: &mut Vec<u8>) {
    let remainder = image.len() % BLOCK;
    if remainder != 0 {
        image.resize(image.len() + BLOCK - remainder, 0);
    }
}

/// One directory block: 12-byte dirents (`nid` u64, `nameoff` u16,
/// `file_type` u8, reserved), then the names back to back. The block is as
/// long as its contents, so the last name ends at the directory size.
fn dir_block(entries: &[(String, u64, u8)]) -> Vec<u8> {
    let mut block = vec![0u8; entries.len() * 12];
    for (k, (name, nid, file_type)) in entries.iter().enumerate() {
        let nameoff = u16::try_from(block.len()).unwrap();
        put64(&mut block, k * 12, *nid);
        put16(&mut block, k * 12 + 8, nameoff);
        block[k * 12 + 10] = *file_type;
        block.extend_from_slice(name.as_bytes());
    }
    block
}

/// `(name, nid, file_type)` for a directory entry.
fn entry(name: &str, nid: u64, file_type: u8) -> (String, u64, u8) {
    (name.to_string(), nid, file_type)
}

#[test]
fn directory_cycles_and_hard_links_are_walked_once() {
    let elf = fixture("compressed/payload.elf");
    // nid 0: /, nid 2: /sub, nid 4: /a.elf; /sub/loop names / again,
    // /sub/self names /sub, and /sub/b.elf is a hard link to /a.elf.
    let image = synthetic(
        &[
            (
                0,
                Node::Dir(vec![
                    entry(".", 0, FT_DIR),
                    entry("..", 0, FT_DIR),
                    entry("a.elf", 4, FT_REG_FILE),
                    entry("sub", 2, FT_DIR),
                ]),
            ),
            (
                2,
                Node::Dir(vec![
                    entry(".", 2, FT_DIR),
                    entry("..", 0, FT_DIR),
                    entry("b.elf", 4, FT_REG_FILE),
                    entry("loop", 0, FT_DIR),
                    entry("self", 2, FT_DIR),
                ]),
            ),
            (4, Node::File(&elf)),
        ],
        0,
        1,
    );
    let c = parse(&image);
    assert_eq!(labels(&c), ["/a.elf"]);
    assert!(
        has_note(
            &c,
            "Directory walk: 2 directories, 1 regular file (0 compressed)"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "3 directory entries name an inode already visited (hard links)"
    ));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Erofs);
    assert_eq!(p.primary.isa, Isa::X86_64);
}

#[test]
fn extended_inodes_may_cross_a_block_boundary() {
    let elf = fixture("compressed/payload.elf");
    // Slot 127 is the last of block 1, so the 64-byte inode ends in block 2.
    let image = synthetic(
        &[
            (
                0,
                Node::Dir(vec![
                    entry(".", 0, FT_DIR),
                    entry("..", 0, FT_DIR),
                    entry("wide.elf", 127, FT_REG_FILE),
                ]),
            ),
            (127, Node::Extended(&elf)),
        ],
        0,
        2,
    );
    let c = parse(&image);
    assert_eq!(labels(&c), ["/wide.elf"]);
    assert_eq!(&child(&c, "/wide.elf").data[..], &elf[..]);
}

#[test]
fn chunk_holes_read_as_zeros() {
    let elf = fixture("compressed/payload.elf");
    let mut first = elf.clone();
    first.resize(BLOCK, 0x11);
    let last = vec![0x22; BLOCK];
    let image = synthetic(
        &[
            (
                0,
                Node::Dir(vec![
                    entry(".", 0, FT_DIR),
                    entry("..", 0, FT_DIR),
                    entry("holes.elf", 2, FT_REG_FILE),
                ]),
            ),
            (2, Node::Chunks(vec![Some(&first), None, Some(&last)])),
        ],
        0,
        1,
    );
    let c = parse(&image);
    let member = child(&c, "/holes.elf");
    assert_eq!(member.transform, Some("EROFS chunks"));
    assert_eq!(member.stored_size, BLOCK);
    let mut expected = first.clone();
    expected.extend(vec![0; BLOCK]);
    expected.extend(&last);
    assert_eq!(&member.data[..], &expected[..]);
}

#[test]
fn walks_stop_below_64_levels() {
    let elf = fixture("compressed/payload.elf");
    // nids 0, 2, 4, ...: 70 nested directories; the deepest holds deep.elf.
    let depth = 70u64;
    let mut nodes = Vec::new();
    for level in 0..depth {
        let nid = level * 2;
        let mut entries = vec![
            entry(".", nid, FT_DIR),
            entry("..", nid.saturating_sub(2), FT_DIR),
        ];
        if level + 1 < depth {
            entries.push(entry("d", nid + 2, FT_DIR));
        } else {
            entries.push(entry("deep.elf", nid + 2, FT_REG_FILE));
        }
        nodes.push((nid, Node::Dir(entries)));
    }
    nodes.push((depth * 2, Node::File(&elf)));
    let image = synthetic(&nodes, 0, 2);
    let c = parse(&image);
    assert_eq!(labels(&c), Vec::<String>::new());
    assert!(
        has_note(&c, "1 directory deeper than 64 levels was not walked"),
        "{}",
        notes(&c)
    );
}

// ---------------------------------------------------------------------------
// Android sparse image of an EROFS partition
// ---------------------------------------------------------------------------

/// `sparse_header_t` (little-endian): magic `0xED26FF3A`, version 1.0,
/// header sizes 28 and 12, block size 4096, total blocks, chunk count 2,
/// checksum 0; a RAW chunk (`0xCAC1`: type, reserved, output blocks, input
/// bytes with the header) holding `raw`, then a DONT_CARE chunk (`0xCAC3`)
/// of `free` blocks.
fn sparse(raw: &[u8], free: u32) -> Vec<u8> {
    let blocks = u32::try_from(raw.len() / BLOCK).unwrap();
    let mut image = vec![0u8; 28];
    put32(&mut image, 0, 0xed26_ff3a);
    put16(&mut image, 4, 1);
    put16(&mut image, 8, 28);
    put16(&mut image, 10, 12);
    put32(&mut image, 12, 4096);
    put32(&mut image, 16, blocks + free);
    put32(&mut image, 20, 2);
    let mut chunk = vec![0u8; 12];
    put16(&mut chunk, 0, 0xcac1);
    put32(&mut chunk, 4, blocks);
    put32(&mut chunk, 8, u32::try_from(12 + raw.len()).unwrap());
    image.extend_from_slice(&chunk);
    image.extend_from_slice(raw);
    let mut dont_care = vec![0u8; 12];
    put16(&mut dont_care, 0, 0xcac3);
    put32(&mut dont_care, 4, free);
    put32(&mut dont_care, 8, 12);
    image.extend_from_slice(&dont_care);
    image
}

#[test]
fn a_sparse_image_of_an_erofs_partition_is_classified_through_it() {
    let erofs = fixture("erofs/lz4.img");
    let image = sparse(&erofs, 3);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AndroidSparse);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let expanded = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("Expanded image"))
        .expect("expanded image slice");
    assert_eq!(expanded.isa, Isa::X86_64);
    let text: Vec<&str> = p.notes.iter().map(|n| n.message.as_str()).collect();
    assert!(
        text.iter().any(|n| n.contains("(contained EROFS)")),
        "{text:?}"
    );
    assert!(text
        .iter()
        .any(|n| n.contains("Primary ISA selected from Expanded image")));
}
