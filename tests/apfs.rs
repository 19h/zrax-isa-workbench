//! APFS containers: macOS fixtures (case-insensitive and case-sensitive
//! volumes, hard and symbolic links, decmpfs LZVN in the attribute's data
//! stream and the resource fork, a fragmented file, a two-level file-system
//! tree, an encrypted volume), synthetic containers built from the Apple
//! File System Reference layouts for what the fixtures do not cover
//! (checkpoint choice, plain name keys, zlib, LZFSE and stored decmpfs,
//! several volumes, sealed and snapshot volumes, the EFI jumpstart, holes,
//! damaged trees), a GPT partition holding a container, truncation and
//! mutation sweeps, and sample scans gated on environment variables.

use std::borrow::Cow;
use zrax::formats::checksum::crc32;
use zrax::formats::container::{Child, Container};
use zrax::formats::{apfs, detect_format, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// The contents of a gzip file written by `gzip -n` (RFC 1952): a 10-byte
/// header without optional fields, a DEFLATE stream and an 8-byte trailer.
fn gunzip(file: &[u8]) -> Vec<u8> {
    assert_eq!(&file[..4], &[0x1f, 0x8b, 8, 0], "gzip -n header");
    miniz_oxide::inflate::decompress_to_vec(&file[10..file.len() - 8]).expect("inflates")
}

fn apfs_img() -> Vec<u8> {
    gunzip(&fixture("apfs/apfs.img.gz"))
}

fn apfs_cs_img() -> Vec<u8> {
    gunzip(&fixture("apfs/apfs-cs.img.gz"))
}

fn encrypted_img() -> Vec<u8> {
    gunzip(&fixture("apfs/encrypted.img.gz"))
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse a container that must be valid.
fn parse(image: &[u8]) -> Container<'_> {
    let layout = apfs::detect(image).expect("detected as APFS");
    apfs::parse_container(image, layout).expect("parses")
}

/// The error text of a container that is detected but does not parse.
fn parse_error(image: &[u8]) -> String {
    let layout = apfs::detect(image).expect("detected as APFS");
    apfs::parse_container(image, layout)
        .expect_err("does not parse")
        .to_string()
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("{label} is listed: {:?}", labels(c)))
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|note| note.contains(text))
}

fn le16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(data[at..at + 2].try_into().expect("2 bytes"))
}

fn le32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn le64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    put(data, at, &value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    put(data, at, &value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Fixture members (tests/fixtures/apfs/README.md)
// ---------------------------------------------------------------------------

/// `head`, padded with repeated `text` to `size` bytes, as `generate.sh`
/// builds its members.
fn padded(head: &[u8], size: usize, text: &[u8]) -> Vec<u8> {
    let mut body = head.to_vec();
    while body.len() < size {
        body.extend_from_slice(text);
    }
    body.truncate(size);
    body
}

/// `head` followed by words picked with the linear congruential generator
/// of `generate.sh` (`state = state * 1103515245 + 12345 mod 2^31`, word
/// `(state >> 16) mod 12`), each followed by a space, cut at `size` bytes.
fn words(head: &[u8], size: usize) -> Vec<u8> {
    const VOCABULARY: [&[u8]; 12] = [
        b"zrax",
        b"synthetic",
        b"apfs",
        b"resource",
        b"fork",
        b"chunk",
        b"member",
        b"stream",
        b"extent",
        b"block",
        b"node",
        b"tree",
    ];
    let mut body = head.to_vec();
    let mut state: u64 = 1;
    while body.len() < size {
        state = (state * 1_103_515_245 + 12_345) % (1 << 31);
        body.extend_from_slice(VOCABULARY[((state >> 16) % 12) as usize]);
        body.push(b' ');
    }
    body.truncate(size);
    body
}

fn payload_elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

fn kernel_macho() -> Vec<u8> {
    fixture("apple/kernel.macho")
}

fn zrax_macho() -> Vec<u8> {
    padded(&kernel_macho(), 24 << 10, b"zrax synthetic inline member ")
}

fn large_macho() -> Vec<u8> {
    padded(
        &kernel_macho(),
        200 << 10,
        b"zrax synthetic resource fork member ",
    )
}

fn huge_macho() -> Vec<u8> {
    words(&kernel_macho(), 70 << 10)
}

fn fragmented_elf() -> Vec<u8> {
    padded(
        &payload_elf(),
        40 << 10,
        b"zrax synthetic fragmented member ",
    )
}

/// The recognized members of `apfs.img` in walk order.
const APFS_MEMBERS: [&str; 5] = [
    "/ZRAX/payload.elf",
    "/ZRAX/Applications/Zrax.app/Contents/MacOS/Zrax",
    "/ZRAX/Library/huge.macho",
    "/ZRAX/Library/large.macho",
    "/ZRAX/bin/fragmented.elf",
];

// ---------------------------------------------------------------------------
// macOS fixtures
// ---------------------------------------------------------------------------

#[test]
fn macos_containers_are_detected_by_their_superblock_before_any_other_family() {
    for image in [apfs_img(), apfs_cs_img(), encrypted_img()] {
        assert_eq!(apfs::detect(&image), Some(apfs::Layout::Container));
        assert!(
            matches!(
                detect_format(&image),
                DetectedFormat::Container {
                    kind: zrax::formats::container::Kind::Apfs(apfs::Layout::Container)
                }
            ),
            "no earlier check claims the container"
        );
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::Apfs);
        assert_eq!(p.format.variant_name.as_deref(), Some("APFS container"));
    }
    assert_eq!(apfs::Layout::Container.format(), FileFormat::Apfs);
}

#[test]
fn recognized_files_are_listed_by_volume_and_path_and_classified_on_their_own() {
    let image = apfs_img();
    let c = parse(&image);
    assert_eq!(labels(&c), APFS_MEMBERS);
    assert!(c.target.is_none(), "the container names no ISA");
    assert!(c.children.iter().all(|m| !m.opaque));
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::X86_64, "the first member decides");
    let isa = |label: &str| {
        p.slices
            .iter()
            .find(|s| s.label.as_deref() == Some(label))
            .unwrap_or_else(|| panic!("{label} has a slice"))
            .isa
    };
    assert_eq!(isa("/ZRAX/payload.elf"), Isa::X86_64);
    assert_eq!(isa("/ZRAX/bin/fragmented.elf"), Isa::X86_64);
    for label in &APFS_MEMBERS[1..4] {
        assert_eq!(isa(label), Isa::AArch64, "{label}");
    }
    assert_eq!(
        p.slices.len(),
        APFS_MEMBERS.len(),
        "text files are not listed"
    );
}

#[test]
fn stored_members_keep_their_file_offsets_and_reassembled_ones_their_first_extent() {
    let image = apfs_img();
    let c = parse(&image);
    let elf = child(&c, "/ZRAX/payload.elf");
    assert!(matches!(elf.data, Cow::Borrowed(_)), "one extent: stored");
    assert_eq!(elf.transform, None);
    assert_eq!(
        &image[elf.offset..elf.offset + elf.stored_size],
        &payload_elf()[..]
    );
    assert_eq!(elf.offset % 4096, 0, "a block start");

    let fragmented = child(&c, "/ZRAX/bin/fragmented.elf");
    assert_eq!(fragmented.transform, Some("APFS extents"));
    assert_eq!(&fragmented.data[..], &fragmented_elf()[..]);
    assert_eq!(
        fragmented.stored_size, 4096,
        "the first of ten one-block extents"
    );
    assert_eq!(
        &image[fragmented.offset..fragmented.offset + 4096],
        &fragmented_elf()[..4096]
    );
}

#[test]
fn decmpfs_files_decode_from_attribute_streams_and_resource_forks() {
    let image = apfs_img();
    let c = parse(&image);
    let zrax = child(&c, "/ZRAX/Applications/Zrax.app/Contents/MacOS/Zrax");
    assert_eq!(zrax.transform, Some("decmpfs LZVN"));
    assert_eq!(&zrax.data[..], &zrax_macho()[..]);
    // The com.apple.decmpfs attribute is a 300-byte data stream: the
    // compressed bytes follow its 16-byte header.
    assert_eq!(zrax.stored_size, 300 - 16);
    assert_eq!(&image[zrax.offset - 16..zrax.offset - 12], b"fpmc");
    assert_eq!(
        le32(&image, zrax.offset - 12),
        7,
        "type 7: LZVN in the attribute"
    );

    let large = child(&c, "/ZRAX/Library/large.macho");
    assert_eq!(large.transform, Some("decmpfs LZVN"));
    assert_eq!(&large.data[..], &large_macho()[..]);
    assert_eq!(large.stored_size, 1799, "the resource fork stream");
    assert_eq!(
        le32(&image, large.offset),
        4 * 5,
        "an offset table for four chunks"
    );

    let huge = child(&c, "/ZRAX/Library/huge.macho");
    assert_eq!(&huge.data[..], &huge_macho()[..]);
    assert_eq!(huge.stored_size, 17_032);
    assert!(
        has_note(
            &c,
            "3 decmpfs-compressed files were decoded for examination (LZVN: 3)"
        ),
        "{:?}",
        c.notes
    );
}

#[test]
fn hard_links_are_examined_once_and_symlinks_are_counted() {
    let image = apfs_img();
    let c = parse(&image);
    assert!(!labels(&c).iter().any(|l| l.contains("hardlink")));
    assert!(has_note(
        &c,
        "/ZRAX: 1 further hard link was skipped as it leads to a file already examined"
    ));
    assert!(has_note(
        &c,
        "/ZRAX: 1 symbolic link was counted, not followed"
    ));
    assert!(has_note(
        &c,
        "/ZRAX: walked 9 directories, 166 regular files; members in a recognized format: 5"
    ));
}

#[test]
fn the_file_system_tree_is_read_through_index_nodes_and_the_volume_object_map() {
    let image = apfs_img();
    let c = parse(&image);
    assert!(
        has_note(
            &c,
            "/ZRAX: file-system tree of 704 records in 16 nodes, 2 levels"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "Volume /ZRAX (index 0): role none, case-insensitive names, 166 files, 8 directories, \
         1 symbolic link (superblock counts)"
    ));
    assert!(has_note(
        &c,
        "APFS container: 2048 blocks of 4 KiB; checkpoint xid"
    ));
}

#[test]
fn case_sensitive_names_differ_by_case() {
    let image = apfs_cs_img();
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/ZRAXCS/payload.elf",
            "/ZRAXCS/CASE/payload.elf",
            "/ZRAXCS/case/payload.elf"
        ]
    );
    assert_eq!(
        &child(&c, "/ZRAXCS/CASE/payload.elf").data[..],
        &payload_elf()[..]
    );
    assert_eq!(
        &child(&c, "/ZRAXCS/case/payload.elf").data[..],
        &zrax_macho()[..]
    );
    assert!(has_note(&c, "case-sensitive names"));
    let p = classify(&image);
    let case = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("/ZRAXCS/case/payload.elf"))
        .expect("slice");
    assert_eq!(case.isa, Isa::AArch64);
}

#[test]
fn an_encrypted_volume_is_opaque_and_never_read() {
    let image = encrypted_img();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/ZRAXENC"]);
    assert!(c.children[0].opaque);
    assert!(c.opaque, "every listed child is opaque");
    assert!(has_note(
        &c,
        "/ZRAXENC: encrypted (APFS_FS_UNENCRYPTED clear); its file-system tree and file \
         contents are opaque and were not read"
    ));
    assert!(has_note(&c, "software encryption (NX_CRYPTO_SW)"));
    assert!(has_note(&c, "Container keybag of 1 block"));
    // The superblock block of the volume is the slice.
    let volume = &c.children[0];
    assert_eq!(&image[volume.offset + 32..volume.offset + 36], b"APSB");
    let p = classify(&image);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
}

#[test]
fn metadata_reports_the_container_volumes_and_walk() {
    let image = apfs_img();
    let c = parse(&image);
    let value = |key: &str| {
        c.metadata
            .iter()
            .find(|e| matches!(&e.key, zrax::MetadataKey::Custom(k) if k == key))
            .unwrap_or_else(|| panic!("{key} is reported"))
            .value
            .to_string()
    };
    assert_eq!(value("apfs_block_size"), "4096");
    assert_eq!(value("apfs_block_count"), "2048");
    assert_eq!(value("apfs_blocks_present"), "2048");
    assert_eq!(value("apfs_volume_count"), "1");
    assert_eq!(
        value("apfs_volume_0"),
        "\"ZRAX\"; role none; case-insensitive; readable"
    );
    assert_eq!(value("apfs_directory_count"), "9");
    assert_eq!(value("apfs_regular_file_count"), "166");
    assert_eq!(value("apfs_member_count"), "5");
    assert_eq!(value("apfs_container_uuid").len(), 36);
    assert_eq!(c.consumed, image.len());
}

// ---------------------------------------------------------------------------
// A GPT partition holding a container
// ---------------------------------------------------------------------------

/// `APFS_GPT_PARTITION_UUID` ([REF] "Partition UUIDs").
const APFS_PARTITION_TYPE: [u8; 16] = [
    0xef, 0x57, 0x34, 0x7c, 0x00, 0x00, 0xaa, 0x11, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac,
];

/// Partition start (LBA) and the 512-byte sectors of the disk.
const PARTITION_LBA: usize = 40;
const SECTOR: usize = 512;

/// A disk of `volume` in one GPT partition (UEFI 2.10, 5.3): a protective
/// MBR (one type 0xEE record from LBA 1), the header at LBA 1 (signature,
/// revision 1.0, header size 92, header CRC-32 at 16, `MyLBA` 1,
/// `AlternateLBA` the last sector, usable LBAs 34 to last - 33, a disk
/// GUID, entries at LBA 2, 128 entries of 128 B, entry array CRC-32 at 88)
/// and one entry (type GUID, unique GUID, first and last LBA, a UTF-16LE
/// name) for the container from LBA 40. No backup header.
fn gpt_disk(volume: &[u8]) -> Vec<u8> {
    let sectors = PARTITION_LBA + volume.len() / SECTOR + 33;
    let mut disk = vec![0u8; sectors * SECTOR];
    // Protective MBR record: type 0xEE from LBA 1, signature 55 AA.
    put(&mut disk, 446 + 4, &[0xee]);
    put32(&mut disk, 446 + 8, 1);
    put32(&mut disk, 446 + 12, (sectors - 1) as u32);
    put(&mut disk, 510, &[0x55, 0xaa]);
    let mut entries = vec![0u8; 128 * 128];
    put(&mut entries, 0, &APFS_PARTITION_TYPE);
    put(&mut entries, 16, &[0x5a; 16]);
    put64(&mut entries, 32, PARTITION_LBA as u64);
    put64(
        &mut entries,
        40,
        (PARTITION_LBA + volume.len() / SECTOR - 1) as u64,
    );
    for (i, unit) in "Container".encode_utf16().enumerate() {
        put16(&mut entries, 56 + 2 * i, unit);
    }
    let header = SECTOR;
    put(&mut disk, header, b"EFI PART");
    put32(&mut disk, header + 8, 0x0001_0000);
    put32(&mut disk, header + 12, 92);
    put64(&mut disk, header + 24, 1);
    put64(&mut disk, header + 32, (sectors - 1) as u64);
    put64(&mut disk, header + 40, 34);
    put64(&mut disk, header + 48, (sectors - 34) as u64);
    put(&mut disk, header + 56, &[0xa5; 16]);
    put64(&mut disk, header + 72, 2);
    put32(&mut disk, header + 80, 128);
    put32(&mut disk, header + 84, 128);
    put32(&mut disk, header + 88, crc32(&entries));
    let header_crc = crc32(&disk[header..header + 92]);
    put32(&mut disk, header + 16, header_crc);
    put(&mut disk, 2 * SECTOR, &entries);
    put(&mut disk, PARTITION_LBA * SECTOR, volume);
    disk
}

#[test]
fn a_container_in_a_gpt_partition_is_reached_as_the_partition() {
    let volume = apfs_cs_img();
    let disk = gpt_disk(&volume);
    assert!(
        apfs::detect(&disk).is_none(),
        "the disk itself is not a container"
    );
    let p = classify(&disk);
    assert_eq!(p.format.format, FileFormat::Gpt);
    let partition = p
        .slices
        .iter()
        .find(|s| s.label.as_deref().is_some_and(|l| l.contains("Container")))
        .expect("the APFS partition is listed");
    assert_eq!(partition.offset, (PARTITION_LBA * SECTOR) as u64);
    assert_eq!(partition.size, volume.len() as u64);
    assert_eq!(partition.isa, Isa::X86_64, "its first member decides");
    assert!(
        p.notes.iter().any(|n| n
            .message
            .contains("Primary ISA selected from Partition 1 \"Container\" (Apple APFS)")),
        "{:?}",
        p.notes
    );
}

// ---------------------------------------------------------------------------
// Synthetic containers ([REF] layouts)
// ---------------------------------------------------------------------------

const BLOCK: usize = 4096;

/// Object types and flags ([REF] "Object Types", "Object Type Flags").
const OBJ_EPHEMERAL: u32 = 0x8000_0000;
const OBJ_PHYSICAL: u32 = 0x4000_0000;
const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x01;
const OBJECT_TYPE_BTREE: u32 = 0x02;
const OBJECT_TYPE_BTREE_NODE: u32 = 0x03;
const OBJECT_TYPE_OMAP: u32 = 0x0b;
const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0x0c;
const OBJECT_TYPE_FS: u32 = 0x0d;
const OBJECT_TYPE_FSTREE: u32 = 0x0e;
const OBJECT_TYPE_EFI_JUMPSTART: u32 = 0x14;

/// Record types (`j_obj_types`) and directory entry types.
const APFS_TYPE_INODE: u64 = 3;
const APFS_TYPE_XATTR: u64 = 4;
const APFS_TYPE_FILE_EXTENT: u64 = 8;
const APFS_TYPE_DIR_REC: u64 = 9;
const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;

/// Volume flags and features.
const APFS_FS_UNENCRYPTED: u64 = 1;
const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 1;
const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x20;

/// `UF_COMPRESSED` and the decmpfs magic `cmpf`.
const UF_COMPRESSED: u32 = 0x20;
const DECMPFS_MAGIC: u32 = 0x636d_7066;

/// File modes.
const S_IFDIR: u16 = 0o040_000;
const S_IFREG: u16 = 0o100_000;

/// Blocks of the synthetic layout: block 0, the checkpoint descriptor
/// area (blocks 1-4: a checkpoint map and a superblock, then unused), the
/// EFI jumpstart, the container object map and its tree, then 16 blocks
/// per volume (superblock, object map, object map tree, tree nodes), and
/// file data from block 128.
const DESC_BASE: u64 = 1;
const DESC_BLOCKS: u32 = 4;
const EFI_BLOCK: u64 = 8;
const NX_OMAP_BLOCK: u64 = 10;
const NX_OMAP_TREE_BLOCK: u64 = 11;
const VOLUME_BASE: u64 = 20;
const VOLUME_BLOCKS: u64 = 16;
const DATA_BASE: u64 = 128;

/// Virtual identifiers: volume `k` is `1026 + 100 k`, its tree root
/// `1028 + 100 k`, its leaves follow.
fn volume_oid(k: usize) -> u64 {
    1026 + 100 * k as u64
}

fn tree_oid(k: usize, node: usize) -> u64 {
    1028 + 100 * k as u64 + node as u64
}

/// Fletcher-64 as [REF] `o_cksum` stores it (the algorithm of apfs-fuse
/// `Fletcher64` and libfsapfs): sums of the little-endian words after the
/// checksum, folded so that the stored value makes both sums zero.
fn fletcher64(block: &[u8]) -> u64 {
    const MODULUS: u64 = 0xffff_ffff;
    let (mut low, mut high) = (0u64, 0u64);
    for word in block[8..].chunks_exact(4) {
        low = (low + u64::from(u32::from_le_bytes(word.try_into().unwrap()))) % MODULUS;
        high = (high + low) % MODULUS;
    }
    let check_low = MODULUS - (low + high) % MODULUS;
    let check_high = MODULUS - (low + check_low) % MODULUS;
    (check_high << 32) | check_low
}

/// Store the Fletcher-64 of `block` in its `o_cksum`.
fn seal(block: &mut [u8]) {
    let checksum = fletcher64(block);
    put64(block, 0, checksum);
}

/// An object header (`obj_phys_t`): checksum (sealed later), `o_oid` (8),
/// `o_xid` (16), `o_type` (24), `o_subtype` (28).
fn object(oid: u64, xid: u64, object_type: u32, subtype: u32) -> Vec<u8> {
    let mut block = vec![0u8; BLOCK];
    put64(&mut block, 8, oid);
    put64(&mut block, 16, xid);
    put32(&mut block, 24, object_type);
    put32(&mut block, 28, subtype);
    block
}

/// A B-tree record.
#[derive(Debug, Clone)]
struct Entry {
    key: Vec<u8>,
    value: Vec<u8>,
}

/// How a node stores its table of contents: `kvoff_t` with the tree's
/// fixed sizes, or `kvloc_t` with lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Toc {
    Fixed,
    Variable,
}

/// A B-tree node ([REF] `btree_node_phys_t`): `btn_flags` (32; root 1,
/// leaf 2, fixed 4), `btn_level` (34), `btn_nkeys` (36), the table of
/// contents at `btn_data` (56) with `btn_table_space` (40) offset 0 and its
/// length, keys packed after the table, values packed back from the end
/// (or from the 40-byte `btree_info_t` of a root, whose fields are flags,
/// node size, key size, value size, longest key and value, key count and
/// node count).
struct NodeSpec<'e> {
    oid: u64,
    xid: u64,
    /// `o_type`: storage flags with `OBJECT_TYPE_BTREE` (root) or
    /// `OBJECT_TYPE_BTREE_NODE`.
    object_type: u32,
    subtype: u32,
    level: u16,
    toc: Toc,
    /// `btree_info_t`: tree flags, key size, value size, key count, node
    /// count; `None` for a non-root node.
    info: Option<TreeInfo>,
    entries: &'e [Entry],
}

#[derive(Debug, Clone, Copy)]
struct TreeInfo {
    flags: u32,
    key_size: u32,
    value_size: u32,
    key_count: u64,
    node_count: u64,
}

/// `BTREE_PHYSICAL` and `BTREE_KV_NONALIGNED`.
const BTREE_PHYSICAL: u32 = 0x10;
const BTREE_KV_NONALIGNED: u32 = 0x40;

fn btree_node(spec: &NodeSpec<'_>) -> Vec<u8> {
    let mut block = object(spec.oid, spec.xid, spec.object_type, spec.subtype);
    let is_root = spec.info.is_some();
    let mut flags = 0u16;
    if is_root {
        flags |= 1;
    }
    if spec.level == 0 {
        flags |= 2;
    }
    if spec.toc == Toc::Fixed {
        flags |= 4;
    }
    let entry_size = if spec.toc == Toc::Fixed { 4 } else { 8 };
    let table = entry_size * spec.entries.len();
    put16(&mut block, 32, flags);
    put16(&mut block, 34, spec.level);
    put32(&mut block, 36, spec.entries.len() as u32);
    put16(&mut block, 40, 0);
    put16(&mut block, 42, table as u16);
    let key_start = 56 + table;
    let value_end = if is_root { BLOCK - 40 } else { BLOCK };
    let mut key_at = 0usize;
    let mut value_back = 0usize;
    for (i, entry) in spec.entries.iter().enumerate() {
        put(&mut block, key_start + key_at, &entry.key);
        value_back += entry.value.len();
        put(&mut block, value_end - value_back, &entry.value);
        let toc = 56 + entry_size * i;
        if spec.toc == Toc::Fixed {
            put16(&mut block, toc, key_at as u16);
            put16(&mut block, toc + 2, value_back as u16);
        } else {
            put16(&mut block, toc, key_at as u16);
            put16(&mut block, toc + 2, entry.key.len() as u16);
            put16(&mut block, toc + 4, value_back as u16);
            put16(&mut block, toc + 6, entry.value.len() as u16);
        }
        key_at += entry.key.len();
    }
    assert!(
        key_start + key_at <= value_end - value_back,
        "the node fits"
    );
    // btn_free_space: from the end of the keys to the start of the values.
    put16(&mut block, 44, key_at as u16);
    put16(
        &mut block,
        46,
        (value_end - value_back - key_start - key_at) as u16,
    );
    put16(&mut block, 48, 0xffff);
    put16(&mut block, 52, 0xffff);
    if let Some(info) = spec.info {
        let at = BLOCK - 40;
        put32(&mut block, at, info.flags);
        put32(&mut block, at + 4, BLOCK as u32);
        put32(&mut block, at + 8, info.key_size);
        put32(&mut block, at + 12, info.value_size);
        put64(&mut block, at + 24, info.key_count);
        put64(&mut block, at + 32, info.node_count);
    }
    block
}

/// An object map leaf entry: `omap_key_t` (oid, xid) to `omap_val_t`
/// (flags 0, size one block, address).
fn omap_entry(oid: u64, xid: u64, paddr: u64) -> Entry {
    let mut key = oid.to_le_bytes().to_vec();
    key.extend(xid.to_le_bytes());
    let mut value = 0u32.to_le_bytes().to_vec();
    value.extend((BLOCK as u32).to_le_bytes());
    value.extend(paddr.to_le_bytes());
    Entry { key, value }
}

/// An object map object and its one-node tree.
struct OmapBlocks {
    omap: Vec<u8>,
    tree: Vec<u8>,
}

/// An object map in block `paddr` (`omap_phys_t`: flags at 32, tree type
/// `OBJ_PHYSICAL | OBJECT_TYPE_BTREE` at 40, tree address at 48, snapshot
/// count at 36) and its one-node tree in block `tree_paddr`.
fn omap_blocks(paddr: u64, tree_paddr: u64, xid: u64, entries: &[Entry]) -> OmapBlocks {
    let mut omap = object(paddr, xid, OBJ_PHYSICAL | OBJECT_TYPE_OMAP, 0);
    put32(&mut omap, 32, 1);
    put32(&mut omap, 40, OBJ_PHYSICAL | OBJECT_TYPE_BTREE);
    put32(&mut omap, 44, OBJ_PHYSICAL | OBJECT_TYPE_BTREE);
    put64(&mut omap, 48, tree_paddr);
    let tree = btree_node(&NodeSpec {
        oid: tree_paddr,
        xid,
        object_type: OBJ_PHYSICAL | OBJECT_TYPE_BTREE,
        subtype: OBJECT_TYPE_OMAP,
        level: 0,
        toc: Toc::Fixed,
        info: Some(TreeInfo {
            flags: BTREE_PHYSICAL | 0x7,
            key_size: 16,
            value_size: 16,
            key_count: entries.len() as u64,
            node_count: 1,
        }),
        entries,
    });
    OmapBlocks { omap, tree }
}

/// A `j_key_t`: the object identifier with the record type in the top
/// four bits.
fn j_key(oid: u64, kind: u64) -> Vec<u8> {
    (oid | kind << 60).to_le_bytes().to_vec()
}

/// An inode record (`j_inode_val_t`, 92 B): parent (0), private id (8),
/// four times (16-47), internal flags (48), link count (56), protection
/// class (60), write counter (64), BSD flags (68), owner (72), group (76),
/// mode (80), then, for a data size, an `xf_blob_t` with one
/// `INO_EXT_TYPE_DSTREAM` field (type 8, flags 0x20, 40 B) holding the
/// `j_dstream_t` (size, allocated size, crypto id, bytes written and read).
fn inode(
    id: u64,
    parent: u64,
    private_id: u64,
    mode: u16,
    bsd_flags: u32,
    size: Option<u64>,
) -> Entry {
    let mut value = vec![0u8; 92];
    put64(&mut value, 0, parent);
    put64(&mut value, 8, private_id);
    put32(&mut value, 56, 1);
    put32(&mut value, 68, bsd_flags);
    put16(&mut value, 80, mode);
    if let Some(size) = size {
        value.extend(1u16.to_le_bytes());
        value.extend(44u16.to_le_bytes());
        value.extend([8, 0x20]);
        value.extend(40u16.to_le_bytes());
        value.extend(size.to_le_bytes());
        value.extend(size.to_le_bytes());
        value.extend([0; 24]);
    }
    Entry {
        key: j_key(id, APFS_TYPE_INODE),
        value,
    }
}

fn directory_inode(id: u64, parent: u64) -> Entry {
    inode(id, parent, id, S_IFDIR | 0o755, 0, None)
}

fn file_inode(id: u64, parent: u64, size: u64) -> Entry {
    inode(id, parent, id, S_IFREG | 0o644, 0, Some(size))
}

/// A directory entry: the key (`j_drec_hashed_key_t`: a 32-bit length,
/// including the NUL, with a hash in the upper 22 bits; or `j_drec_key_t`:
/// a 16-bit length) and the value (`file_id`, `date_added`, `flags` with
/// the `DT_*` type).
fn drec(parent: u64, name: &str, file_id: u64, file_type: u16, hashed: bool) -> Entry {
    let mut key = j_key(parent, APFS_TYPE_DIR_REC);
    let length = name.len() + 1;
    if hashed {
        key.extend((length as u32 | 0x2a_5a5a << 10).to_le_bytes());
    } else {
        key.extend((length as u16).to_le_bytes());
    }
    key.extend(name.as_bytes());
    key.push(0);
    let mut value = file_id.to_le_bytes().to_vec();
    value.extend(0u64.to_le_bytes());
    value.extend(file_type.to_le_bytes());
    Entry { key, value }
}

/// A file extent: key (`j_key_t` of the stream, `logical_addr`), value
/// (`len_and_flags`, `phys_block_num`, `crypto_id`).
fn extent(stream: u64, logical: u64, length: u64, block: u64) -> Entry {
    let mut key = j_key(stream, APFS_TYPE_FILE_EXTENT);
    key.extend(logical.to_le_bytes());
    let mut value = length.to_le_bytes().to_vec();
    value.extend(block.to_le_bytes());
    value.extend(0u64.to_le_bytes());
    Entry { key, value }
}

/// The key of an extended attribute: `j_key_t`, a 16-bit name length with
/// the NUL, the name.
fn xattr_key(id: u64, name: &str) -> Vec<u8> {
    let mut key = j_key(id, APFS_TYPE_XATTR);
    key.extend(((name.len() + 1) as u16).to_le_bytes());
    key.extend(name.as_bytes());
    key.push(0);
    key
}

/// An embedded attribute (`XATTR_DATA_EMBEDDED`): flags 2, length, data.
fn xattr_embedded(id: u64, name: &str, data: &[u8]) -> Entry {
    let mut value = 2u16.to_le_bytes().to_vec();
    value.extend((data.len() as u16).to_le_bytes());
    value.extend(data);
    Entry {
        key: xattr_key(id, name),
        value,
    }
}

/// An attribute in a data stream (`XATTR_DATA_STREAM`): flags 1, length 48,
/// `j_xattr_dstream_t` (stream id, then `j_dstream_t` with the size).
fn xattr_stream(id: u64, name: &str, stream: u64, size: u64) -> Entry {
    let mut value = 1u16.to_le_bytes().to_vec();
    value.extend(48u16.to_le_bytes());
    value.extend(stream.to_le_bytes());
    value.extend(size.to_le_bytes());
    value.extend(size.to_le_bytes());
    value.extend([0; 24]);
    Entry {
        key: xattr_key(id, name),
        value,
    }
}

/// A `decmpfs_disk_header` (magic `cmpf`, type, size) followed by `data`.
fn decmpfs(compression_type: u32, size: u64, data: &[u8]) -> Vec<u8> {
    let mut attribute = DECMPFS_MAGIC.to_le_bytes().to_vec();
    attribute.extend(compression_type.to_le_bytes());
    attribute.extend(size.to_le_bytes());
    attribute.extend(data);
    attribute
}

/// A synthetic volume: the superblock fields the parser reads and the
/// file-system records, which the builder sorts by object and type.
#[derive(Debug, Clone)]
struct VolumeSpec {
    name: String,
    fs_flags: u64,
    incompatible: u64,
    role: u16,
    snapshots: u64,
    integrity_meta_oid: u64,
    records: Vec<Entry>,
    /// Records per leaf; more records make an index root over the leaves.
    leaf_capacity: usize,
}

impl VolumeSpec {
    fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            fs_flags: APFS_FS_UNENCRYPTED,
            incompatible: APFS_INCOMPAT_CASE_INSENSITIVE,
            role: 0,
            snapshots: 0,
            integrity_meta_oid: 0,
            records: vec![directory_inode(2, 1)],
            leaf_capacity: 64,
        }
    }

    fn hashed(&self) -> bool {
        self.incompatible & (APFS_INCOMPAT_CASE_INSENSITIVE | 0x8) != 0
    }
}

/// Where the EFI driver was stored.
#[derive(Debug, Clone, Copy)]
struct EfiDriver {
    /// Length in bytes.
    length: usize,
    /// First block.
    block: u64,
}

/// A volume's file-system tree nodes and the volume object map entries
/// that locate them.
struct TreeBlocks {
    nodes: Vec<Vec<u8>>,
    mappings: Vec<Entry>,
}

/// A synthetic container of `blocks` blocks of 4 KiB.
struct Synthetic {
    image: Vec<u8>,
    blocks: u64,
    /// Next free data block.
    next: u64,
    xid: u64,
    volumes: Vec<VolumeSpec>,
    efi: Option<EfiDriver>,
}

impl Synthetic {
    fn new(blocks: u64) -> Self {
        Self {
            image: vec![0u8; blocks as usize * BLOCK],
            blocks,
            next: DATA_BASE,
            xid: 5,
            volumes: Vec::new(),
            efi: None,
        }
    }

    /// Store `bytes` in fresh blocks; returns the first block.
    fn store(&mut self, bytes: &[u8]) -> u64 {
        let first = self.next;
        put(&mut self.image, first as usize * BLOCK, bytes);
        self.next += (bytes.len().max(1) as u64 + BLOCK as u64 - 1) / BLOCK as u64;
        first
    }

    /// Add a regular file `name` in directory `parent` stored in one extent.
    fn file(&mut self, volume: usize, parent: u64, id: u64, name: &str, bytes: &[u8]) {
        let block = self.store(bytes);
        let hashed = self.volumes[volume].hashed();
        let length = (bytes.len() as u64 + BLOCK as u64 - 1) / BLOCK as u64 * BLOCK as u64;
        let records = &mut self.volumes[volume].records;
        records.push(drec(parent, name, id, DT_REG, hashed));
        records.push(file_inode(id, parent, bytes.len() as u64));
        records.push(extent(id, 0, length, block));
    }

    /// Add directory `name` (inode `id`) in `parent`.
    fn directory(&mut self, volume: usize, parent: u64, id: u64, name: &str) {
        let hashed = self.volumes[volume].hashed();
        let records = &mut self.volumes[volume].records;
        records.push(drec(parent, name, id, DT_DIR, hashed));
        records.push(directory_inode(id, parent));
    }

    /// Embed `driver` as the EFI jumpstart.
    fn efi_driver(&mut self, driver: &[u8]) {
        let block = self.store(driver);
        self.efi = Some(EfiDriver {
            length: driver.len(),
            block,
        });
    }

    /// The container superblock (`nx_superblock_t`) of transaction `xid`
    /// in block `paddr`: magic (32), block size (36), block count (40),
    /// incompatible features `NX_INCOMPAT_VERSION2` (64), UUID (72), next
    /// oid and xid (88, 96), descriptor area blocks and base (104, 112),
    /// data area blocks and base (108, 120), object map (160), maximum
    /// volumes (180), volume identifiers (184), EFI jumpstart (1272).
    fn superblock(&self, xid: u64) -> Vec<u8> {
        let mut block = object(1, xid, OBJ_EPHEMERAL | OBJECT_TYPE_NX_SUPERBLOCK, 0);
        put(&mut block, 32, b"NXSB");
        put32(&mut block, 36, BLOCK as u32);
        put64(&mut block, 40, self.blocks);
        put64(&mut block, 64, 2);
        put(&mut block, 72, &[0x5a; 16]);
        put64(&mut block, 88, 5000);
        put64(&mut block, 96, xid + 1);
        put32(&mut block, 104, DESC_BLOCKS);
        put32(&mut block, 108, 2);
        put64(&mut block, 112, DESC_BASE);
        put64(&mut block, 120, DESC_BASE + u64::from(DESC_BLOCKS));
        put64(&mut block, 160, NX_OMAP_BLOCK);
        put32(&mut block, 180, self.volumes.len().max(1) as u32);
        for k in 0..self.volumes.len() {
            put64(&mut block, 184 + 8 * k, volume_oid(k));
        }
        if self.efi.is_some() {
            put64(&mut block, 1272, EFI_BLOCK);
        }
        block
    }

    /// The volume superblock (`apfs_superblock_t`) of volume `k`: magic
    /// (32), index (36), incompatible features (56), root tree type
    /// (116, virtual B-tree), object map (128), root tree (136), counts
    /// (184..), snapshots (216), flags (264), name (704), role (964),
    /// integrity metadata (1024).
    fn volume_superblock(&self, k: usize) -> Vec<u8> {
        let spec = &self.volumes[k];
        let base = VOLUME_BASE + VOLUME_BLOCKS * k as u64;
        let mut block = object(volume_oid(k), self.xid, OBJECT_TYPE_FS, 0);
        put(&mut block, 32, b"APSB");
        put32(&mut block, 36, k as u32);
        put64(&mut block, 56, spec.incompatible);
        put32(&mut block, 116, OBJECT_TYPE_BTREE);
        put64(&mut block, 128, base + 1);
        put64(&mut block, 136, tree_oid(k, 0));
        put64(&mut block, 184, 1);
        put64(&mut block, 192, 1);
        put64(&mut block, 216, spec.snapshots);
        put64(&mut block, 264, spec.fs_flags);
        put(&mut block, 704, spec.name.as_bytes());
        put16(&mut block, 964, spec.role);
        put64(&mut block, 1024, spec.integrity_meta_oid);
        block
    }

    /// The file-system tree nodes of volume `k`, in blocks from
    /// `base + 3`: one root leaf, or an index root over leaves of
    /// `leaf_capacity` records; with the volume object map entries.
    fn volume_tree(&self, k: usize) -> TreeBlocks {
        let spec = &self.volumes[k];
        let mut records = spec.records.clone();
        records.sort_by_key(|r| {
            let header = le64(&r.key, 0);
            (
                header & 0x0fff_ffff_ffff_ffff,
                header >> 60,
                r.key[8..].to_vec(),
            )
        });
        let base = VOLUME_BASE + VOLUME_BLOCKS * k as u64;
        let info = |node_count: u64| TreeInfo {
            flags: BTREE_KV_NONALIGNED | 0x2,
            key_size: 0,
            value_size: 0,
            key_count: records.len() as u64,
            node_count,
        };
        if records.len() <= spec.leaf_capacity {
            let root = btree_node(&NodeSpec {
                oid: tree_oid(k, 0),
                xid: self.xid,
                object_type: OBJECT_TYPE_BTREE,
                subtype: OBJECT_TYPE_FSTREE,
                level: 0,
                toc: Toc::Variable,
                info: Some(info(1)),
                entries: &records,
            });
            return TreeBlocks {
                nodes: vec![root],
                mappings: vec![omap_entry(tree_oid(k, 0), self.xid, base + 3)],
            };
        }
        let leaves: Vec<&[Entry]> = records.chunks(spec.leaf_capacity).collect();
        let mut nodes = Vec::new();
        let mut index = Vec::new();
        let mut mappings = vec![omap_entry(tree_oid(k, 0), self.xid, base + 3)];
        for (i, leaf) in leaves.iter().enumerate() {
            let oid = tree_oid(k, i + 1);
            index.push(Entry {
                key: leaf[0].key.clone(),
                value: oid.to_le_bytes().to_vec(),
            });
            mappings.push(omap_entry(oid, self.xid, base + 4 + i as u64));
            nodes.push(btree_node(&NodeSpec {
                oid,
                xid: self.xid,
                object_type: OBJECT_TYPE_BTREE_NODE,
                subtype: OBJECT_TYPE_FSTREE,
                level: 0,
                toc: Toc::Variable,
                info: None,
                entries: leaf,
            }));
        }
        let root = btree_node(&NodeSpec {
            oid: tree_oid(k, 0),
            xid: self.xid,
            object_type: OBJECT_TYPE_BTREE,
            subtype: OBJECT_TYPE_FSTREE,
            level: 1,
            toc: Toc::Variable,
            info: Some(info(1 + leaves.len() as u64)),
            entries: &index,
        });
        nodes.insert(0, root);
        TreeBlocks { nodes, mappings }
    }

    /// The image with every metadata object written and sealed.
    fn build(&self) -> Vec<u8> {
        let mut image = self.image.clone();
        let mut write = |paddr: u64, mut block: Vec<u8>| {
            seal(&mut block);
            put(&mut image, paddr as usize * BLOCK, &block);
        };
        // Block 0 holds an older copy; the descriptor area the latest.
        write(0, self.superblock(self.xid - 1));
        let mut map = object(
            DESC_BASE,
            self.xid,
            OBJ_PHYSICAL | OBJECT_TYPE_CHECKPOINT_MAP,
            0,
        );
        put32(&mut map, 32, 1);
        write(DESC_BASE, map);
        write(DESC_BASE + 1, self.superblock(self.xid));
        let mappings: Vec<Entry> = (0..self.volumes.len())
            .map(|k| {
                omap_entry(
                    volume_oid(k),
                    self.xid,
                    VOLUME_BASE + VOLUME_BLOCKS * k as u64,
                )
            })
            .collect();
        let container_omap = omap_blocks(NX_OMAP_BLOCK, NX_OMAP_TREE_BLOCK, self.xid, &mappings);
        write(NX_OMAP_BLOCK, container_omap.omap);
        write(NX_OMAP_TREE_BLOCK, container_omap.tree);
        for k in 0..self.volumes.len() {
            let base = VOLUME_BASE + VOLUME_BLOCKS * k as u64;
            write(base, self.volume_superblock(k));
            let tree = self.volume_tree(k);
            let volume_omap = omap_blocks(base + 1, base + 2, self.xid, &tree.mappings);
            write(base + 1, volume_omap.omap);
            write(base + 2, volume_omap.tree);
            for (i, node) in tree.nodes.into_iter().enumerate() {
                write(base + 3 + i as u64, node);
            }
        }
        if let Some(driver) = self.efi {
            // nx_efi_jumpstart_t: magic JSDR (32), version 1 (36), driver
            // length (40), one extent (44) at 176: start block, block count.
            let mut jumpstart = object(
                EFI_BLOCK,
                self.xid,
                OBJ_PHYSICAL | OBJECT_TYPE_EFI_JUMPSTART,
                0,
            );
            put(&mut jumpstart, 32, b"JSDR");
            put32(&mut jumpstart, 36, 1);
            put32(&mut jumpstart, 40, driver.length as u32);
            put32(&mut jumpstart, 44, 1);
            put64(&mut jumpstart, 176, driver.block);
            let blocks = (driver.length as u64 + BLOCK as u64 - 1) / BLOCK as u64;
            put64(&mut jumpstart, 184, blocks);
            write(EFI_BLOCK, jumpstart);
        }
        image
    }
}

/// One volume `ZRAX` with `/payload.elf` (inode 16) and `/bin/tool.macho`
/// (inode 18 in directory 17).
fn simple() -> Synthetic {
    let mut s = Synthetic::new(256);
    s.volumes.push(VolumeSpec::new("ZRAX"));
    s.file(0, 2, 16, "payload.elf", &payload_elf());
    s.directory(0, 2, 17, "bin");
    s.file(0, 17, 18, "tool.macho", &kernel_macho());
    s
}

#[test]
fn a_synthetic_container_lists_its_members() {
    let image = simple().build();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/ZRAX/payload.elf", "/ZRAX/bin/tool.macho"]);
    assert_eq!(&c.children[1].data[..], &kernel_macho()[..]);
    assert!(has_note(
        &c,
        "checkpoint xid 5 (checkpoint descriptor block 1, block 0x2)"
    ));
    assert!(has_note(
        &c,
        "Block 0 holds checkpoint xid 4; the latest valid checkpoint, xid 5, is used"
    ));
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::X86_64);
}

#[test]
fn the_latest_checkpoint_with_a_valid_checksum_is_chosen() {
    let mut image = simple().build();
    // Damage the descriptor superblock: block 0 (xid 4) is used instead.
    image[2 * BLOCK + 200] ^= 1;
    let c = parse(&image);
    assert!(has_note(&c, "checkpoint xid 4 (block 0)"), "{:?}", c.notes);
    assert!(has_note(
        &c,
        "1 block of the checkpoint descriptor area skipped: checksum or superblock invalid"
    ));
    // Block 0's volume list still finds the volume, whose objects carry
    // xid 5: lookups as of xid 4 find no mapping.
    assert!(
        has_note(&c, "Volume 0 (object 0x402) not read"),
        "{:?}",
        c.notes
    );

    // A damaged block 0 is used only to find the checkpoints.
    let mut image = simple().build();
    image[300] ^= 1;
    let c = parse(&image);
    assert_eq!(c.children.len(), 2);
    assert!(has_note(
        &c,
        "The block 0 superblock's checksum does not verify"
    ));

    // Neither verifies: an error.
    image[2 * BLOCK + 200] ^= 1;
    assert_eq!(
        parse_error(&image),
        "APFS parse error: Invalid container superblock: the block 0 checksum does not verify \
         and no checkpoint superblock does"
    );
}

#[test]
fn detection_requires_the_superblock_identity_and_geometry() {
    let image = simple().build();
    assert!(apfs::detect(&image).is_some());
    let mutated = |at: usize, bytes: &[u8]| {
        let mut copy = image.clone();
        put(&mut copy, at, bytes);
        apfs::detect(&copy)
    };
    assert_eq!(mutated(32, b"NXSA"), None, "magic");
    assert_eq!(mutated(8, &2u64.to_le_bytes()), None, "o_oid");
    assert_eq!(
        mutated(24, &1u32.to_le_bytes()),
        None,
        "o_type without OBJ_EPHEMERAL"
    );
    assert_eq!(
        mutated(36, &2048u32.to_le_bytes()),
        None,
        "block size below 4 KiB"
    );
    assert_eq!(
        mutated(36, &12_288u32.to_le_bytes()),
        None,
        "not a power of two"
    );
    assert_eq!(
        mutated(36, &(128u32 << 10).to_le_bytes()),
        None,
        "above 64 KiB"
    );
    assert_eq!(mutated(40, &255u64.to_le_bytes()), None, "below 1 MiB");
    assert_eq!(mutated(40, &u64::MAX.to_le_bytes()), None, "size overflows");
    assert!(apfs::detect(&image[..47]).is_none());
    assert!(
        apfs::detect(&image[..48]).is_some(),
        "48 bytes are enough to detect"
    );
}

#[test]
fn a_short_block_0_and_trailing_data_are_errors() {
    let image = simple().build();
    assert_eq!(
        parse_error(&image[..4095]),
        "APFS parse error: Truncated container superblock: block 0 needs 4096 B, 4095 B present"
    );
    let mut longer = image.clone();
    longer.extend(vec![0xff; 2 * BLOCK]);
    assert_eq!(
        parse(&longer).consumed,
        image.len(),
        "padding after the container"
    );
    longer[image.len() + 10] = 1;
    assert_eq!(
        parse_error(&longer),
        "APFS parse error: Invalid trailing data: 8 KiB after the container at 0x100000 are not \
         padding"
    );
    let mut short_tail = image.clone();
    short_tail.extend([1, 2, 3]);
    assert_eq!(parse(&short_tail).consumed, short_tail.len());
}

#[test]
fn plain_name_keys_and_index_nodes_are_read() {
    let mut s = Synthetic::new(512);
    let mut volume = VolumeSpec::new("PLAIN");
    volume.incompatible = 0;
    volume.leaf_capacity = 5;
    s.volumes.push(volume);
    for i in 0..12u64 {
        s.directory(0, 2, 100 + i, &format!("d{i:02}"));
    }
    s.file(0, 105, 200, "inner.elf", &payload_elf());
    s.file(0, 2, 201, "Top.macho", &kernel_macho());
    let image = s.build();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/PLAIN/Top.macho", "/PLAIN/d05/inner.elf"]);
    assert!(has_note(&c, "case-sensitive names"));
    assert!(has_note(&c, "2 levels"), "{:?}", c.notes);
    assert!(has_note(
        &c,
        "/PLAIN: walked 13 directories, 2 regular files"
    ));
}

/// A decmpfs file: its compression type, the data after the attribute's
/// header (for type 9, the `0xCC` marker and the data), and the resource
/// fork when the type stores the data there.
struct CompressedFile {
    name: &'static str,
    compression_type: u32,
    inline: Vec<u8>,
    fork: Option<Vec<u8>>,
}

#[test]
fn zlib_lzfse_and_stored_decmpfs_files_are_decoded() {
    let elf = payload_elf();
    let size = elf.len() as u64;
    let lzfse = fixture("compressed/payload.elf.lzfse");
    let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&elf, 9);
    // Type 4: a Resource Manager header whose data offset (256) is followed
    // by the resource length, then the block table: count 1 and one
    // (offset from the count, size) pair.
    let mut zlib_fork = vec![0u8; 256];
    put(&mut zlib_fork, 0, &256u32.to_be_bytes());
    zlib_fork.extend(0u32.to_be_bytes());
    zlib_fork.extend(1u32.to_le_bytes());
    zlib_fork.extend(12u32.to_le_bytes());
    zlib_fork.extend((zlib.len() as u32).to_le_bytes());
    zlib_fork.extend(&zlib);
    // Type 12: an offset table of two entries (8 B), then the chunk.
    let mut lzfse_fork = 8u32.to_le_bytes().to_vec();
    lzfse_fork.extend((8 + lzfse.len() as u32).to_le_bytes());
    lzfse_fork.extend(&lzfse);

    let mut s = Synthetic::new(256);
    s.volumes.push(VolumeSpec::new("Z"));
    let compressed = |id: u64| inode(id, 2, id, S_IFREG | 0o644, UF_COMPRESSED, None);
    let files = [
        CompressedFile {
            name: "type1.elf",
            compression_type: 1,
            inline: elf.clone(),
            fork: None,
        },
        CompressedFile {
            name: "type3.elf",
            compression_type: 3,
            inline: zlib.clone(),
            fork: None,
        },
        CompressedFile {
            name: "type4.elf",
            compression_type: 4,
            inline: Vec::new(),
            fork: Some(zlib_fork),
        },
        CompressedFile {
            name: "type11.elf",
            compression_type: 11,
            inline: lzfse.clone(),
            fork: None,
        },
        CompressedFile {
            name: "type12.elf",
            compression_type: 12,
            inline: Vec::new(),
            fork: Some(lzfse_fork),
        },
        CompressedFile {
            name: "type9.elf",
            compression_type: 9,
            inline: [&[0xcc], &elf[..]].concat(),
            fork: None,
        },
    ];
    for (i, file) in files.into_iter().enumerate() {
        let id = 20 + 2 * i as u64;
        let attribute = decmpfs(file.compression_type, size, &file.inline);
        let records = &mut s.volumes[0].records;
        records.push(drec(2, file.name, id, DT_REG, true));
        records.push(compressed(id));
        records.push(xattr_embedded(id, "com.apple.decmpfs", &attribute));
        if let Some(fork) = file.fork {
            // The resource fork as a data stream of its own identifier.
            let block = s.store(&fork);
            let records = &mut s.volumes[0].records;
            records.push(xattr_stream(
                id,
                "com.apple.ResourceFork",
                id + 1,
                fork.len() as u64,
            ));
            records.push(extent(id + 1, 0, BLOCK as u64, block));
        }
    }
    let image = s.build();
    let c = parse(&image);
    let expected = [
        ("/Z/type1.elf", "decmpfs attribute data"),
        ("/Z/type11.elf", "decmpfs LZFSE"),
        ("/Z/type12.elf", "decmpfs LZFSE"),
        ("/Z/type3.elf", "decmpfs zlib"),
        ("/Z/type4.elf", "decmpfs zlib"),
        ("/Z/type9.elf", "decmpfs raw"),
    ];
    assert_eq!(
        labels(&c),
        expected.iter().map(|(label, _)| *label).collect::<Vec<_>>()
    );
    for (label, transform) in expected {
        let member = child(&c, label);
        assert_eq!(member.transform, Some(transform), "{label}");
        assert_eq!(&member.data[..], &elf[..], "{label}");
    }
    assert!(has_note(
        &c,
        "6 decmpfs-compressed files were decoded for examination (LZFSE: 2, raw: 1, stored: 1, zlib: \
         2)"
    ));
}

#[test]
fn unsupported_or_damaged_decmpfs_files_are_counted_or_noted() {
    let elf = payload_elf();
    let mut s = Synthetic::new(256);
    s.volumes.push(VolumeSpec::new("Z"));
    let compressed = |id: u64| inode(id, 2, id, S_IFREG | 0o644, UF_COMPRESSED, None);
    let records = &mut s.volumes[0].records;
    // Type 13 (LZBITMAP in apfs-fuse) and a dataless file are not decoded.
    for (id, name, compression_type) in [(20u64, "a", 13u32), (21, "b", 0x8000_0001)] {
        records.push(drec(2, name, id, DT_REG, true));
        records.push(compressed(id));
        records.push(xattr_embedded(
            id,
            "com.apple.decmpfs",
            &decmpfs(compression_type, 256, &[]),
        ));
    }
    // A bad magic, a missing attribute, a missing resource fork, and stored
    // data of the wrong size.
    records.push(drec(2, "c", 22, DT_REG, true));
    records.push(compressed(22));
    let mut bad = decmpfs(1, 256, &elf);
    bad[0] ^= 1;
    records.push(xattr_embedded(22, "com.apple.decmpfs", &bad));
    records.push(drec(2, "d", 23, DT_REG, true));
    records.push(compressed(23));
    records.push(drec(2, "e", 24, DT_REG, true));
    records.push(compressed(24));
    records.push(xattr_embedded(
        24,
        "com.apple.decmpfs",
        &decmpfs(8, 256, &[]),
    ));
    records.push(drec(2, "f", 25, DT_REG, true));
    records.push(compressed(25));
    records.push(xattr_embedded(
        25,
        "com.apple.decmpfs",
        &decmpfs(1, 300, &elf),
    ));
    // Type 9 data without its 0xCC marker.
    records.push(drec(2, "g", 26, DT_REG, true));
    records.push(compressed(26));
    records.push(xattr_embedded(
        26,
        "com.apple.decmpfs",
        &decmpfs(9, 255, &elf),
    ));
    let image = s.build();
    let c = parse(&image);
    assert!(c.children.is_empty());
    assert!(has_note(
        &c,
        "Skipped /Z/g: Invalid decmpfs type 9 data: marker 0x7F, 0xCC expected"
    ));
    assert!(has_note(
        &c,
        "1 file uses decmpfs compression type 0xD, which is not implemented"
    ));
    assert!(has_note(
        &c,
        "1 file uses decmpfs compression type 0x80000001"
    ));
    assert!(has_note(
        &c,
        "Skipped /Z/c: Invalid com.apple.decmpfs magic 0x636D7067"
    ));
    assert!(has_note(
        &c,
        "Skipped /Z/d: Missing com.apple.decmpfs attribute"
    ));
    assert!(has_note(
        &c,
        "Skipped /Z/e: Missing com.apple.ResourceFork attribute of a decmpfs type 8 file"
    ));
    assert!(has_note(
        &c,
        "Skipped /Z/f: Invalid decmpfs data: 256 B decoded, 300 B expected"
    ));
}

#[test]
fn several_volumes_are_labeled_and_a_repeated_name_is_qualified() {
    let mut s = Synthetic::new(256);
    s.volumes.push(VolumeSpec::new("Data"));
    s.volumes.push(VolumeSpec::new("Data"));
    s.volumes.push(VolumeSpec::new(""));
    s.file(0, 2, 16, "a.elf", &payload_elf());
    s.file(1, 2, 16, "b.macho", &kernel_macho());
    s.file(2, 2, 16, "c.elf", &payload_elf());
    s.volumes[1].role = 1 << 6;
    let image = s.build();
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        ["/Data/a.elf", "/Data (volume 1)/b.macho", "/volume 2/c.elf"]
    );
    assert!(has_note(&c, "Volume /Data (volume 1) (index 1): role data"));
    assert!(has_note(&c, "3 of 3 volume slots used"));
}

#[test]
fn sealed_encrypted_and_snapshot_volumes_are_noted() {
    let mut s = Synthetic::new(256);
    let mut sealed = VolumeSpec::new("System");
    sealed.role = 1;
    sealed.incompatible |= APFS_INCOMPAT_SEALED_VOLUME;
    sealed.integrity_meta_oid = 4000;
    let mut encrypted = VolumeSpec::new("Secret");
    encrypted.fs_flags = 0x8;
    let mut snapshots = VolumeSpec::new("Snap");
    snapshots.snapshots = 2;
    s.volumes.extend([sealed, encrypted, snapshots]);
    s.file(0, 2, 16, "sealed.elf", &payload_elf());
    s.file(1, 2, 16, "secret.elf", &payload_elf());
    s.file(2, 2, 16, "snap.elf", &payload_elf());
    let image = s.build();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/Snap/snap.elf", "/Secret"]);
    assert!(c.children[1].opaque);
    assert!(!c.opaque, "a readable member remains");
    assert!(has_note(
        &c,
        "/System: sealed volume (APFS_INCOMPAT_SEALED_VOLUME): its integrity metadata and file \
         extent tree are not read, so its files are not listed"
    ));
    assert!(has_note(&c, "/Secret: encrypted"));
    assert!(has_note(
        &c,
        "/Snap: 2 snapshots; snapshot contents are not read"
    ));
    let p = classify(&s.build());
    assert_eq!(p.primary.isa, Isa::X86_64, "the readable member decides");
}

#[test]
fn the_efi_jumpstart_driver_is_listed_last() {
    let mut s = simple();
    let driver = padded(&payload_elf(), 6000, b"efi driver ");
    s.efi_driver(&driver);
    let image = s.build();
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/ZRAX/payload.elf",
            "/ZRAX/bin/tool.macho",
            "EFI jumpstart driver"
        ]
    );
    let efi = child(&c, "EFI jumpstart driver");
    assert_eq!(&efi.data[..], &driver[..]);
    assert!(matches!(efi.data, Cow::Borrowed(_)), "one extent: stored");
    assert!(has_note(
        &c,
        "an embedded EFI driver of 6000 B, listed last"
    ));
    // A bad magic is noted.
    let mut damaged = image.clone();
    put(&mut damaged, EFI_BLOCK as usize * BLOCK + 32, b"JSDX");
    let mut block = damaged[EFI_BLOCK as usize * BLOCK..(EFI_BLOCK as usize + 1) * BLOCK].to_vec();
    seal(&mut block);
    put(&mut damaged, EFI_BLOCK as usize * BLOCK, &block);
    let c = parse(&damaged);
    assert_eq!(c.children.len(), 2);
    assert!(has_note(
        &c,
        "EFI jumpstart at block 0x8 not read: Invalid EFI jumpstart magic"
    ));
}

#[test]
fn holes_read_as_zeros_and_gaps_are_errors() {
    let mut s = Synthetic::new(256);
    s.volumes.push(VolumeSpec::new("H"));
    let elf = payload_elf();
    let first = s.store(&elf);
    let records = &mut s.volumes[0].records;
    // A file of a stored block, a hole block, then a stored block.
    records.push(drec(2, "holey.elf", 16, DT_REG, true));
    records.push(file_inode(16, 2, 3 * BLOCK as u64));
    records.push(extent(16, 0, BLOCK as u64, first));
    records.push(extent(16, BLOCK as u64, BLOCK as u64, 0));
    records.push(extent(16, 2 * BLOCK as u64, BLOCK as u64, first));
    // A file whose second extent starts after a gap.
    records.push(drec(2, "gap.elf", 17, DT_REG, true));
    records.push(file_inode(17, 2, 2 * BLOCK as u64));
    records.push(extent(17, 0, BLOCK as u64, first));
    records.push(extent(17, 2 * BLOCK as u64, BLOCK as u64, first));
    let image = s.build();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/H/holey.elf"]);
    let holey = &c.children[0];
    assert_eq!(holey.transform, Some("APFS extents"));
    assert_eq!(&holey.data[BLOCK..2 * BLOCK], &[0u8; BLOCK][..]);
    assert_eq!(&holey.data[..elf.len()], &elf[..]);
    assert!(has_note(
        &c,
        "Skipped /H/gap.elf: Invalid file extents: an extent at 0x2000 where 0x1000 was expected"
    ));
}

/// Rewrite node `block` of `image` with `edit` applied, and reseal it.
fn edit_block(image: &mut [u8], block: u64, edit: impl FnOnce(&mut [u8])) {
    let at = block as usize * BLOCK;
    let mut copy = image[at..at + BLOCK].to_vec();
    edit(&mut copy);
    seal(&mut copy);
    put(image, at, &copy);
}

#[test]
fn damaged_trees_and_objects_are_noted_without_failing_the_container() {
    let base = VOLUME_BASE;
    // The tree root of the only volume claims level 3 with no children.
    let mut image = simple().build();
    edit_block(&mut image, base + 3, |node| put16(node, 34, 3));
    let c = parse(&image);
    assert!(c.children.is_empty());
    assert!(
        has_note(
            &c,
            "/ZRAX: file-system tree not read: Invalid B-tree node flags 0x3 in block 0x17 at \
             level 3"
        ),
        "{:?}",
        c.notes
    );

    // Keys out of order in the root leaf.
    let mut image = simple().build();
    edit_block(&mut image, base + 3, |node| {
        let key_start = 56 + usize::from(le16(node, 42));
        let first_key = key_start + usize::from(le16(node, 56));
        put64(node, first_key, 99 | APFS_TYPE_INODE << 60);
    });
    let c = parse(&image);
    assert!(
        has_note(&c, "Invalid B-tree: keys out of order"),
        "{:?}",
        c.notes
    );

    // A table of contents larger than its space.
    let mut image = simple().build();
    edit_block(&mut image, base + 3, |node| put32(node, 36, 4000));
    let c = parse(&image);
    assert!(has_note(
        &c,
        "/ZRAX: file-system tree not read: Invalid B-tree node"
    ));

    // The volume object map lacks the tree root.
    let mut image = simple().build();
    edit_block(&mut image, base + 2, |node| {
        let key_start = 56 + usize::from(le16(node, 42));
        put64(node, key_start, 77);
    });
    let c = parse(&image);
    assert!(has_note(
        &c,
        "/ZRAX: file-system tree not read: Missing object map entry for object 0x404"
    ));

    // A volume superblock with a bad checksum.
    let mut image = simple().build();
    image[base as usize * BLOCK + 900] ^= 1;
    let c = parse(&image);
    assert!(has_note(
        &c,
        "Volume 0 (object 0x402) not read: Invalid object checksum in block 0x14"
    ));

    // The container object map is damaged.
    let mut image = simple().build();
    image[NX_OMAP_BLOCK as usize * BLOCK + 40] ^= 1;
    let c = parse(&image);
    assert!(has_note(
        &c,
        "Container object map at block 0xA not read; no volume was read"
    ));
}

#[test]
fn a_child_node_at_the_wrong_level_cannot_make_the_walk_cycle() {
    let mut s = simple();
    s.volumes[0].leaf_capacity = 2;
    let mut image = s.build();
    // Point the first index entry of the root at the root itself.
    let root = VOLUME_BASE + 3;
    edit_block(&mut image, root, |node| {
        let value_end = BLOCK - 40;
        let value = value_end - usize::from(le16(node, 56 + 4));
        put64(node, value, tree_oid(0, 0));
    });
    let c = parse(&image);
    assert!(c.children.is_empty());
    assert!(
        has_note(&c, "Invalid B-tree node") || has_note(&c, "level"),
        "{:?}",
        c.notes
    );
}

// ---------------------------------------------------------------------------
// Truncation and mutation sweeps
// ---------------------------------------------------------------------------

#[test]
fn a_container_cut_short_lists_only_what_is_present() {
    let image = apfs_img();
    let full = parse(&image);
    // Every block boundary, and one byte after it.
    for end in (0..=image.len())
        .step_by(BLOCK)
        .flat_map(|end| [end, end + 1])
    {
        let prefix = &image[..end.min(image.len())];
        let Some(layout) = apfs::detect(prefix) else {
            assert!(prefix.len() < 48, "prefix {end} is detected");
            continue;
        };
        let Ok(c) = apfs::parse_container(prefix, layout) else {
            assert!(prefix.len() < BLOCK, "prefix {end} with block 0 fails");
            continue;
        };
        for member in &c.children {
            let whole = child(&full, &member.label);
            assert_eq!(member.data, whole.data, "prefix {end}: {}", member.label);
            assert!(member.offset + member.stored_size <= prefix.len());
        }
        if prefix.len() < image.len() - BLOCK {
            assert!(has_note(&c, "Truncated container"), "prefix {end}");
        }
    }
    // In the fixture the latest metadata follows the file data, so a cut
    // inside the fragmented file also loses the container object map.
    let fragmented = child(&full, "/ZRAX/bin/fragmented.elf");
    let c = parse(&image[..fragmented.offset + 2 * BLOCK]);
    assert!(c.children.is_empty());
    assert!(
        has_note(&c, "Container object map at block 0x"),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "1 object read was skipped because its block lies beyond the"
    ));
}

#[test]
fn a_member_whose_blocks_are_cut_off_is_skipped_with_a_note() {
    // The synthetic metadata precedes the data (from block 128), so a cut
    // inside the second file keeps the first.
    let mut s = Synthetic::new(512);
    s.volumes.push(VolumeSpec::new("ZRAX"));
    s.file(0, 2, 16, "a.elf", &payload_elf());
    let large = padded(&kernel_macho(), 16 * BLOCK, b"zrax cut member ");
    s.file(0, 2, 17, "b.macho", &large);
    let image = s.build();
    let cut = (DATA_BASE as usize + 1 + 8) * BLOCK;
    let c = parse(&image[..cut]);
    assert_eq!(labels(&c), ["/ZRAX/a.elf"]);
    assert!(
        has_note(
            &c,
            "Skipped /ZRAX/b.macho: Truncated container: block 0x89 is not present (137 blocks \
             present)"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "Truncated container: 137 of its 512 blocks are present"
    ));
    assert_eq!(c.consumed, cut);
}

#[test]
fn every_short_prefix_is_rejected() {
    let image = apfs_cs_img();
    for end in 0..2 * BLOCK {
        let prefix = &image[..end];
        if let Some(layout) = apfs::detect(prefix) {
            let parsed = apfs::parse_container(prefix, layout);
            assert_eq!(parsed.is_err(), end < BLOCK, "prefix {end}");
        }
    }
    for end in (0..image.len()).step_by(65_537) {
        let prefix = &image[..end];
        if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
            if p.format.format == FileFormat::Apfs {
                for slice in &p.slices {
                    assert!(slice.offset + slice.size <= end as u64, "prefix {end}");
                }
            }
        }
    }
}

/// Parse `image` if it is detected; the result does not matter, only that
/// parsing returns.
fn try_parse(image: &[u8]) {
    if let Some(layout) = apfs::detect(image) {
        let _ = apfs::parse_container(image, layout);
    }
}

/// Parse `image` with `at` replaced by each of 0x00, 0xFF and the byte with
/// its low bit flipped, then with its block resealed, so that the damage
/// passes the checksum and reaches the structure checks; it must not panic.
/// The image is restored afterwards.
fn mutate(image: &mut [u8], at: usize) {
    let block = at / BLOCK * BLOCK;
    let saved = image[block..block + BLOCK].to_vec();
    for value in [0x00, 0xff, saved[at - block] ^ 0x01] {
        image[at] = value;
        try_parse(image);
        let checksum = fletcher64(&image[block..block + BLOCK]);
        put64(image, block, checksum);
        try_parse(image);
        image[block..block + BLOCK].copy_from_slice(&saved);
    }
}

/// Blocks of `image` holding an object whose checksum verifies.
fn object_blocks(image: &[u8]) -> Vec<usize> {
    (0..image.len() / BLOCK)
        .filter(|&n| {
            let block = &image[n * BLOCK..(n + 1) * BLOCK];
            let stored = le64(block, 0);
            stored != 0 && stored == fletcher64(block)
        })
        .collect()
}

#[test]
fn byte_mutations_of_the_metadata_never_panic() {
    for mut image in [apfs_cs_img(), simple().build()] {
        let blocks = object_blocks(&image);
        assert!(blocks.len() >= 8, "{} object blocks", blocks.len());
        for block in blocks {
            // The header and node fields every byte, the rest every 13th.
            let start = block * BLOCK;
            let fields = start..start + 64;
            let rest = (start + 64..start + BLOCK).step_by(13);
            for at in fields.chain(rest) {
                mutate(&mut image, at);
            }
        }
    }
}

#[test]
fn byte_mutations_of_the_whole_image_never_panic_the_classifier() {
    let mut image = apfs_cs_img();
    for block in object_blocks(&image) {
        for at in (block * BLOCK..(block + 1) * BLOCK).step_by(611) {
            image[at] ^= 0xff;
            let _ = detect_payload(&image, &ClassifierOptions::new());
            image[at] ^= 0xff;
        }
    }
    // The stored bytes of the decoded members: the decoders see damaged
    // streams.
    let mut image = apfs_img();
    let runs: Vec<std::ops::Range<usize>> = parse(&image)
        .children
        .iter()
        .filter(|m| matches!(m.data, Cow::Owned(_)))
        .map(|m| m.offset..m.offset + m.stored_size)
        .collect();
    for run in runs {
        for at in run.step_by(37) {
            image[at] ^= 0x01;
            try_parse(&image);
            image[at] ^= 0x01;
        }
    }
}

// ---------------------------------------------------------------------------
// Sample scans (skipped without the environment variables)
// ---------------------------------------------------------------------------

/// A directory waiting to be listed, `depth` levels below the sample
/// directory.
struct SampleDirectory {
    path: std::path::PathBuf,
    depth: usize,
}

/// Regular files of at most `max_size` bytes in `dir` and the directories
/// up to `max_depth` levels below it, sorted.
fn sample_files(dir: &str, max_size: u64, max_depth: usize) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![SampleDirectory {
        path: std::path::PathBuf::from(dir),
        depth: 0,
    }];
    while let Some(SampleDirectory { path, depth }) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() && depth < max_depth {
                pending.push(SampleDirectory {
                    path: entry.path(),
                    depth: depth + 1,
                });
            } else if meta.is_file() && meta.len() <= max_size {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files
}

/// `APFS_SAMPLE_DIR` names a directory of disk images (for example
/// `~/Downloads`). Each image of at most 256 MiB, in the directory or up to
/// two levels below it, is classified; every APFS
/// container reached directly or as a disk image's or partition table's
/// child must parse, and `AudirvanaStudio_3.3.104.dmg` (an `Apple_APFS`
/// partition cut at the 64 MiB disk-image extraction limit) must be reached.
#[test]
fn local_disk_images_with_apfs_containers_parse() {
    let Ok(dir) = std::env::var("APFS_SAMPLE_DIR") else {
        eprintln!("APFS_SAMPLE_DIR not set; skipped");
        return;
    };
    let mut containers = 0;
    for path in sample_files(&dir, 256 << 20, 2) {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if !(name.ends_with(".dmg") || name.ends_with(".img") || name.ends_with(".iso")) {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let mut found = Vec::new();
        if apfs::detect(&data).is_some() {
            found.push(parse(&data).children.len());
        }
        if let DetectedFormat::Container { kind } = detect_format(&data) {
            if let Ok(outer) = zrax::formats::container::parse(&data, kind) {
                for part in &outer.children {
                    if let Some(layout) = apfs::detect(&part.data) {
                        let c = apfs::parse_container(&part.data, layout)
                            .unwrap_or_else(|e| panic!("{name} {}: {e}", part.label));
                        eprintln!(
                            "{name} {}: {} members; {}",
                            part.label,
                            c.children.len(),
                            c.notes.join(" | ")
                        );
                        found.push(c.children.len());
                    }
                }
            }
        }
        let _ = detect_payload(&data, &ClassifierOptions::new());
        if name == "AudirvanaStudio_3.3.104.dmg" {
            assert_eq!(found.len(), 1, "{name}: one APFS container is reached");
        }
        containers += found.len();
    }
    eprintln!("{containers} APFS containers parsed");
}

/// `IDA_INPUT_DIR` names IDA Pro's test inputs: none of them, in any
/// directory up to 16 levels below, may be detected as an APFS container.
#[test]
fn ida_inputs_are_not_apfs_containers() {
    let Ok(dir) = std::env::var("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR not set; skipped");
        return;
    };
    let mut scanned = 0;
    for path in sample_files(&dir, u64::MAX, 16) {
        // Detection reads the first 48 bytes; 4 KiB is block 0.
        let mut head = vec![0u8; 4096];
        let Ok(mut file) = std::fs::File::open(&path) else {
            continue;
        };
        let Ok(read) = std::io::Read::read(&mut file, &mut head) else {
            continue;
        };
        scanned += 1;
        assert!(
            apfs::detect(&head[..read]).is_none(),
            "{} detected",
            path.display()
        );
    }
    eprintln!("{scanned} IDA inputs scanned");
}
