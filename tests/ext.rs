//! ext2, ext3 and ext4 filesystem images: mke2fs fixtures (block maps,
//! extent trees, htree directories, hard links, `metadata_csum`),
//! synthetic images built from the `ext4.h` layouts for what the fixtures
//! do not cover (ext3, `gdt_csum`, `meta_bg`, 64 KiB blocks, unwritten
//! extents, encrypted and inline files, limits), corrupted fields and
//! checksums, and truncation and mutation sweeps.

use zrax::formats::checksum::crc16_modbus_update;
use zrax::formats::container::{Child, Container};
use zrax::formats::ext::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// The synthetic x86-64 ELF that `generate.sh` copies into the images.
fn payload_elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse an image that must be valid.
fn parse(image: &[u8]) -> Container<'_> {
    let layout = ext::detect(image).expect("detected as ext");
    ext::parse_container(image, layout).expect("parses")
}

/// The error text of an image that is detected but does not parse.
fn parse_error(image: &[u8]) -> String {
    let layout = ext::detect(image).expect("detected as ext");
    ext::parse_container(image, layout)
        .expect_err("does not parse")
        .to_string()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("{label} is listed: {:?}", labels(c)))
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|note| note.contains(text))
}

fn le_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

// ---------------------------------------------------------------------------
// mke2fs fixtures (tests/fixtures/ext/README.md)
// ---------------------------------------------------------------------------

/// The regular files of the fixture tree that are recognized formats, in
/// walk order: the root's files, then subdirectories in entry order.
const MEMBERS: [&str; 4] = [
    "/payload.elf",
    "/bin/sparse.elf",
    "/boot/payload.elf.gz",
    "/many/member-entry-160.elf",
];

/// `bin/sparse.elf` as `generate.sh` writes it: `payload.elf`, then one
/// text line at each of 64, 128, 192, 256 and 300 KiB, 310 KiB in all.
fn sparse_elf() -> Vec<u8> {
    let mut bytes = vec![0u8; 310 << 10];
    let elf = payload_elf();
    bytes[..elf.len()].copy_from_slice(&elf);
    for kib in [64, 128, 192, 256, 300] {
        let line = format!("zrax sparse region at {kib} KiB\n");
        bytes[kib << 10..(kib << 10) + line.len()].copy_from_slice(line.as_bytes());
    }
    bytes
}

/// Position of the directory record named `name` in an image, from its
/// layout: `inode` (4), `rec_len` (2), `name_len` (1), `file_type` (1),
/// then the name. Returns the record offset.
fn dirent(image: &[u8], name: &[u8]) -> usize {
    image
        .windows(name.len())
        .enumerate()
        .find(|&(at, window)| window == name && at >= 8 && usize::from(image[at - 2]) == name.len())
        .map(|(at, _)| at - 8)
        .unwrap_or_else(|| panic!("record {:?} is in the image", String::from_utf8_lossy(name)))
}

/// File offset of inode `number`'s record. The fixtures have one block
/// group whose descriptor follows the superblock's block; `bg_inode_table_lo`
/// is at descriptor offset 8.
fn inode_offset(image: &[u8], block_size: usize, inode_size: usize, number: u32) -> usize {
    let descriptors = if block_size == 1024 { 2048 } else { block_size };
    let table = le_u32(image, descriptors + 8) as usize;
    table * block_size + (number as usize - 1) * inode_size
}

#[test]
fn mke2fs_images_are_named_by_their_feature_sets() {
    assert_eq!(ext::detect(&fixture("ext/ext2.img")), Some(Layout::Ext2));
    assert_eq!(ext::detect(&fixture("ext/ext4.img")), Some(Layout::Ext4));
    for (name, label) in [("ext/ext2.img", "ext2"), ("ext/ext4.img", "ext4")] {
        let p = classify(&fixture(name));
        assert_eq!(p.format.format, FileFormat::Ext, "{name}");
        assert_eq!(p.format.variant_name.as_deref(), Some(label), "{name}");
        assert!(p.format.confidence >= 1.0, "{name}: magic-bearing");
    }
}

#[test]
fn recognized_members_are_listed_by_path_and_classified_on_their_own() {
    let elf = payload_elf();
    let gzip = fixture("compressed/payload.elf.gz");
    for name in ["ext/ext2.img", "ext/ext4.img"] {
        let image = fixture(name);
        let p = classify(&image);
        let labels: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
        assert_eq!(
            labels, MEMBERS,
            "{name}: notes.txt and the symlink are not listed"
        );
        assert!(p.slices.iter().all(|s| s.isa == Isa::X86_64), "{name}");
        assert_eq!(p.primary.isa, Isa::X86_64, "{name}");
        assert!(
            p.notes
                .iter()
                .any(|n| n.message.contains("Primary ISA selected from /payload.elf")),
            "{name}: {:?}",
            p.notes
        );
        // Contiguous members are stored as they are, at their file offset.
        for (label, bytes) in [("/payload.elf", &elf), ("/boot/payload.elf.gz", &gzip)] {
            let slice = p
                .slices
                .iter()
                .find(|s| s.label.as_deref() == Some(label))
                .expect("listed");
            let offset = slice.offset as usize;
            assert_eq!(
                &image[offset..offset + slice.size as usize],
                &bytes[..],
                "{name} {label}"
            );
            assert!(slice.decoded.is_none(), "{name} {label}");
        }
    }
}

#[test]
fn sparse_files_are_reassembled_with_holes_as_zeros() {
    let expected = sparse_elf();
    let cases = [
        ("ext/ext2.img", "ext block map", 1024),
        ("ext/ext4.img", "ext extent map", 4096),
    ];
    for (name, transform, block_size) in cases {
        let image = fixture(name);
        let c = parse(&image);
        let sparse = child(&c, "/bin/sparse.elf");
        assert_eq!(sparse.data.len(), expected.len(), "{name}");
        assert!(
            sparse.data.as_ref() == expected.as_slice(),
            "{name}: contents"
        );
        assert_eq!(sparse.transform, Some(transform), "{name}");
        // The stored range is the first run: block 0 of the file.
        assert_eq!(sparse.stored_size, block_size, "{name}");
        assert_eq!(
            &image[sparse.offset..sparse.offset + 256],
            &payload_elf()[..],
            "{name}"
        );

        let p = classify(&image);
        let slice = p
            .slices
            .iter()
            .find(|s| s.label.as_deref() == Some("/bin/sparse.elf"))
            .expect("listed");
        let decoded = slice.decoded.as_ref().expect("decoded range");
        assert_eq!(decoded.transform, transform);
        assert_eq!(decoded.size, expected.len() as u64);
        assert_eq!(slice.offset, sparse.offset as u64);
    }
}

#[test]
fn htree_directories_and_hard_links_are_walked_once() {
    for name in ["ext/ext2.img", "ext/ext4.img"] {
        let image = fixture(name);
        let c = parse(&image);
        // many/ is an htree directory (e2fsck -D); its member in a leaf block
        // is found, and its 161 hard links (160 to many/empty, one to
        // payload.elf) are examined once.
        assert!(labels(&c).contains(&"/many/member-entry-160.elf".to_string()));
        assert!(
            has_note(
                &c,
                "Directory walk: 5 directories, 6 regular files; members in a recognized format: 4"
            ),
            "{name}: {:?}",
            c.notes
        );
        assert!(
            has_note(
                &c,
                "161 directory entries name an inode already visited (hard links)"
            ),
            "{name}: {:?}",
            c.notes
        );
        assert!(
            !c.notes.iter().any(|n| n.starts_with("Skipped")),
            "{name}: {:?}",
            c.notes
        );
    }
}

#[test]
fn checksums_are_reported_as_verified_only_when_checked() {
    let ext4 = parse_owned("ext/ext4.img");
    assert!(ext4.iter().any(|n| n.starts_with(
        "metadata_csum: superblock and group descriptor checksums verified (CRC32C); inode, \
         extent block and directory block checksums verified"
    )));
    assert!(ext4
        .iter()
        .any(|n| n.contains("htree index, extended attribute and journal checksums not verified")));
    let ext2 = parse_owned("ext/ext2.img");
    assert!(ext2
        .iter()
        .any(|n| n == "The filesystem has no metadata checksums"));
    assert!(ext2
        .iter()
        .any(|n| n
            .starts_with("No processor field: s_creator_os names the operating system (Linux)")));
}

/// The notes of a fixture that must parse.
fn parse_owned(name: &str) -> Vec<String> {
    let image = fixture(name);
    parse(&image).notes
}

#[test]
fn superblock_and_descriptor_checksum_failures_are_parse_errors() {
    let image = fixture("ext/ext4.img");
    // s_volume_name is covered by s_checksum.
    let mut corrupt = image.clone();
    corrupt[1024 + 0x78] ^= 1;
    assert!(parse_error(&corrupt).contains("Invalid superblock checksum"));
    // bg_free_blocks_count_lo of group 0, in the block after the superblock.
    let mut corrupt = image.clone();
    corrupt[4096 + 0x0c] ^= 1;
    assert!(parse_error(&corrupt).contains("Invalid group descriptor 0 checksum"));
    assert!(detect_payload(&corrupt, &ClassifierOptions::new()).is_err());
}

#[test]
fn inode_extent_and_directory_checksum_failures_skip_the_entry() {
    let image = fixture("ext/ext4.img");
    let payload_inode = le_u32(&image, dirent(&image, b"payload.elf"));
    let mut corrupt = image.clone();
    // i_mtime of payload.elf's inode.
    corrupt[inode_offset(&image, 4096, 256, payload_inode) + 0x10] ^= 1;
    let c = parse(&corrupt);
    assert!(!labels(&c).contains(&"/payload.elf".to_string()));
    assert!(
        has_note(
            &c,
            &format!("Skipped /payload.elf: Invalid inode {payload_inode} checksum")
        ),
        "{:?}",
        c.notes
    );
    assert_eq!(
        classify(&corrupt).primary.isa,
        Isa::X86_64,
        "other members remain"
    );

    // The first extent of sparse.elf's leaf block, which the root's index
    // entry names (`ei_leaf_lo` at i_block + 12 + 4).
    let sparse_inode = le_u32(&image, dirent(&image, b"sparse.elf"));
    let record = inode_offset(&image, 4096, 256, sparse_inode);
    let leaf = le_u32(&image, record + 0x28 + 12 + 4) as usize;
    let mut corrupt = image.clone();
    corrupt[leaf * 4096 + 12 + 8] ^= 1;
    let c = parse(&corrupt);
    assert!(!labels(&c).contains(&"/bin/sparse.elf".to_string()));
    let expected = format!(
        "Skipped /bin/sparse.elf: Invalid inode {sparse_inode} extent block 0x{leaf:X} checksum"
    );
    assert!(has_note(&c, &expected), "{:?}", c.notes);

    // A name byte in boot/'s only directory block.
    let mut corrupt = image.clone();
    corrupt[dirent(&image, b"payload.elf.gz") + 8] ^= 1;
    let c = parse(&corrupt);
    assert!(!labels(&c).contains(&"/boot/payload.elf.gz".to_string()));
    assert!(
        has_note(&c, "Skipped /boot directory block 0: invalid checksum"),
        "{:?}",
        c.notes
    );
}

#[test]
fn damaged_block_maps_and_records_are_skipped_with_notes() {
    let image = fixture("ext/ext2.img");
    let sparse_inode = le_u32(&image, dirent(&image, b"sparse.elf"));
    let record = inode_offset(&image, 1024, 128, sparse_inode);
    let mut corrupt = image.clone();
    // i_block[13], the double-indirect block, beyond the 256 blocks.
    corrupt[record + 0x28 + 13 * 4..record + 0x28 + 14 * 4]
        .copy_from_slice(&0x0100_0000u32.to_le_bytes());
    let c = parse(&corrupt);
    assert!(!labels(&c).contains(&"/bin/sparse.elf".to_string()));
    let expected = format!(
        "Skipped /bin/sparse.elf: Invalid inode {sparse_inode} block map entry 0x1000000 beyond \
         the filesystem"
    );
    assert!(has_note(&c, &expected), "{:?}", c.notes);

    // rec_len 6 for bin/sparse.elf's record: the rest of the block is skipped.
    let mut corrupt = image.clone();
    let at = dirent(&image, b"sparse.elf");
    corrupt[at + 4..at + 6].copy_from_slice(&6u16.to_le_bytes());
    let c = parse(&corrupt);
    assert!(
        has_note(
            &c,
            "Skipped the rest of /bin directory block 0: invalid entry at 0x"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "rec_len is smaller than minimal"));

    // A root inode that is a regular file makes the image unreadable.
    let mut corrupt = image.clone();
    let root = inode_offset(&image, 1024, 128, 2);
    corrupt[root..root + 2].copy_from_slice(&0x81a4u16.to_le_bytes());
    assert_eq!(
        parse_error(&corrupt),
        "ext filesystem parse error: Invalid root inode: mode 0x81A4 is not a directory"
    );
}

#[test]
fn every_prefix_of_a_fixture_is_an_error() {
    for name in ["ext/ext2.img", "ext/ext4.img"] {
        let image = fixture(name);
        let layout = ext::detect(&image).expect("detected");
        for end in 0..image.len() {
            assert!(
                ext::parse_container(&image[..end], layout).is_err(),
                "{name}: prefix {end}"
            );
        }
        for end in (0..image.len()).step_by(4093) {
            if let Ok(p) = detect_payload(&image[..end], &ClassifierOptions::new()) {
                assert!(p.slices.is_empty(), "{name}: prefix {end} claims members");
            }
        }
    }
}

/// Byte positions to mutate: the superblock, the group descriptor, the
/// inode table and every 97th byte elsewhere.
fn mutation_positions(image: &[u8], block_size: usize, inode_size: usize) -> Vec<usize> {
    let descriptors = if block_size == 1024 { 2048 } else { block_size };
    let table = inode_offset(image, block_size, inode_size, 1);
    let mut positions: Vec<usize> = (1024..2048).collect();
    positions.extend(descriptors..descriptors + 64);
    positions.extend(table..table + 32 * inode_size);
    positions.extend((0..image.len()).step_by(97));
    positions
}

#[test]
fn fixture_mutations_never_panic() {
    for (name, block_size, inode_size) in [("ext/ext2.img", 1024, 128), ("ext/ext4.img", 4096, 256)]
    {
        let image = fixture(name);
        for at in mutation_positions(&image, block_size, inode_size) {
            for value in [0x00, 0xff, image[at] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[at] = value;
                if let Some(layout) = ext::detect(&mutated) {
                    let _ = ext::parse_container(&mutated, layout);
                }
            }
        }
        for at in (0..4096).step_by(31) {
            let mut mutated = image.clone();
            mutated[at] ^= 0xff;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

// ---------------------------------------------------------------------------
// Synthetic images (Linux v6.11 fs/ext4/ext4.h layouts)
// ---------------------------------------------------------------------------

/// `s_magic`.
const EXT4_SUPER_MAGIC: u16 = 0xef53;

/// Feature bits.
const COMPAT_HAS_JOURNAL: u32 = 0x0004;
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const INCOMPAT_COMPRESSION: u32 = 0x0001;
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;

/// `i_mode`: a directory with mode 0755 and a regular file with 0644.
const MODE_DIR: u16 = 0x41ed;
const MODE_FILE: u16 = 0x81a4;

/// `i_flags`.
const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;

/// `bg_flags`: the inode table is not initialized.
const EXT4_BG_INODE_UNINIT: u16 = 0x0001;

/// Directory record file types.
const FT_REG_FILE: u8 = 1;
const FT_DIR: u8 = 2;

/// Extent header magic and the unwritten-extent length bias.
const EXT4_EXT_MAGIC: u16 = 0xf30a;
const EXT_INIT_MAX_LEN: u16 = 1 << 15;

/// The volume UUID of every synthetic image.
const UUID: [u8; 16] = *b"zrax-ext-synth-1";

/// The block size and counts of a synthetic image with one block group.
/// Blocks from the superblock's: superblock, group descriptors, block
/// bitmap, inode bitmap, inode table, root directory, then free blocks.
#[derive(Clone, Copy)]
struct Geometry {
    log_block_size: u32,
    blocks: u32,
    inodes: u32,
}

/// 1 KiB blocks: blocks 1-4 hold the superblock, descriptors and bitmaps,
/// 5-20 the 128 inodes, 21 the root directory.
const SMALL: Geometry = Geometry {
    log_block_size: 0,
    blocks: 256,
    inodes: 128,
};

/// 64 KiB blocks: block 0 holds the superblock at byte 1024, 1 the
/// descriptors, 2-3 the bitmaps, 4 the 512 inodes, 5 the root directory.
const LARGE: Geometry = Geometry {
    log_block_size: 6,
    blocks: 8,
    inodes: 512,
};

impl Geometry {
    fn block_size(self) -> usize {
        1024 << self.log_block_size
    }

    /// 1 for 1 KiB blocks (block 0 is the boot block), else 0.
    fn first_data_block(self) -> u32 {
        u32::from(self.log_block_size == 0)
    }

    fn descriptor_block(self) -> u32 {
        self.first_data_block() + 1
    }

    fn inode_table(self) -> u32 {
        self.descriptor_block() + 3
    }

    fn root_block(self) -> u32 {
        let table_blocks = self.inodes as usize * 128 / self.block_size();
        self.inode_table() + table_blocks as u32
    }
}

/// A directory record to write.
struct DirEntry {
    inode: u32,
    file_type: u8,
    name: Vec<u8>,
}

/// A directory inode and its only block.
struct Dir {
    inode: u32,
    block: u32,
}

/// The root directory of a synthetic image.
fn root(geometry: Geometry) -> Dir {
    Dir {
        inode: 2,
        block: geometry.root_block(),
    }
}

/// A directory block and its records, written by [`Synthetic::finish`].
struct DirBlock {
    block: u32,
    entries: Vec<DirEntry>,
}

/// A synthetic filesystem under construction: revision 1, 128-byte inodes,
/// `filetype`, one block group, root inode 2 with one directory block.
struct Synthetic {
    geometry: Geometry,
    image: Vec<u8>,
    directories: Vec<DirBlock>,
    next_block: u32,
    next_inode: u32,
}

fn put_u16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// `i_block` of a block map with the given direct block numbers.
fn block_map(direct: &[u32]) -> [u8; 60] {
    let mut block = [0u8; 60];
    for (i, &number) in direct.iter().enumerate() {
        put_u32(&mut block, i * 4, number);
    }
    block
}

/// A leaf extent: `ee_block`, `ee_len` (4), `ee_start_hi` (6),
/// `ee_start_lo` (8).
fn extent(logical: u32, len: u16, physical: u32) -> [u8; 12] {
    let mut entry = [0u8; 12];
    put_u32(&mut entry, 0, logical);
    put_u16(&mut entry, 4, len);
    put_u32(&mut entry, 8, physical);
    entry
}

/// An index entry: `ei_block`, `ei_leaf_lo` (4), `ei_leaf_hi` (8).
fn extent_index(logical: u32, leaf: u32) -> [u8; 12] {
    let mut entry = [0u8; 12];
    put_u32(&mut entry, 0, logical);
    put_u32(&mut entry, 4, leaf);
    entry
}

/// An extent node of `size` bytes: `eh_magic`, `eh_entries` (2), `eh_max`
/// (4), `eh_depth` (6), `eh_generation` (8), then the entries.
fn extent_node(depth: u16, entries: &[[u8; 12]], size: usize) -> Vec<u8> {
    let mut node = vec![0u8; size];
    put_u16(&mut node, 0, EXT4_EXT_MAGIC);
    put_u16(&mut node, 2, entries.len() as u16);
    put_u16(&mut node, 4, ((size - 12) / 12) as u16);
    put_u16(&mut node, 6, depth);
    for (i, entry) in entries.iter().enumerate() {
        node[12 + i * 12..24 + i * 12].copy_from_slice(entry);
    }
    node
}

/// `i_block` holding an extent tree root.
fn extent_root(depth: u16, entries: &[[u8; 12]]) -> [u8; 60] {
    extent_node(depth, entries, 60)
        .try_into()
        .expect("60 bytes")
}

impl Synthetic {
    fn new(geometry: Geometry) -> Self {
        let block_size = geometry.block_size();
        let mut s = Self {
            geometry,
            image: vec![0u8; geometry.blocks as usize * block_size],
            directories: Vec::new(),
            next_block: geometry.root_block() + 1,
            next_inode: 12,
        };
        s.superblock();
        s.group_descriptor();
        let root = geometry.root_block();
        s.inode(2, MODE_DIR, block_size as u64, 0, block_map(&[root]));
        s.directories.push(DirBlock {
            block: root,
            entries: vec![
                DirEntry {
                    inode: 2,
                    file_type: FT_DIR,
                    name: b".".to_vec(),
                },
                DirEntry {
                    inode: 2,
                    file_type: FT_DIR,
                    name: b"..".to_vec(),
                },
            ],
        });
        s
    }

    fn superblock(&mut self) {
        let g = self.geometry;
        let sb = &mut self.image[1024..2048];
        put_u32(sb, 0x00, g.inodes); // s_inodes_count: one group
        put_u32(sb, 0x04, g.blocks); // s_blocks_count_lo
        put_u32(sb, 0x14, g.first_data_block()); // s_first_data_block
        put_u32(sb, 0x18, g.log_block_size); // s_log_block_size
        put_u32(sb, 0x1c, g.log_block_size); // s_log_cluster_size: no bigalloc
        put_u32(sb, 0x20, 8192); // s_blocks_per_group
        put_u32(sb, 0x24, 8192); // s_clusters_per_group
        put_u32(sb, 0x28, g.inodes); // s_inodes_per_group
        put_u16(sb, 0x38, EXT4_SUPER_MAGIC); // s_magic
        put_u16(sb, 0x3a, 1); // s_state: cleanly unmounted
        put_u32(sb, 0x4c, 1); // s_rev_level: EXT4_DYNAMIC_REV
        put_u32(sb, 0x54, 11); // s_first_ino
        put_u16(sb, 0x58, 128); // s_inode_size
        put_u32(sb, 0x60, INCOMPAT_FILETYPE); // s_feature_incompat
        sb[0x68..0x78].copy_from_slice(&UUID); // s_uuid
    }

    /// Group 0: block bitmap, inode bitmap and inode table after the
    /// descriptor block (`bg_block_bitmap_lo`, `bg_inode_bitmap_lo` (4),
    /// `bg_inode_table_lo` (8)).
    fn group_descriptor(&mut self) {
        let g = self.geometry;
        let at = g.descriptor_block() as usize * g.block_size();
        let desc = &mut self.image[at..at + 32];
        put_u32(desc, 0x00, g.descriptor_block() + 1);
        put_u32(desc, 0x04, g.descriptor_block() + 2);
        put_u32(desc, 0x08, g.inode_table());
    }

    fn descriptor_mut(&mut self) -> &mut [u8] {
        let g = self.geometry;
        let at = g.descriptor_block() as usize * g.block_size();
        &mut self.image[at..at + 32]
    }

    fn add_features(&mut self, compat: u32, ro_compat: u32, incompat: u32) {
        let sb = &mut self.image[1024..2048];
        for (at, bits) in [(0x5c, compat), (0x64, ro_compat), (0x60, incompat)] {
            let value = u32::from_le_bytes(sb[at..at + 4].try_into().expect("4 bytes"));
            put_u32(sb, at, value | bits);
        }
    }

    /// Write inode `number`: `i_mode`, `i_size_lo` (4), `i_links_count`
    /// (0x1A), `i_flags` (0x20), `i_block` (0x28), `i_size_high` (0x6C).
    fn inode(&mut self, number: u32, mode: u16, size: u64, flags: u32, block: [u8; 60]) {
        let g = self.geometry;
        let at = g.inode_table() as usize * g.block_size() + (number as usize - 1) * 128;
        let record = &mut self.image[at..at + 128];
        put_u16(record, 0x00, mode);
        put_u32(record, 0x04, size as u32);
        put_u16(record, 0x1a, 1);
        put_u32(record, 0x20, flags);
        record[0x28..0x64].copy_from_slice(&block);
        put_u32(record, 0x6c, (size >> 32) as u32);
    }

    fn allocate(&mut self, blocks: u32) -> u32 {
        let first = self.next_block;
        self.next_block += blocks;
        assert!(
            self.next_block <= self.geometry.blocks,
            "synthetic image is full"
        );
        first
    }

    fn allocate_inode(&mut self) -> u32 {
        let number = self.next_inode;
        self.next_inode += 1;
        number
    }

    fn write_block(&mut self, block: u32, bytes: &[u8]) {
        let at = block as usize * self.geometry.block_size();
        self.image[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn link(&mut self, directory: u32, inode: u32, file_type: u8, name: &str) {
        let block = self
            .directories
            .iter_mut()
            .find(|d| d.block == directory)
            .expect("directory block exists");
        block.entries.push(DirEntry {
            inode,
            file_type,
            name: name.as_bytes().to_vec(),
        });
    }

    /// A regular file in `directory` with `contents` in consecutive
    /// blocks, mapped by direct blocks.
    fn file(&mut self, directory: u32, name: &str, contents: &[u8]) -> u32 {
        let block_size = self.geometry.block_size();
        let blocks = ((contents.len() + block_size - 1) / block_size) as u32;
        assert!(blocks <= 12, "direct blocks only");
        let first = self.allocate(blocks);
        self.write_block(first, contents);
        let direct: Vec<u32> = (first..first + blocks).collect();
        let number = self.allocate_inode();
        self.inode(
            number,
            MODE_FILE,
            contents.len() as u64,
            0,
            block_map(&direct),
        );
        self.link(directory, number, FT_REG_FILE, name);
        number
    }

    /// A subdirectory of the directory at `parent` with one block.
    fn directory(&mut self, parent: &Dir, name: &str) -> Dir {
        let block = self.allocate(1);
        let number = self.allocate_inode();
        let size = self.geometry.block_size() as u64;
        self.inode(number, MODE_DIR, size, 0, block_map(&[block]));
        self.link(parent.block, number, FT_DIR, name);
        self.directories.push(DirBlock {
            block,
            entries: vec![
                DirEntry {
                    inode: number,
                    file_type: FT_DIR,
                    name: b".".to_vec(),
                },
                DirEntry {
                    inode: parent.inode,
                    file_type: FT_DIR,
                    name: b"..".to_vec(),
                },
            ],
        });
        Dir {
            inode: number,
            block,
        }
    }

    /// Write the directory blocks: each record is `ext4_dir_rec_len` long
    /// and the last one extends to the end of the block. With `gdt_csum`,
    /// write `bg_checksum`: CRC16 of `s_uuid`, the group number and the
    /// descriptor before the checksum field.
    fn finish(mut self) -> Vec<u8> {
        let block_size = self.geometry.block_size();
        for directory in std::mem::take(&mut self.directories) {
            let mut bytes = vec![0u8; block_size];
            let mut pos = 0;
            let count = directory.entries.len();
            for (i, entry) in directory.entries.iter().enumerate() {
                let rec_len = if i + 1 == count {
                    block_size - pos
                } else {
                    (8 + entry.name.len() + 3) & !3
                };
                put_u32(&mut bytes, pos, entry.inode);
                put_u16(&mut bytes, pos + 4, rec_len as u16);
                bytes[pos + 6] = entry.name.len() as u8;
                bytes[pos + 7] = entry.file_type;
                bytes[pos + 8..pos + 8 + entry.name.len()].copy_from_slice(&entry.name);
                pos += rec_len;
            }
            self.write_block(directory.block, &bytes);
        }
        let ro_compat = le_u32(&self.image, 1024 + 0x64);
        if ro_compat & RO_COMPAT_GDT_CSUM != 0 {
            let mut crc = crc16_modbus_update(0xffff, &UUID);
            crc = crc16_modbus_update(crc, &0u32.to_le_bytes());
            crc = crc16_modbus_update(crc, &self.descriptor_mut()[..0x1e]);
            put_u16(self.descriptor_mut(), 0x1e, crc);
        }
        self.image
    }
}

/// A synthetic ext2 image whose root holds `payload.elf`.
fn synthetic_ext2() -> Vec<u8> {
    let mut s = Synthetic::new(SMALL);
    s.file(SMALL.root_block(), "payload.elf", &payload_elf());
    s.finish()
}

#[test]
fn synthetic_ext2_and_ext3_list_their_members() {
    let image = synthetic_ext2();
    assert_eq!(ext::detect(&image), Some(Layout::Ext2));
    let c = parse(&image);
    let elf = child(&c, "/payload.elf");
    assert_eq!(elf.data.as_ref(), payload_elf().as_slice());
    assert_eq!(elf.offset, 22 * 1024);
    let p = classify(&image);
    assert_eq!(
        (p.format.format, p.primary.isa),
        (FileFormat::Ext, Isa::X86_64)
    );

    let mut s = Synthetic::new(SMALL);
    s.add_features(COMPAT_HAS_JOURNAL, 0, 0);
    s.file(SMALL.root_block(), "payload.elf", &payload_elf());
    let image = s.finish();
    assert_eq!(ext::detect(&image), Some(Layout::Ext3));
    assert_eq!(
        classify(&image).format.variant_name.as_deref(),
        Some("ext3")
    );
}

#[test]
fn inconsistent_superblocks_are_not_detected() {
    let image = synthetic_ext2();
    assert!(
        ext::detect(&image[..2047]).is_none(),
        "the superblock is incomplete"
    );
    let cases: [(usize, u32); 5] = [
        (0x38, 0xef54), // s_magic
        (0x18, 7),      // s_log_block_size: 128 KiB blocks
        (0x00, 129),    // s_inodes_count other than groups x inodes per group
        (0x28, 7),      // s_inodes_per_group below the 8 inodes of one block
        (0x20, 8193),   // s_blocks_per_group above the bits of one bitmap block
    ];
    for (at, value) in cases {
        let mut corrupt = image.clone();
        if at == 0x38 {
            put_u16(&mut corrupt, 1024 + at, value as u16);
        } else {
            put_u32(&mut corrupt, 1024 + at, value);
        }
        assert!(ext::detect(&corrupt).is_none(), "field 0x{at:X} = {value}");
        assert!(
            !matches!(
                zrax::formats::detect_format(&corrupt),
                zrax::formats::DetectedFormat::Container {
                    kind: zrax::formats::container::Kind::Ext(_)
                }
            ),
            "field 0x{at:X}"
        );
    }
}

#[test]
fn unsupported_features_truncation_and_trailing_data_are_parse_errors() {
    let mut s = Synthetic::new(SMALL);
    s.add_features(0, 0, INCOMPAT_COMPRESSION);
    assert_eq!(
        parse_error(&s.finish()),
        "ext filesystem parse error: Unsupported incompatible features: compression"
    );

    let image = synthetic_ext2();
    assert!(parse_error(&image[..image.len() - 1])
        .contains("Truncated filesystem: 256 blocks of 1 KiB need 262144 B, 262143 B present"));
    for padding in [0x00, 0xff] {
        let mut padded = image.clone();
        padded.extend_from_slice(&[padding; 4096]);
        assert_eq!(parse(&padded).consumed, image.len());
    }
    let mut trailing = image.clone();
    trailing.push(0x12);
    assert_eq!(
        parse_error(&trailing),
        "ext filesystem parse error: Invalid trailing data: 1 B after the filesystem at 0x40000 \
         are not padding"
    );
}

#[test]
fn gdt_csum_descriptor_checksums_are_verified() {
    let mut s = Synthetic::new(SMALL);
    s.add_features(0, RO_COMPAT_GDT_CSUM, 0);
    s.file(SMALL.root_block(), "payload.elf", &payload_elf());
    let image = s.finish();
    let c = parse(&image);
    assert!(has_note(
        &c,
        "gdt_csum: group descriptor checksums verified (CRC16)"
    ));
    assert_eq!(labels(&c), ["/payload.elf"]);
    let mut corrupt = image.clone();
    corrupt[2 * 1024 + 0x0c] ^= 1;
    assert!(parse_error(&corrupt).contains("Invalid group descriptor 0 checksum"));
}

#[test]
fn uninitialized_inode_tables_are_not_read() {
    // bg_itable_unused: only inodes 1-12 were ever used.
    let mut s = Synthetic::new(SMALL);
    s.add_features(0, RO_COMPAT_GDT_CSUM, 0);
    s.file(SMALL.root_block(), "used.elf", &payload_elf());
    s.file(SMALL.root_block(), "unused.elf", &payload_elf());
    put_u16(s.descriptor_mut(), 0x1c, (SMALL.inodes - 12) as u16);
    let image = s.finish();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/used.elf"]);
    assert!(
        has_note(
            &c,
            "Skipped /unused.elf: Invalid inode 13: uninitialized in group 0's inode table"
        ),
        "{:?}",
        c.notes
    );

    let mut s = Synthetic::new(SMALL);
    s.add_features(0, RO_COMPAT_GDT_CSUM, 0);
    put_u16(s.descriptor_mut(), 0x12, EXT4_BG_INODE_UNINIT);
    assert!(parse_error(&s.finish())
        .contains("Invalid inode 2: uninitialized in group 0's inode table"));
}

#[test]
fn meta_bg_descriptors_are_read_from_their_meta_group() {
    // 33 groups of 8 blocks with 8 inodes each: descriptor block 0 (groups
    // 0-31) is block 2, descriptor block 1 (groups 32) is in group 32,
    // after its superblock backup (every group has one without
    // sparse_super): block 1 + 32 * 8 + 1 = 258.
    const GROUPS: u32 = 33;
    const BLOCKS_PER_GROUP: u32 = 8;
    let blocks = 1 + GROUPS * BLOCKS_PER_GROUP;
    let mut image = vec![0u8; blocks as usize * 1024];
    {
        let sb = &mut image[1024..2048];
        put_u32(sb, 0x00, GROUPS * 8); // s_inodes_count
        put_u32(sb, 0x04, blocks); // s_blocks_count_lo
        put_u32(sb, 0x14, 1); // s_first_data_block
        put_u32(sb, 0x20, BLOCKS_PER_GROUP); // s_blocks_per_group
        put_u32(sb, 0x24, BLOCKS_PER_GROUP); // s_clusters_per_group
        put_u32(sb, 0x28, 8); // s_inodes_per_group: one inode table block
        put_u16(sb, 0x38, EXT4_SUPER_MAGIC); // s_magic
        put_u32(sb, 0x4c, 1); // s_rev_level
        put_u32(sb, 0x54, 11); // s_first_ino
        put_u16(sb, 0x58, 128); // s_inode_size
        put_u32(sb, 0x60, INCOMPAT_FILETYPE | INCOMPAT_META_BG); // s_feature_incompat
        put_u32(sb, 0x104, 0); // s_first_meta_bg: every descriptor block is in its meta group
    }
    let first_block = |group: u32| 1 + group * BLOCKS_PER_GROUP;
    for group in 0..GROUPS {
        // Group 0: superblock 1, descriptors 2, bitmaps 3-4, table 5, root 6,
        // file 7. Group 32: backup 257, descriptors 258, bitmaps 259-260,
        // table 261, file 262. Others: bitmaps and table after the backup.
        let base = if group == 0 || group == 32 {
            first_block(group) + 2
        } else {
            first_block(group) + 1
        };
        let descriptor_block = if group < 32 { 2 } else { 258 };
        let at = descriptor_block * 1024 + (group % 32) as usize * 32;
        put_u32(&mut image, at, base); // bg_block_bitmap_lo
        put_u32(&mut image, at + 4, base + 1); // bg_inode_bitmap_lo
        put_u32(&mut image, at + 8, base + 2); // bg_inode_table_lo
    }
    // Root inode 2 (group 0, table block 5) with directory block 6.
    let root = 5 * 1024 + 128;
    put_u16(&mut image, root, MODE_DIR);
    put_u32(&mut image, root + 4, 1024);
    put_u16(&mut image, root + 0x1a, 2);
    put_u32(&mut image, root + 0x28, 6);
    // Inode 257 (group 32, index 0, table block 261) maps block 262.
    let file = 261 * 1024;
    let elf = payload_elf();
    put_u16(&mut image, file, MODE_FILE);
    put_u32(&mut image, file + 4, elf.len() as u32);
    put_u16(&mut image, file + 0x1a, 1);
    put_u32(&mut image, file + 0x28, 262);
    image[262 * 1024..262 * 1024 + elf.len()].copy_from_slice(&elf);
    // Root directory: ".", "..", "payload.elf" -> 257.
    let dir = 6 * 1024;
    for (pos, inode, rec_len, name) in [
        (0, 2, 12, &b"."[..]),
        (12, 2, 12, b".."),
        (24, 257, 1000, b"payload.elf"),
    ] {
        put_u32(&mut image, dir + pos, inode);
        put_u16(&mut image, dir + pos + 4, rec_len);
        image[dir + pos + 6] = name.len() as u8;
        image[dir + pos + 7] = if inode == 2 { FT_DIR } else { FT_REG_FILE };
        image[dir + pos + 8..dir + pos + 8 + name.len()].copy_from_slice(name);
    }
    let c = parse(&image);
    assert!(
        has_note(&c, "33 block groups; 32-bit group descriptors"),
        "{:?}",
        c.notes
    );
    assert_eq!(child(&c, "/payload.elf").offset, 262 * 1024);

    // Without descriptor block 258, group 32's descriptor is zeros.
    let mut corrupt = image.clone();
    corrupt[258 * 1024..259 * 1024].fill(0);
    assert!(parse_error(&corrupt).contains("Invalid group 32 block bitmap 0x0"));
}

#[test]
fn large_blocks_decode_whole_block_records() {
    let mut s = Synthetic::new(LARGE);
    // A second root block whose only record spans the 64 KiB block: the
    // stored rec_len 0xFFFF stands for 65536.
    let second = s.allocate(1);
    let elf = payload_elf();
    let data_block = s.allocate(1);
    s.write_block(data_block, &elf);
    let number = s.allocate_inode();
    s.inode(
        number,
        MODE_FILE,
        elf.len() as u64,
        0,
        block_map(&[data_block]),
    );
    let root = LARGE.root_block();
    s.inode(2, MODE_DIR, 2 << 16, 0, block_map(&[root, second]));
    let mut image = s.finish();
    let at = second as usize * LARGE.block_size();
    put_u32(&mut image, at, number);
    put_u16(&mut image, at + 4, 0xffff);
    image[at + 6] = 7;
    image[at + 7] = FT_REG_FILE;
    image[at + 8..at + 15].copy_from_slice(b"big.elf");
    let c = parse(&image);
    assert!(
        has_note(&c, "ext2 filesystem: 64 KiB blocks"),
        "{:?}",
        c.notes
    );
    assert_eq!(labels(&c), ["/big.elf"]);
    assert!(
        !c.notes.iter().any(|n| n.starts_with("Skipped")),
        "{:?}",
        c.notes
    );
}

#[test]
fn extent_trees_read_unwritten_extents_and_index_blocks() {
    let block_size = SMALL.block_size();
    let mut s = Synthetic::new(SMALL);
    s.add_features(0, 0, INCOMPAT_EXTENTS);
    let elf = payload_elf();
    // Logical 0: the ELF; logical 1: an unwritten extent over garbage;
    // logical 3: text, reached through a depth-1 index.
    let data = s.allocate(3);
    s.write_block(data, &elf);
    s.write_block(data + 1, &vec![0xaa; block_size]);
    s.write_block(data + 2, b"third block");
    let leaf = s.allocate(1);
    let leaf_node = extent_node(
        0,
        &[
            extent(0, 1, data),
            extent(1, EXT_INIT_MAX_LEN + 1, data + 1),
            extent(3, 1, data + 2),
        ],
        block_size,
    );
    s.write_block(leaf, &leaf_node);
    let number = s.allocate_inode();
    let size = 4 * block_size as u64;
    s.inode(
        number,
        MODE_FILE,
        size,
        EXT4_EXTENTS_FL,
        extent_root(1, &[extent_index(0, leaf)]),
    );
    s.link(SMALL.root_block(), number, FT_REG_FILE, "tree.elf");
    let image = s.finish();
    assert_eq!(ext::detect(&image), Some(Layout::Ext4));
    let c = parse(&image);
    let tree = child(&c, "/tree.elf");
    assert_eq!(tree.transform, Some("ext extent map"));
    assert_eq!(&tree.data[..elf.len()], &elf[..]);
    assert!(
        tree.data[block_size..3 * block_size]
            .iter()
            .all(|&b| b == 0),
        "unwritten and hole"
    );
    assert_eq!(
        &tree.data[3 * block_size..3 * block_size + 11],
        b"third block"
    );

    // eh_depth 6 is deeper than EXT4_MAX_EXTENT_DEPTH.
    let mut corrupt = image.clone();
    let record = SMALL.inode_table() as usize * block_size + (number as usize - 1) * 128;
    put_u16(&mut corrupt, record + 0x28 + 6, 6);
    let c = parse(&corrupt);
    assert!(
        has_note(
            &c,
            &format!("Skipped /tree.elf: Invalid inode {number} extent depth 6 (at most 5)")
        ),
        "{:?}",
        c.notes
    );
    // Overlapping extents.
    let mut corrupt = image.clone();
    let second_extent = leaf as usize * block_size + 24;
    put_u32(&mut corrupt, second_extent, 0);
    let c = parse(&corrupt);
    assert!(
        has_note(&c, "it overlaps the previous extent"),
        "{:?}",
        c.notes
    );
}

#[test]
fn encrypted_and_inline_files_are_not_read() {
    let mut s = Synthetic::new(SMALL);
    s.add_features(0, 0, INCOMPAT_ENCRYPT | INCOMPAT_INLINE_DATA);
    let elf = payload_elf();
    for (name, flags) in [
        ("secret.elf", EXT4_ENCRYPT_FL),
        ("inline.elf", EXT4_INLINE_DATA_FL),
    ] {
        let block = s.allocate(1);
        s.write_block(block, &elf);
        let number = s.allocate_inode();
        s.inode(
            number,
            MODE_FILE,
            elf.len() as u64,
            flags,
            block_map(&[block]),
        );
        s.link(SMALL.root_block(), number, FT_REG_FILE, name);
    }
    let image = s.finish();
    let c = parse(&image);
    assert!(c.children.is_empty(), "{:?}", labels(&c));
    assert!(
        has_note(
            &c,
            "1 encrypted file and 0 encrypted directories are opaque and were not read"
        ),
        "{:?}",
        c.notes
    );
    assert!(
        has_note(
            &c,
            "1 file and 0 directories store inline data, which is not implemented"
        ),
        "{:?}",
        c.notes
    );
}

#[test]
fn deep_trees_cycles_and_large_files_are_bounded() {
    let mut s = Synthetic::new(SMALL);
    let elf = payload_elf();
    let mut parent = root(SMALL);
    for level in 0..70 {
        let directory = s.directory(&parent, &format!("d{level}"));
        if level == 62 {
            s.file(directory.block, "shallow.elf", &elf);
        }
        if level == 0 {
            // A link back to the root: a cycle.
            s.link(directory.block, 2, FT_DIR, "loop");
        }
        parent = directory;
    }
    s.file(parent.block, "deep.elf", &elf);
    // A sparse 65 MiB file whose first block is an ELF header.
    let block = s.allocate(1);
    s.write_block(block, &elf);
    let number = s.allocate_inode();
    s.inode(number, MODE_FILE, 65 << 20, 0, block_map(&[block]));
    s.link(SMALL.root_block(), number, FT_REG_FILE, "huge.elf");
    let image = s.finish();
    let c = parse(&image);
    let shallow: String = (0..63)
        .map(|level| format!("/d{level}"))
        .collect::<String>()
        + "/shallow.elf";
    assert_eq!(labels(&c), [shallow]);
    assert!(
        has_note(&c, "1 directory deeper than 64 levels was not walked"),
        "{:?}",
        c.notes
    );
    assert!(
        has_note(&c, "1 directory entry names an inode already visited"),
        "{:?}",
        c.notes
    );
    assert!(
        has_note(
            &c,
            "1 recognized file exceeds the 64 MiB extraction limit; not extracted"
        ),
        "{:?}",
        c.notes
    );
}

#[test]
fn the_total_extraction_limit_stops_extraction() {
    // Five sparse 60 MiB files: four fit in the 256 MiB limit.
    let mut s = Synthetic::new(SMALL);
    let elf = payload_elf();
    for i in 0..5 {
        let block = s.allocate(1);
        s.write_block(block, &elf);
        let number = s.allocate_inode();
        s.inode(number, MODE_FILE, 60 << 20, 0, block_map(&[block]));
        s.link(
            SMALL.root_block(),
            number,
            FT_REG_FILE,
            &format!("part{i}.elf"),
        );
    }
    let image = s.finish();
    let c = parse(&image);
    assert_eq!(c.children.len(), 4);
    assert!(c.children.iter().all(|child| child.data.len() == 60 << 20));
    assert!(
        has_note(
            &c,
            "1 recognized file was not extracted: the 256 MiB total extraction limit was reached"
        ),
        "{:?}",
        c.notes
    );
}

#[test]
fn synthetic_mutations_and_truncations_never_panic() {
    let mut s = Synthetic::new(SMALL);
    s.add_features(0, RO_COMPAT_GDT_CSUM, INCOMPAT_EXTENTS);
    let elf = payload_elf();
    s.file(SMALL.root_block(), "payload.elf", &elf);
    let sub = s.directory(&root(SMALL), "sub").block;
    let data = s.allocate(1);
    s.write_block(data, &elf);
    let number = s.allocate_inode();
    s.inode(
        number,
        MODE_FILE,
        3 << 10,
        EXT4_EXTENTS_FL,
        extent_root(0, &[extent(0, 1, data), extent(2, 1, data)]),
    );
    s.link(sub, number, FT_REG_FILE, "extents.elf");
    // Every used block: metadata, directories and file data.
    let used_end = s.next_block as usize * SMALL.block_size();
    let image = s.finish();
    assert_eq!(parse(&image).children.len(), 2);
    for at in 1024..used_end {
        for value in [0x00, 0xff, image[at] ^ 0x01] {
            let mut mutated = image.clone();
            mutated[at] = value;
            if let Some(layout) = ext::detect(&mutated) {
                let _ = ext::parse_container(&mutated, layout);
            }
        }
    }
    for end in (0..image.len()).step_by(257) {
        let _ = detect_payload(&image[..end], &ClassifierOptions::new());
    }
}
