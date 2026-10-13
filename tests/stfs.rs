//! Xbox 360 STFS packages: synthetic CON, LIVE and PIRS packages built from
//! the documented layout (Free60 "STFS", Velocity `StfsPackage.cpp` and
//! `XContentHeader.cpp`, xenia `stfs_xbox.h`), covering the read-only and
//! two-copy hash table formats, consecutive and chained files with XEX2
//! members, directory paths, SHA-1 checks, an SVOD header, corrupted
//! structures, and truncation and mutation sweeps.

use zrax::formats::checksum::Sha1;
use zrax::formats::container::{self, Child, Classify, Container, Kind};
use zrax::formats::stfs::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// Block size (Free60).
const BLOCK: usize = 0x1000;

/// Hash records per table, and data blocks per level-0 table.
const RECORDS: usize = 170;

/// A hash record: SHA-1, status byte, 24-bit big-endian next block.
const RECORD: usize = 0x18;
const END_OF_CHAIN: u32 = 0xFF_FFFF;

/// Level-0 status of an allocated block (Free60), and the level-1 status
/// bit that selects the second copy of a level-0 table (Velocity).
const ALLOCATED: u8 = 0x80;
const ACTIVE_INDEX: u8 = 0x40;

/// Block separation flags (xenia `StfsVolumeDescriptor`).
const READ_ONLY_FORMAT: u8 = 0x01;
const ROOT_ACTIVE_INDEX: u8 = 0x02;

/// File table entry flags and the root's directory index (Free60).
const CONSECUTIVE: u8 = 0x40;
const DIRECTORY: u8 = 0x80;
const ROOT: u16 = 0xFFFF;

/// Header sizes Velocity writes for one and two hash table copies.
const HEADER_READ_ONLY: u32 = 0xAD0E;
const HEADER_TWO_COPIES: u32 = 0x971A;

/// Title ID and display name of every fixture.
const TITLE_ID: u32 = 0x4D53_07E6;
const DISPLAY_NAME: &str = "Zrax Test Pack";
const TITLE_NAME: &str = "Zrax";

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    container::parse(data, Kind::Stfs(layout)).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    container::parse(data, Kind::Stfs(layout))
        .expect_err("is a parse error")
        .to_string()
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("child {label} in {:?}", labels(c)))
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|n| n.contains(text))
}

fn assert_note(c: &Container<'_>, text: &str) {
    assert!(has_note(c, text), "no note {text:?} in {:#?}", c.notes);
}

fn slice_labels(p: &DetectionPayload) -> Vec<String> {
    p.slices
        .iter()
        .map(|s| s.label.clone().unwrap_or_default())
        .collect()
}

fn metadata<'p>(p: &'p DetectionPayload, key: &str) -> &'p zrax::MetadataValue {
    &p.metadata
        .iter()
        .find(|m| m.key == zrax::MetadataKey::Custom(key.into()))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
}

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finish()
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put_be16(data: &mut [u8], at: usize, value: u16) {
    put(data, at, &value.to_be_bytes());
}

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_be_bytes());
}

fn put_be24(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_be_bytes()[1..]);
}

fn put_le16(data: &mut [u8], at: usize, value: u16) {
    put(data, at, &value.to_le_bytes());
}

fn put_le24(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_le_bytes()[..3]);
}

/// `text` as UTF-16BE.
fn utf16be(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// `value` rounded up to whole blocks.
fn round_up_to_block(value: usize) -> usize {
    match value % BLOCK {
        0 => value,
        rest => value + BLOCK - rest,
    }
}

// --- Member fixtures --------------------------------------------------------

/// An XEX2 header (the layout `console.rs` reads): `XEX2`, module flags 1
/// (title), PE offset 0x40, reserved, security offset 0x20, no optional
/// headers; then PowerPC `nop`s (0x60000000) up to `size`.
fn xex(size: usize) -> Vec<u8> {
    let mut xex: Vec<u8> = [0x60, 0, 0, 0].iter().copied().cycle().take(size).collect();
    xex[..0x40].fill(0);
    put(&mut xex, 0, b"XEX2");
    put_be32(&mut xex, 4, 1);
    put_be32(&mut xex, 8, 0x40);
    put_be32(&mut xex, 16, 0x20);
    xex
}

const README: &[u8] = b"Synthetic STFS fixture for zrax; no game data.\n";

// --- Package builder ---------------------------------------------------------

/// A file table entry (Free60 "File Listing"; xenia `StfsDirectoryEntry`).
struct EntrySpec {
    name: &'static str,
    /// Extra flags (consecutive, directory) above the 6-bit name length.
    flags: u8,
    start_block: u32,
    /// Blocks the entry records as valid and allocated.
    block_count: u32,
    /// Index of the parent directory entry, or `ROOT`.
    parent: u16,
    size: u32,
}

/// The 64-byte entry: name (0x28, NUL-padded); name length and flags
/// (0x28); valid and allocated blocks (24-bit little-endian, 0x29 and
/// 0x2C); starting block (24-bit little-endian, 0x2F); directory index
/// (big-endian, 0x32); size (big-endian, 0x34); created and modified FAT
/// timestamps (0x38, 0x3C).
fn entry_bytes(spec: &EntrySpec) -> [u8; 0x40] {
    let mut entry = [0u8; 0x40];
    put(&mut entry, 0, spec.name.as_bytes());
    entry[0x28] = u8::try_from(spec.name.len()).expect("short name") | spec.flags;
    put_le24(&mut entry, 0x29, spec.block_count);
    put_le24(&mut entry, 0x2C, spec.block_count);
    put_le24(&mut entry, 0x2F, spec.start_block);
    put_be16(&mut entry, 0x32, spec.parent);
    put_be32(&mut entry, 0x34, spec.size);
    // 2026-10-13 12:00:00 as a FAT date (high half) and time (low half).
    put_be32(&mut entry, 0x38, 0x5D4D_6000);
    put_be32(&mut entry, 0x3C, 0x5D4D_6000);
    entry
}

/// The parts of a package: header fields, data blocks with their chain
/// pointers, and which hash table copies are active.
struct Package {
    magic: &'static [u8; 4],
    header_size: u32,
    block_separation: u8,
    /// Data blocks, 4 KiB each.
    blocks: Vec<Vec<u8>>,
    /// Next block of each data block's level-0 record.
    next: Vec<u32>,
    /// File table blocks in chain order, and the declared block count.
    file_table: Vec<u32>,
    file_table_blocks: u16,
    /// Level-0 tables whose second copy is active (two-copy format).
    second_copies: Vec<usize>,
    volume_type: u32,
}

impl Package {
    fn new(magic: &'static [u8; 4], header_size: u32, block_separation: u8, blocks: usize) -> Self {
        Self {
            magic,
            header_size,
            block_separation,
            blocks: vec![vec![0u8; BLOCK]; blocks],
            next: vec![END_OF_CHAIN; blocks],
            file_table: vec![0],
            file_table_blocks: 1,
            second_copies: Vec::new(),
            volume_type: 0,
        }
    }

    fn copies(&self) -> usize {
        if self.block_separation & READ_ONLY_FORMAT != 0 {
            1
        } else {
            2
        }
    }

    /// Store `contents` in `chain` and link the chain's records; a
    /// consecutive file keeps next block 0, as Velocity writes it.
    fn store(&mut self, chain: &[u32], contents: &[u8], consecutive: bool) {
        for (i, (&block, piece)) in chain.iter().zip(contents.chunks(BLOCK)).enumerate() {
            let block = block as usize;
            self.blocks[block][..piece.len()].copy_from_slice(piece);
            self.next[block] = if consecutive {
                0
            } else {
                chain.get(i + 1).copied().unwrap_or(END_OF_CHAIN)
            };
        }
    }

    /// Write `entries` into the file table blocks, 64 per block.
    fn file_entries(&mut self, entries: &[EntrySpec]) {
        for (i, spec) in entries.iter().enumerate() {
            let block = self.file_table[i / 64] as usize;
            put(&mut self.blocks[block], (i % 64) * 0x40, &entry_bytes(spec));
        }
        for pair in self.file_table.clone().windows(2) {
            self.next[pair[0] as usize] = pair[1];
        }
    }

    /// Backing slot (4 KiB, from the first hash table) of data block `b`
    /// below 28,900: the level-0 tables of every group up to `b`'s, and
    /// from block 170 on the first level-1 table (Velocity
    /// `ComputeBackingDataBlockNumber`).
    fn data_slot(&self, b: usize) -> usize {
        let mut tables = b / RECORDS + 1;
        if b >= RECORDS {
            tables += 1;
        }
        b + tables * self.copies()
    }

    /// Slot of the first copy of level-0 table `group`: right before the
    /// group's first block.
    fn level0_slot(&self, group: usize) -> usize {
        self.data_slot(group * RECORDS) - self.copies()
    }

    /// Slot of the first level-1 table: after level-0 table 0 and the first
    /// 170 data blocks (Velocity `blockStep[0]`).
    fn level1_slot(&self) -> usize {
        self.copies() + RECORDS
    }

    fn first_table_offset(&self) -> usize {
        round_up_to_block(self.header_size as usize)
    }

    fn block_offset(&self, b: usize) -> usize {
        self.first_table_offset() + self.data_slot(b) * BLOCK
    }

    /// Write `table` to the active copy at `slot`; the other copy of a
    /// two-copy package holds stale bytes.
    fn write_table(&self, image: &mut [u8], slot: usize, table: &[u8], second: bool) {
        let first = self.first_table_offset() + slot * BLOCK;
        let (active, stale) = if second {
            (first + BLOCK, first)
        } else {
            (first, first + BLOCK)
        };
        put(image, active, table);
        if self.copies() == 2 {
            image[stale..stale + BLOCK].fill(0xEE);
        }
    }

    /// The package: header and metadata, the volume descriptor, data blocks
    /// at their slots, level-0 tables hashing the blocks, a level-1 table
    /// hashing the level-0 tables when there are more than 170 blocks, the
    /// top table's SHA-1 in the descriptor and the header SHA-1.
    fn build(&self) -> Vec<u8> {
        let count = self.blocks.len();
        let end = self.block_offset(count - 1) + BLOCK;
        let mut image = vec![0u8; end];
        for (b, block) in self.blocks.iter().enumerate() {
            put(&mut image, self.block_offset(b), block);
        }
        // Level-0 tables, one per started group of 170 blocks.
        let groups = count / RECORDS + usize::from(count % RECORDS != 0);
        // The top table's active copy is the second one (two copies only).
        let root_second = self.copies() == 2 && self.block_separation & ROOT_ACTIVE_INDEX != 0;
        let mut level1 = vec![0u8; BLOCK];
        let mut top = Vec::new();
        for group in 0..groups {
            let mut table = vec![0u8; BLOCK];
            for b in group * RECORDS..count.min((group + 1) * RECORDS) {
                let record = (b % RECORDS) * RECORD;
                put(&mut table, record, &sha1(&self.blocks[b]));
                table[record + 0x14] = ALLOCATED;
                put_be24(&mut table, record + 0x15, self.next[b]);
            }
            let second = self.copies() == 2 && self.second_copies.contains(&group);
            if count <= RECORDS {
                self.write_table(&mut image, self.level0_slot(group), &table, root_second);
                top = table.clone();
            } else {
                self.write_table(&mut image, self.level0_slot(group), &table, second);
                put(&mut level1, group * RECORD, &sha1(&table));
                level1[group * RECORD + 0x14] = if second { ACTIVE_INDEX } else { 0 };
            }
        }
        if count > RECORDS {
            self.write_table(&mut image, self.level1_slot(), &level1, root_second);
            top = level1;
        }
        self.write_header(&mut image, count, &sha1(&top));
        image
    }

    /// Header (Free60 "Content Packages", xenia `XContentHeader` and
    /// `XContentMetadata`): magic; for `CON ` a retail console certificate
    /// (console type 2 at 0x1F); header size (0x340); content type 1
    /// (0x344); metadata version 2; title ID (0x360); platform 2; volume
    /// descriptor at 0x379 (size 0x24, block separation, file table block
    /// count little-endian, first file table block little-endian, top hash,
    /// allocated and free blocks big-endian); volume type (0x3A9); display
    /// name (UTF-16BE, 0x411) and title name (0x1691); then the header
    /// SHA-1 of 0x344 up to the first hash table at 0x32C.
    fn write_header(&self, image: &mut [u8], count: usize, top_hash: &[u8; 20]) {
        put(image, 0, self.magic);
        if self.magic == b"CON " {
            put_be16(image, 4, 0x01A8);
            put(image, 0x0B, b"X803968-001");
            image[0x1F] = 2;
        } else {
            image[4..0x104].fill(0x5A);
        }
        put_be32(image, 0x340, self.header_size);
        put_be32(image, 0x344, 1);
        put_be32(image, 0x348, 2);
        put_be32(image, 0x360, TITLE_ID);
        image[0x364] = 2;
        image[0x379] = 0x24;
        image[0x37B] = self.block_separation;
        put_le16(image, 0x37C, self.file_table_blocks);
        put_le24(image, 0x37E, self.file_table[0]);
        put(image, 0x381, top_hash);
        put_be32(image, 0x395, u32::try_from(count).expect("block count"));
        put_be32(image, 0x399, 0);
        put_be32(image, 0x3A9, self.volume_type);
        put(image, 0x411, &utf16be(DISPLAY_NAME));
        put(image, 0x1691, &utf16be(TITLE_NAME));
        let hashed = sha1(&image[0x344..self.first_table_offset()]);
        put(image, 0x32C, &hashed);
    }
}

/// Data blocks of `/media/game.xex`, chained out of order.
const GAME_CHAIN: [u32; 3] = [6, 4, 5];
const GAME_SIZE: usize = 0x2100;
const DEFAULT_SIZE: usize = 0x1800;

/// A read-only LIVE package of 8 blocks: the file table in block 0;
/// `/default.xex` in consecutive blocks 1-2 (next blocks 0); `/readme.txt`
/// in block 3; `/media/game.xex` chained through blocks 6, 4, 5; and
/// `/media/maps/level.xex` in block 7.
fn live_package() -> Package {
    let mut p = Package::new(b"LIVE", HEADER_READ_ONLY, READ_ONLY_FORMAT, 8);
    p.store(&[1, 2], &xex(DEFAULT_SIZE), true);
    p.store(&[3], README, false);
    p.store(&GAME_CHAIN, &xex(GAME_SIZE), false);
    p.store(&[7], &xex(0x40), false);
    p.file_entries(&live_entries());
    p
}

fn live_entries() -> Vec<EntrySpec> {
    vec![
        EntrySpec {
            name: "default.xex",
            flags: CONSECUTIVE,
            start_block: 1,
            block_count: 2,
            parent: ROOT,
            size: DEFAULT_SIZE as u32,
        },
        EntrySpec {
            name: "media",
            flags: DIRECTORY,
            start_block: 0,
            block_count: 0,
            parent: ROOT,
            size: 0,
        },
        EntrySpec {
            name: "readme.txt",
            flags: 0,
            start_block: 3,
            block_count: 1,
            parent: ROOT,
            size: README.len() as u32,
        },
        EntrySpec {
            name: "game.xex",
            flags: 0,
            start_block: GAME_CHAIN[0],
            block_count: 3,
            parent: 1,
            size: GAME_SIZE as u32,
        },
        EntrySpec {
            name: "maps",
            flags: DIRECTORY,
            start_block: 0,
            block_count: 0,
            parent: 1,
            size: 0,
        },
        EntrySpec {
            name: "level.xex",
            flags: 0,
            start_block: 7,
            block_count: 1,
            parent: 4,
            size: 0x40,
        },
    ]
}

/// Blocks of the two-copy CON package and of its consecutive
/// `/default.xex`, which runs across the first level-1 table and level-0
/// table 1.
const CON_BLOCKS: usize = 175;
const CON_XEX_START: u32 = 168;
const CON_XEX_SIZE: usize = 0x4800;

/// A two-copy CON package of 175 blocks (so a level-1 table exists): the
/// top table and level-0 table 1 active in their second copies; the file
/// table in block 0; `/save.dat` in block 1; `/default.xex` in consecutive
/// blocks 168-172.
fn con_package() -> Package {
    let mut p = Package::new(b"CON ", HEADER_TWO_COPIES, ROOT_ACTIVE_INDEX, CON_BLOCKS);
    p.second_copies = vec![1];
    p.store(&[1], README, false);
    let chain: Vec<u32> = (CON_XEX_START..CON_XEX_START + 5).collect();
    p.store(&chain, &xex(CON_XEX_SIZE), true);
    p.file_entries(&[
        EntrySpec {
            name: "save.dat",
            flags: 0,
            start_block: 1,
            block_count: 1,
            parent: ROOT,
            size: README.len() as u32,
        },
        EntrySpec {
            name: "default.xex",
            flags: CONSECUTIVE,
            start_block: CON_XEX_START,
            block_count: 5,
            parent: ROOT,
            size: CON_XEX_SIZE as u32,
        },
    ]);
    p
}

/// A read-only PIRS package of one block: an empty file table.
fn empty_pirs() -> Vec<u8> {
    Package::new(b"PIRS", HEADER_READ_ONLY, READ_ONLY_FORMAT, 1).build()
}

/// An XContent header of an SVOD volume (volume type 1) with two data
/// files of 0x20000 B together, and no blocks in the file.
fn svod_header() -> Vec<u8> {
    let mut image = vec![0u8; HEADER_TWO_COPIES as usize];
    put(&mut image, 0, b"LIVE");
    put_be32(&mut image, 0x340, HEADER_TWO_COPIES);
    put_be32(&mut image, 0x344, 0x7000);
    put_be32(&mut image, 0x348, 2);
    put_be32(&mut image, 0x360, TITLE_ID);
    image[0x379] = 0x24;
    put_be32(&mut image, 0x39D, 2);
    put(&mut image, 0x3A1, &0x2_0000u64.to_be_bytes());
    put_be32(&mut image, 0x3A9, 1);
    let hashed = sha1(&image[0x344..]);
    put(&mut image, 0x32C, &hashed);
    image
}

// --- Positive cases ----------------------------------------------------------

#[test]
fn live_package_lists_recognized_files_by_path() {
    let p = live_package();
    let image = p.build();
    assert_eq!(stfs::detect(&image), Some(Layout::Live));
    let c = parse(&image, Layout::Live);
    assert_eq!(c.format, FileFormat::XboxStfs);
    assert_eq!(c.variant, "Xbox 360 LIVE package");
    assert_eq!(c.target, None);
    assert_eq!(
        labels(&c),
        ["/default.xex", "/media/game.xex", "/media/maps/level.xex"]
    );
    // Consecutive blocks 1-2 are stored contiguously: borrowed as-is.
    let default = child(&c, "/default.xex");
    assert_eq!(default.offset, 0xD000);
    assert_eq!(default.offset, p.block_offset(1));
    assert_eq!(default.transform, None);
    assert_eq!(default.data.as_ref(), xex(DEFAULT_SIZE).as_slice());
    assert_eq!(default.classify, Classify::IfRecognized);
    // The chain 6, 4, 5 is reassembled; the stored range is block 6.
    let game = child(&c, "/media/game.xex");
    assert_eq!(game.offset, p.block_offset(6));
    assert_eq!(game.stored_size, BLOCK);
    assert_eq!(game.transform, Some("STFS data blocks"));
    assert_eq!(game.data.as_ref(), xex(GAME_SIZE).as_slice());
    assert_eq!(c.consumed, image.len());
    assert_note(
        &c,
        "Content type 0x00000001 (Saved Game); metadata version 2",
    );
    assert_note(&c, "Title ID 0x4D5307E6");
    assert_note(&c, "platform 2 (Xbox 360)");
    assert_note(&c, "Display name \"Zrax Test Pack\"; title \"Zrax\"");
    assert_note(
        &c,
        "Package signature present (Microsoft-signed); not verified",
    );
    assert_note(&c, "Header SHA-1 (content ID) over 0x344-0xAFFF matches");
    assert_note(
        &c,
        "STFS volume: 8 blocks allocated, 0 free; read-only format (one copy of each hash \
         table); 1 level of hash tables from 0xB000",
    );
    assert_note(
        &c,
        "File table: 1 block from block 0; 4 files, 2 directories; 3 in a recognized format listed",
    );
    assert_note(
        &c,
        "SHA-1 of the top hash table matches the volume descriptor",
    );
    assert_note(
        &c,
        "SHA-1 checked for 7 data blocks (the file table and the \
         files read in full): all match",
    );
}

#[test]
fn package_members_are_classified_by_their_own_parsers() {
    let p = classify(&live_package().build());
    assert_eq!(p.format.format, FileFormat::XboxStfs);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Xbox 360 LIVE package")
    );
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert_eq!(
        slice_labels(&p),
        ["/default.xex", "/media/game.xex", "/media/maps/level.xex"]
    );
    assert!(p.slices.iter().all(|s| s.isa == Isa::Ppc));
    let game = &p.slices[1];
    let decoded = game.decoded.as_ref().expect("reassembled member");
    assert_eq!(decoded.transform, "STFS data blocks");
    assert_eq!(decoded.size, GAME_SIZE as u64);
    assert_eq!(metadata(&p, "stfs_title_id").to_string(), "0x4D5307E6");
    assert_eq!(metadata(&p, "stfs_display_name").to_string(), DISPLAY_NAME);
    assert_eq!(metadata(&p, "stfs_title_name").to_string(), TITLE_NAME);
    assert_eq!(metadata(&p, "stfs_files").to_string(), "4");
    assert_eq!(metadata(&p, "stfs_directories").to_string(), "2");
    assert_eq!(metadata(&p, "stfs_allocated_blocks").to_string(), "8");
    assert_eq!(metadata(&p, "stfs_volume_type").to_string(), "STFS");
}

#[test]
fn two_copy_packages_read_the_active_table_copies() {
    let p = con_package();
    let image = p.build();
    assert_eq!(stfs::detect(&image), Some(Layout::Con));
    let c = parse(&image, Layout::Con);
    assert_eq!(c.variant, "Xbox 360 CON package");
    assert_eq!(labels(&c), ["/default.xex"]);
    // Blocks 168-169 precede level-1 table 0 and level-0 table 1 (two
    // copies each); blocks 170-172 follow them.
    let default = child(&c, "/default.xex");
    assert_eq!(default.offset, p.block_offset(168));
    assert_eq!(p.block_offset(170) - p.block_offset(169), 5 * BLOCK);
    assert_eq!(default.stored_size, 2 * BLOCK);
    assert_eq!(default.transform, Some("STFS data blocks"));
    assert_eq!(default.data.as_ref(), xex(CON_XEX_SIZE).as_slice());
    assert_note(
        &c,
        "Console certificate and signature present (console-signed); not verified",
    );
    assert_note(
        &c,
        "two copies of each hash table; top table copy 2 active; 2 levels of hash tables \
         from 0xA000",
    );
    assert_note(
        &c,
        "SHA-1 of the top hash table matches the volume descriptor",
    );
    assert_note(
        &c,
        "SHA-1 checked for 2 further hash tables and 6 data blocks (the file table and the \
         files read in full): all match",
    );
    let payload = classify(&image);
    assert_eq!(payload.primary.isa, Isa::Ppc);
    assert_eq!(slice_labels(&payload), ["/default.xex"]);
}

#[test]
fn empty_packages_and_svod_headers_have_no_members() {
    let pirs = empty_pirs();
    assert_eq!(stfs::detect(&pirs), Some(Layout::Pirs));
    let c = parse(&pirs, Layout::Pirs);
    assert_eq!(c.variant, "Xbox 360 PIRS package");
    assert_eq!(labels(&c), Vec::<String>::new());
    assert_note(
        &c,
        "File table: 1 block from block 0; 0 files, 0 directories",
    );
    let svod = svod_header();
    assert_eq!(stfs::detect(&svod), Some(Layout::Live));
    let c = parse(&svod, Layout::Live);
    assert_eq!(labels(&c), Vec::<String>::new());
    assert_note(&c, "Content type 0x00007000 (Game on Demand)");
    assert_note(
        &c,
        "SVOD volume: the data is in 2 separate data files of 131072 B together; not parsed",
    );
    let p = classify(&svod);
    assert_eq!(p.format.format, FileFormat::XboxStfs);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(metadata(&p, "stfs_volume_type").to_string(), "SVOD");
}

#[test]
fn an_empty_file_table_means_no_files() {
    let mut p = Package::new(b"PIRS", HEADER_READ_ONLY, READ_ONLY_FORMAT, 1);
    p.file_table_blocks = 0;
    let image = p.build();
    let c = parse(&image, Layout::Pirs);
    assert_note(&c, "The package contains no files (empty file table)");
}

#[test]
fn bytes_after_the_last_block_are_noted_and_not_consumed() {
    let mut image = live_package().build();
    let end = image.len();
    image.extend_from_slice(&[0xFF; 0x100]);
    let c = parse(&image, Layout::Live);
    assert_eq!(c.consumed, end);
    assert_note(
        &c,
        "256 B after the last allocated block at 0x14000 are not parsed",
    );
}

#[test]
fn file_tables_longer_than_1024_blocks_are_read_up_to_the_limit() {
    // 1025 chained file table blocks; only block 0 holds an entry.
    let mut p = Package::new(b"LIVE", HEADER_READ_ONLY, READ_ONLY_FORMAT, 1026);
    p.file_table = (0..1025).collect();
    p.file_table_blocks = 1025;
    p.store(&[1025], &xex(0x40), false);
    p.file_entries(&[EntrySpec {
        name: "default.xex",
        flags: 0,
        start_block: 1025,
        block_count: 1,
        parent: ROOT,
        size: 0x40,
    }]);
    let image = p.build();
    let c = parse(&image, Layout::Live);
    assert_eq!(labels(&c), ["/default.xex"]);
    assert_note(
        &c,
        "File table: 1025 blocks from block 0; 1 file, 0 directories",
    );
    assert_note(
        &c,
        "File table limit reached (1024 blocks); not read: 1 further block",
    );
}

#[test]
fn file_tables_chain_across_blocks_and_skip_unnamed_entries() {
    // 70 entries: 64 in block 0, the rest in block 3 (chained from 0).
    let mut p = Package::new(b"LIVE", HEADER_READ_ONLY, READ_ONLY_FORMAT, 5);
    p.file_table = vec![0, 3];
    p.file_table_blocks = 2;
    p.store(&[4], &xex(0x40), false);
    let mut entries: Vec<EntrySpec> = (0..69)
        .map(|_| EntrySpec {
            name: "pad.bin",
            flags: 0,
            start_block: 1,
            block_count: 0,
            parent: ROOT,
            size: 0,
        })
        .collect();
    entries.push(EntrySpec {
        name: "late.xex",
        flags: 0,
        start_block: 4,
        block_count: 1,
        parent: ROOT,
        size: 0x40,
    });
    p.file_entries(&entries);
    // Entry 5 keeps its name but has name length 0: Velocity skips it.
    p.blocks[0][5 * 0x40 + 0x28] = 0;
    let image = p.build();
    let c = parse(&image, Layout::Live);
    assert_eq!(labels(&c), ["/late.xex"]);
    assert_note(
        &c,
        "File table: 2 blocks from block 0; 69 files, 0 directories",
    );
    assert_note(&c, "Skipped: 1 file table entry with name length 0");
}

// --- Hash checks -------------------------------------------------------------

#[test]
fn sha1_mismatches_are_reported_and_members_still_listed() {
    let p = live_package();
    let mut image = p.build();
    // A byte of game.xex's second block (block 4), past the XEX header.
    image[p.block_offset(4) + 0x10] ^= 0xFF;
    let c = parse(&image, Layout::Live);
    assert_eq!(labels(&c).len(), 3);
    assert_note(
        &c,
        "SHA-1 checked for 7 data blocks (the file table and the files read in full): 1 block \
         does not match; first: data block 4 at 0x10000",
    );
    // The header SHA-1 covers the metadata, so a changed title ID shows.
    let mut image = p.build();
    image[0x363] ^= 0x01;
    let c = parse(&image, Layout::Live);
    assert_note(
        &c,
        "Header SHA-1 (content ID) over 0x344-0xAFFF does not match",
    );
    // The top hash in the volume descriptor.
    let mut image = p.build();
    image[0x381] ^= 0x01;
    let c = parse(&image, Layout::Live);
    assert_note(
        &c,
        "SHA-1 of the top hash table does not match the volume descriptor",
    );
}

#[test]
fn stale_table_copies_fail_their_sha1_check() {
    let p = con_package();
    let mut image = p.build();
    // Point the level-1 record of level-0 table 1 at its stale first copy.
    let level1 = p.first_table_offset() + (p.level1_slot() + 1) * BLOCK;
    image[level1 + RECORD + 0x14] = 0;
    let c = parse(&image, Layout::Con);
    // The stale copy fails its level-1 SHA-1, and its records fail blocks
    // 170-172; the changed level-1 table fails the descriptor's top hash.
    assert_note(
        &c,
        "1 table and 3 blocks do not match; first: level-0 hash table at 0xB8000",
    );
    assert_note(
        &c,
        "SHA-1 of the top hash table does not match the volume descriptor",
    );
    // The file is consecutive, so its blocks are still read.
    assert_eq!(labels(&c), ["/default.xex"]);
}

// --- Damaged members ---------------------------------------------------------

#[test]
fn damaged_entries_are_skipped_and_named() {
    let mut p = live_package();
    // game.xex: chain 6 -> 4 -> 6 loops.
    p.next[4] = 6;
    // level.xex: its parent index names a file entry.
    put_be16(&mut p.blocks[0], 5 * 0x40 + 0x32, 0);
    let image = p.build();
    let c = parse(&image, Layout::Live);
    assert_eq!(labels(&c), ["/default.xex"]);
    assert_note(
        &c,
        "Skipped /media/game.xex: the block chain reaches block 6 twice",
    );
    assert_note(
        &c,
        "Skipped the file entry at 0xC140: its directory index 0 names no directory entry",
    );
}

#[test]
fn broken_chains_and_unallocated_blocks_skip_the_file() {
    let mut p = live_package();
    p.next[4] = END_OF_CHAIN;
    let image = p.build();
    let c = parse(&image, Layout::Live);
    assert_note(
        &c,
        "Skipped /media/game.xex: the block chain ends after 2 blocks; 8448 B need 3",
    );
    let mut p = live_package();
    p.next[6] = 9;
    let image = p.build();
    let c = parse(&image, Layout::Live);
    assert_note(
        &c,
        "Skipped /media/game.xex: block 9 is not allocated (the volume has 8 blocks)",
    );
    let mut p = live_package();
    // default.xex claims 9 consecutive blocks from block 1.
    put_be32(&mut p.blocks[0], 0x34, 9 * BLOCK as u32);
    let image = p.build();
    let c = parse(&image, Layout::Live);
    assert_note(
        &c,
        "Skipped /default.xex: its 9 consecutive blocks from block 1 pass the 8 allocated blocks",
    );
}

#[test]
fn overlong_names_and_directory_loops_are_skipped() {
    let mut p = live_package();
    // readme.txt: name length 41.
    p.blocks[0][2 * 0x40 + 0x28] = 41;
    // maps: its own parent.
    put_be16(&mut p.blocks[0], 4 * 0x40 + 0x32, 4);
    let image = p.build();
    let c = parse(&image, Layout::Live);
    assert_eq!(labels(&c), ["/default.xex", "/media/game.xex"]);
    assert_note(
        &c,
        "Skipped the file table entry at 0xC080: name length 41 exceeds 40 B",
    );
    assert_note(&c, "its directories form a loop");
}

// --- Corrupted structures ----------------------------------------------------

#[test]
fn detection_requires_the_header_structure() {
    let image = live_package().build();
    // (offset, value, still a package): the header size is 0x0000AD0E.
    for (at, value, is_package) in [
        (0x343, 0x19, true),  // header size 0xAD19
        (0x342, 0x00, false), // header size 0xE: below 0x971A
        (0x340, 0x10, false), // header size 0x1000AD0E: above 0x10000000
        (0x379, 0x23, false), // volume descriptor size
        (0x3AC, 0x02, false), // volume type 2
        (0x003, 0x53, false), // magic `LIVS`
    ] {
        let mut mutated = image.clone();
        mutated[at] = value;
        let expected = is_package.then_some(Layout::Live);
        assert_eq!(stfs::detect(&mutated), expected, "byte 0x{at:X}");
    }
    assert_eq!(stfs::detect(&image[..0x3AC]), None);
    assert_eq!(stfs::detect(b"CON \nplain text"), None);
}

#[test]
fn damaged_headers_and_volumes_are_parse_errors() {
    let image = live_package().build();
    let mut mutated = image.clone();
    mutated[0x342] = 0;
    assert!(parse_error(&mutated, Layout::Live).contains("Invalid XContent header size 0xE"));
    assert!(parse_error(&image[..0x9000], Layout::Live)
        .contains("Truncated XContent header: 36864 B of 44302 B"));
    assert!(parse_error(&image, Layout::Con).contains("Invalid XContent magic at 0x0"));
    let mut mutated = image.clone();
    mutated[0x379] = 0x20;
    let error = parse_error(&mutated, Layout::Live);
    assert!(error.contains("Invalid XContent volume descriptor size 0x20 at 0x379"));
    let mut mutated = image.clone();
    put_be32(&mut mutated, 0x3A9, 7);
    assert!(parse_error(&mutated, Layout::Live).contains("Unsupported XContent volume type 7"));
    let mut mutated = image.clone();
    put_be32(&mut mutated, 0x395, 4_913_001);
    assert!(parse_error(&mutated, Layout::Live)
        .contains("Invalid STFS allocated block count 4913001 at 0x395: at most 4913000"));
    // A top table outside the file: 200 blocks declared, so the top table
    // is the level-1 table after block 169.
    let mut mutated = image.clone();
    put_be32(&mut mutated, 0x395, 200);
    assert!(
        parse_error(&mutated, Layout::Live).contains("Truncated STFS top hash table at 0xB6000")
    );
}

#[test]
fn damaged_file_tables_are_parse_errors() {
    let base = live_package();
    // The volume descriptor names block 9 as the first file table block.
    let mut p = live_package();
    p.file_table = vec![9];
    let error = parse_error(&p.build(), Layout::Live);
    assert!(
        error.contains("Invalid STFS file table block 9: block 9 is not allocated"),
        "{error}"
    );
    // Two declared blocks, but block 0's chain ends.
    let mut p = live_package();
    p.file_table_blocks = 2;
    let error = parse_error(&p.build(), Layout::Live);
    assert!(
        error.contains("Invalid STFS file table chain: it ends after 1 of 2 blocks"),
        "{error}"
    );
    // Two declared blocks chained back to block 0.
    let mut p = live_package();
    p.file_table_blocks = 2;
    p.next[0] = 0;
    let error = parse_error(&p.build(), Layout::Live);
    assert!(
        error.contains("Invalid STFS file table chain: block 0 is reached twice"),
        "{error}"
    );
    // The file table block outside a truncated file.
    let image = base.build();
    let error = parse_error(&image[..base.block_offset(0)], Layout::Live);
    assert!(
        error.contains(
            "Invalid STFS file table block 0: data block 0 at 0xC000 lies outside the file"
        ),
        "{error}"
    );
}

// --- Sweeps ------------------------------------------------------------------

/// Every `step`-th prefix and those around `boundaries` either fail to
/// parse or keep every listed member inside the prefix, with a truncation
/// note when blocks are missing.
fn truncation_sweep(image: &[u8], layout: Layout, step: usize, boundaries: &[usize]) {
    let full = parse(image, layout).children.len();
    let near = boundaries
        .iter()
        .flat_map(|b| b.saturating_sub(2)..b.saturating_add(3));
    for end in (0..image.len()).step_by(step).chain(near) {
        if end >= image.len() {
            continue;
        }
        let prefix = &image[..end];
        let Ok(c) = container::parse(prefix, Kind::Stfs(layout)) else {
            continue;
        };
        assert!(c.children.len() <= full, "prefix of {end} B");
        assert!(
            c.children
                .iter()
                .all(|child| child.offset + child.stored_size <= end),
            "prefix of {end} B lists bytes outside it"
        );
        assert!(has_note(&c, "Truncated package"), "prefix of {end} B");
    }
}

#[test]
fn truncated_packages_fail_or_list_only_what_is_present() {
    let live = live_package();
    let image = live.build();
    let boundaries: Vec<usize> = (0..8).map(|b| live.block_offset(b)).collect();
    truncation_sweep(&image, Layout::Live, 61, &boundaries);
    let con = con_package();
    let image = con.build();
    let boundaries = [
        con.block_offset(0),
        con.block_offset(169),
        con.block_offset(170),
    ];
    truncation_sweep(&image, Layout::Con, 4099, &boundaries);
    for end in [0, 4, 0x340, 0x3AC] {
        assert_eq!(stfs::detect(&image[..end]), None, "prefix of {end} B");
    }
    // From 0x3AD bytes on the header structure is present: a parse error.
    for end in [0x3AD, 0x9719] {
        let error = detect_payload(&image[..end], &ClassifierOptions::new())
            .expect_err("a truncated header is a parse error")
            .to_string();
        assert!(
            error.starts_with("Xbox 360 package parse error: Truncated XContent header"),
            "{error}"
        );
    }
}

/// Single-byte mutations (0x00, 0xFF, bit flip) of every byte in `header`
/// and of every `step`-th byte, classified without panicking.
fn mutation_sweep(data: &[u8], header: std::ops::Range<usize>, step: usize) {
    let positions = header.chain((0..data.len()).step_by(step));
    for i in positions.filter(|i| *i < data.len()) {
        for value in [0x00, 0xff, data[i] ^ 0x01] {
            let mut mutated = data.to_vec();
            mutated[i] = value;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

#[test]
fn packages_survive_byte_mutations() {
    let live = live_package();
    let image = live.build();
    mutation_sweep(&image, 0x320..0x3B0, 409);
    // The first file table entries and level-0 records.
    let table = live.block_offset(0);
    mutation_sweep(&image, table..table + 3 * 0x40, image.len());
    let level0 = live.first_table_offset();
    mutation_sweep(&image, level0..level0 + 4 * RECORD, image.len());
    let con = con_package();
    let image = con.build();
    mutation_sweep(&image, 0x379..0x39D, 8191);
    // The level-1 records that choose the level-0 table copies.
    let level1 = con.first_table_offset() + (con.level1_slot() + 1) * BLOCK;
    mutation_sweep(&image, level1..level1 + 2 * RECORD, image.len());
    mutation_sweep(&svod_header(), 0x340..0x3B0, 1021);
}
