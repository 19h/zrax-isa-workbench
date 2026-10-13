//! UDF volumes: hdiutil and newfs_udf fixtures (UDF 1.02 and 1.50, a UDF
//! bridge disc, 2.01 with a fragmented file, 2.50 with a metadata
//! partition, 512 B and 4096 B blocks), synthetic volumes built from the
//! ECMA-167 and UDF 2.60 layouts for what the fixtures do not cover
//! (sparable and virtual partitions, every allocation descriptor form,
//! continuation extents, ICB indirection, deleted entries, links, loops and
//! limits), corrupted descriptors, and truncation and mutation sweeps.

#[path = "support/truncated_volume.rs"]
mod truncated_volume;

use std::borrow::Cow;
use truncated_volume::{assert_members_inside, prefix_ends};
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::{self, Child, Container, Kind};
use zrax::formats::udf::{self, Layout};
use zrax::formats::{detect_format, iso9660, DetectedFormat};
use zrax::types::ContainedArch;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// A committed image, stored with `gzip -9 -n` (tests/fixtures/udf/README.md).
fn udf_fixture(name: &str) -> Vec<u8> {
    gunzip(&fixture(&format!("udf/{name}.gz")))
}

fn gunzip(stored: &[u8]) -> Vec<u8> {
    compressed::decode(Codec::Gzip, stored)
        .expect("fixture decompresses")
        .data
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse a volume that must be valid.
fn parse(image: &[u8]) -> Container<'_> {
    let layout = udf::detect(image).expect("detected as UDF");
    udf::parse_container(image, layout).expect("parses")
}

/// The error text of a volume that does not parse.
fn parse_error(image: &[u8]) -> String {
    udf::parse_container(image, Layout::Udf)
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
        .unwrap_or_else(|| panic!("no child {label} in {:?}", labels(c)))
}

fn notes(c: &Container<'_>) -> String {
    c.notes.join("\n")
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|note| note.contains(text))
}

fn slice<'a>(payload: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("no slice {label}"))
}

fn metadata(payload: &DetectionPayload, key: &str) -> String {
    payload
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
        .unwrap_or_else(|| panic!("metadata {key}"))
}

fn is_udf(data: &[u8], layout: Layout) -> bool {
    matches!(
        detect_format(data),
        DetectedFormat::Container { kind: Kind::Udf(found) } if found == layout
    )
}

// ---------------------------------------------------------------------------
// Fixture members (tests/fixtures/udf/README.md)
// ---------------------------------------------------------------------------

fn payload_elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

fn kernel_macho() -> Vec<u8> {
    fixture("apple/kernel.macho")
}

/// `payload.elf` padded with text to 40 KiB, as `generate.sh` writes
/// `fragmented.elf`.
fn fragmented_elf() -> Vec<u8> {
    let mut body = payload_elf();
    while body.len() < 40 << 10 {
        body.extend_from_slice(b"zrax synthetic fragmented member ");
    }
    body.truncate(40 << 10);
    body
}

/// The first sector of the partition hdiutil writes for this tree.
const HDIUTIL_PARTITION: usize = 272;

/// The recognized members of every filled fixture, in walk order: the
/// root's files, then each directory's.
const TREE_MEMBERS: [&str; 3] = [
    "/bin/payload.elf",
    "/deep/a/b/c/kernel.macho",
    "/docs/caf\u{e9}-\u{20ac}.elf",
];

/// Every member is stored as-is and holds the bytes of its source.
fn assert_tree_members(name: &str, c: &Container<'_>) {
    for (label, expected) in [
        (TREE_MEMBERS[0], payload_elf()),
        (TREE_MEMBERS[1], kernel_macho()),
        (TREE_MEMBERS[2], payload_elf()),
    ] {
        let member = child(c, label);
        assert_eq!(member.data.as_ref(), expected.as_slice(), "{name}: {label}");
        assert!(matches!(member.data, Cow::Borrowed(_)), "{name}: {label}");
        assert_eq!(member.stored_size, expected.len(), "{name}: {label}");
    }
}

// ---------------------------------------------------------------------------
// Wire layout: ECMA-167 3rd edition and UDF 2.60. All numbers are
// little-endian.
// ---------------------------------------------------------------------------

/// Tag identifiers (ECMA-167 3/7.2.1, 4/7.2.1).
const TAG_SPARING_TABLE: u16 = 0;
const TAG_PRIMARY: u16 = 1;
const TAG_ANCHOR: u16 = 2;
const TAG_POINTER: u16 = 3;
const TAG_PARTITION: u16 = 5;
const TAG_LOGICAL: u16 = 6;
const TAG_TERMINATING: u16 = 8;
const TAG_INTEGRITY: u16 = 9;
const TAG_FILE_SET: u16 = 256;
const TAG_FILE_IDENTIFIER: u16 = 257;
const TAG_ALLOCATION_EXTENT: u16 = 258;
const TAG_INDIRECT: u16 = 259;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_EXTENDED_FILE_ENTRY: u16 = 266;

/// File types (4/14.6.6; UDF 2.60 2.3.5.2).
const FILE_TYPE_INDIRECT: u8 = 3;
const FILE_TYPE_DIRECTORY: u8 = 4;
const FILE_TYPE_BYTES: u8 = 5;
const FILE_TYPE_FIFO: u8 = 9;
const FILE_TYPE_SYMLINK: u8 = 12;
const FILE_TYPE_VAT: u8 = 248;
const FILE_TYPE_REAL_TIME: u8 = 249;
const FILE_TYPE_METADATA: u8 = 250;
const FILE_TYPE_MIRROR: u8 = 251;

/// ICB flags (4/14.6.8): allocation descriptor type in bits 0-2, bit 11
/// transformed.
const AD_SHORT: u16 = 0;
const AD_LONG: u16 = 1;
const AD_EXTENDED: u16 = 2;
const AD_EMBEDDED: u16 = 3;
const FLAG_TRANSFORMED: u16 = 1 << 11;

/// Extent types in the high bits of an extent length (4/14.14.1.1).
const EXTENT_ALLOCATED: u32 = 1 << 30;
const EXTENT_CONTINUATION: u32 = 3 << 30;

/// File characteristics (4/14.4.3).
const FID_DIRECTORY: u8 = 0x02;
const FID_DELETED: u8 = 0x04;
const FID_PARENT: u8 = 0x08;

/// The first logical sector of the partition in every synthetic volume,
/// right after the anchor at 256.
const PARTITION_START: u32 = 257;
const ANCHOR_SECTOR: usize = 256;

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(data[at..at + 2].try_into().expect("2 bytes"))
}

fn get32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

/// Whole units of `unit` covering `length`.
fn units_for(length: usize, unit: usize) -> usize {
    length / unit + usize::from(length % unit != 0)
}

/// CRC-ITU-T (ECMA-167 3/7.2.6): polynomial x^16 + x^12 + x^5 + 1, most
/// significant bit first, initial value 0.
fn crc_itu(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x1021
            };
        }
    }
    crc
}

/// Write the descriptor tag (ECMA-167 3/7.2) of `descriptor`: identifier
/// (0), version 3 (2), checksum of bytes 0-3 and 5-15 (4), serial number 0
/// (6), CRC (8) of the `crc_length` bytes after the tag (10), location
/// (12).
fn seal(descriptor: &mut [u8], identifier: u16, location: u32, crc_length: usize) {
    put16(descriptor, 0, identifier);
    put16(descriptor, 2, 3);
    descriptor[4] = 0;
    put16(descriptor, 6, 0);
    let crc = crc_itu(&descriptor[16..16 + crc_length]);
    put16(descriptor, 8, crc);
    put16(
        descriptor,
        10,
        u16::try_from(crc_length).expect("short descriptor"),
    );
    put32(descriptor, 12, location);
    reseal_checksum(descriptor);
}

/// Recompute only the tag checksum, after a test changed a tag field.
fn reseal_checksum(descriptor: &mut [u8]) {
    descriptor[4] = 0;
    let sum = descriptor[..16]
        .iter()
        .fold(0u8, |sum, &b| sum.wrapping_add(b));
    descriptor[4] = sum;
}

/// Recompute the CRC and checksum of the tag at `at` in `image`, keeping
/// its identifier, location and CRC length.
fn reseal(image: &mut [u8], at: usize) {
    let identifier = get16(image, at);
    let crc_length = usize::from(get16(image, at + 10));
    let location = get32(image, at + 12);
    seal(&mut image[at..], identifier, location, crc_length);
}

/// A dstring of `size` bytes (ECMA-167 1/7.2.12, UDF 2.60 2.1.3): CS0 with
/// compression ID 8, the used length in the last byte.
fn dstring(size: usize, text: &str) -> Vec<u8> {
    let mut field = vec![0u8; size];
    let bytes = cs0(text);
    field[..bytes.len()].copy_from_slice(&bytes);
    field[size - 1] = u8::try_from(bytes.len()).expect("short text");
    field
}

/// OSTA CS0 text (UDF 2.60 2.1.1): compression ID 8 for Latin-1 text,
/// otherwise 16 with big-endian UTF-16 units.
fn cs0(text: &str) -> Vec<u8> {
    if text.chars().all(|c| u32::from(c) < 0x100) {
        let mut bytes = vec![8u8];
        bytes.extend(
            text.chars()
                .map(|c| u8::try_from(u32::from(c)).expect("Latin-1")),
        );
        bytes
    } else {
        let mut bytes = vec![16u8];
        bytes.extend(text.encode_utf16().flat_map(u16::to_be_bytes));
        bytes
    }
}

/// An entity identifier (ECMA-167 1/7.4): flags 0, the identifier from
/// byte 1, an 8-byte suffix from byte 24.
fn regid(identifier: &str, suffix: [u8; 8]) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[1..1 + identifier.len()].copy_from_slice(identifier.as_bytes());
    field[24..].copy_from_slice(&suffix);
    field
}

/// A domain or UDF identifier suffix holding the UDF revision.
fn revision_suffix(revision: u16) -> [u8; 8] {
    let mut suffix = [0u8; 8];
    suffix[..2].copy_from_slice(&revision.to_le_bytes());
    suffix
}

/// A `short_ad` (4/14.14.1): extent length with type bits, block.
fn short_ad(length: u32, block: u32) -> Vec<u8> {
    let mut ad = vec![0u8; 8];
    put32(&mut ad, 0, length);
    put32(&mut ad, 4, block);
    ad
}

/// A `long_ad` (4/14.14.2): extent length, `lb_addr` (block, partition
/// reference), 6 bytes of implementation use.
fn long_ad(length: u32, block: u32, reference: u16) -> Vec<u8> {
    let mut ad = vec![0u8; 16];
    put32(&mut ad, 0, length);
    put32(&mut ad, 4, block);
    put16(&mut ad, 8, reference);
    ad
}

/// An `ext_ad` (4/14.14.3): extent length, recorded length, information
/// length, `lb_addr`, 2 bytes of implementation use.
fn ext_ad(length: u32, recorded: u32, information: u32, block: u32) -> Vec<u8> {
    let mut ad = vec![0u8; 20];
    put32(&mut ad, 0, length);
    put32(&mut ad, 4, recorded);
    put32(&mut ad, 8, information);
    put32(&mut ad, 12, block);
    ad
}

// ---------------------------------------------------------------------------
// Synthetic volumes
// ---------------------------------------------------------------------------

/// How a synthetic file records its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Data {
    /// In the entry's allocation descriptor field.
    Embedded,
    /// One `short_ad`.
    Short,
    /// One `long_ad` naming partition reference 0.
    Long,
    /// One `ext_ad` whose three lengths agree.
    Extended,
    /// Two `short_ad` extents with a free block between them.
    Fragmented,
    /// Three `short_ad` extents; the middle block is allocated but not
    /// recorded, so it reads as zeros.
    Sparse,
    /// One `short_ad` and a continuation extent whose allocation extent
    /// descriptor holds the second one.
    Continued,
}

/// Where a synthetic volume records its file set descriptor, file entries
/// and directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Space {
    /// In the physical partition, reference 0.
    Physical,
    /// In a metadata partition, reference 1, whose metadata file maps its
    /// blocks to physical blocks (UDF 2.60 2.2.10, 2.2.13).
    Metadata,
    /// In a virtual partition, reference 1, read through a UDF 2.00 VAT in
    /// the last sector (UDF 2.60 2.2.8, 2.2.11).
    Virtual,
    /// The same with a UDF 1.50 VAT (UDF 1.50 2.2.10).
    Virtual150,
}

#[derive(Debug, Clone, Copy)]
struct Options {
    /// Logical sector and block size.
    sector: usize,
    /// Extended file entries (4/14.17) instead of file entries (4/14.9).
    extended: bool,
    files: Data,
    /// Directories: `Embedded` or `Short`.
    directories: Data,
    space: Space,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            sector: 2048,
            extended: true,
            files: Data::Short,
            directories: Data::Embedded,
            space: Space::Physical,
        }
    }
}

/// An item of a synthetic directory.
enum Item {
    File(&'static str, Vec<u8>),
    Dir(&'static str, Vec<Item>),
    /// A symbolic link (file type 12).
    Link(&'static str),
    /// A FIFO (file type 9).
    Fifo(&'static str),
    /// A real-time file (file type 249).
    RealTime(&'static str, Vec<u8>),
    /// A file whose ICB tag sets the transformed flag.
    Transformed(&'static str, Vec<u8>),
    /// A deleted entry (characteristics bit 2) with compression ID 254.
    Deleted(&'static str),
    /// A directory entry that names the root directory again.
    Loop(&'static str),
    /// A file of ICB strategy 4096: a stale entry whose next block holds an
    /// indirect entry that names the entry with the data.
    Chained(&'static str, Vec<u8>),
    /// A file whose extended file entry names a stream directory.
    Streams(&'static str, Vec<u8>),
}

/// Where the descriptors of a synthetic volume are.
#[derive(Debug, Clone, Copy)]
struct Places {
    /// Logical sectors of the main and reserve volume descriptor
    /// sequences (primary volume, partition, logical volume and
    /// terminating descriptors) and of the integrity descriptor.
    main: usize,
    reserve: usize,
    integrity: usize,
}

impl Places {
    /// 64 KiB, 128 KiB and 192 KiB into the volume for 2048-byte sectors,
    /// and as many sectors apart for others, all before the anchor.
    fn for_sector(sector: usize) -> Self {
        let main = 65536 / sector;
        Self {
            main,
            reserve: main + 32,
            integrity: main + 64,
        }
    }
}

/// A synthetic volume under construction.
struct Builder {
    options: Options,
    /// The partition's blocks, one `Vec` each.
    blocks: Vec<Vec<u8>>,
    /// Physical blocks of the metadata or virtual blocks, by number.
    mapped: Vec<u32>,
    /// Unique ID of the next file entry.
    unique: u64,
}

/// A synthetic volume and where things are in it.
struct Volume {
    image: Vec<u8>,
    sector: usize,
    places: Places,
    /// Physical block of each metadata or virtual block (the identity for a
    /// physical space).
    mapped: Vec<u32>,
    /// Block of the root directory's file entry in the metadata space.
    root: u32,
}

impl Volume {
    /// File offset of physical partition block `block`.
    fn physical_offset(&self, block: u32) -> usize {
        (PARTITION_START as usize + block as usize) * self.sector
    }

    /// File offset of metadata space block `block`.
    fn space_offset(&self, block: u32) -> usize {
        self.physical_offset(self.mapped[block as usize])
    }
}

impl Builder {
    fn new(options: Options) -> Self {
        let mut builder = Self {
            options,
            blocks: Vec::new(),
            mapped: Vec::new(),
            unique: 16,
        };
        // The metadata file and its mirror come first in a metadata
        // partition; they are written once the metadata space is known.
        if options.space == Space::Metadata {
            builder.data_blocks(2);
        }
        builder
    }

    fn block_size(&self) -> usize {
        self.options.sector
    }

    fn uses_physical_space(&self) -> bool {
        self.options.space == Space::Physical
    }

    fn space_reference(&self) -> u16 {
        u16::from(!self.uses_physical_space())
    }

    /// `count` physical blocks for file data; the first one's number.
    fn data_blocks(&mut self, count: usize) -> u32 {
        let first = u32::try_from(self.blocks.len()).expect("small volume");
        for _ in 0..count {
            self.blocks.push(vec![0; self.block_size()]);
        }
        first
    }

    /// One block of the metadata space; its number there.
    fn space_block(&mut self) -> u32 {
        let physical = self.data_blocks(1);
        if self.uses_physical_space() {
            physical
        } else {
            self.mapped.push(physical);
            u32::try_from(self.mapped.len() - 1).expect("small volume")
        }
    }

    /// The physical block of metadata space block `block`.
    fn physical(&self, block: u32) -> u32 {
        if self.uses_physical_space() {
            block
        } else {
            self.mapped[block as usize]
        }
    }

    /// Write `bytes` into physical block `block`.
    fn write_physical(&mut self, block: u32, bytes: &[u8]) {
        let size = self.block_size();
        assert!(bytes.len() <= size, "one block");
        self.blocks[block as usize][..bytes.len()].copy_from_slice(bytes);
    }

    /// Write `bytes` into metadata space block `block`.
    fn write_space(&mut self, block: u32, bytes: &[u8]) {
        let physical = self.physical(block);
        self.write_physical(physical, bytes);
    }

    /// A file entry or extended file entry recorded at metadata space
    /// block `block` (tag location `block`): ICB tag at 16 with strategy
    /// (20), maximum entries (24), file type (27) and flags (34); uid and
    /// gid `FFFFFFFF` (36, 40); permissions (44); link count 1 (48);
    /// information length (56); then for an FE the logical blocks recorded
    /// (64), implementation regid (128), unique ID (160), L_EA 0 (168) and
    /// L_AD (172) before the descriptors (176), and for an EFE the object
    /// size (64), logical blocks recorded (72), stream directory ICB (152),
    /// implementation regid (168), unique ID (200), L_EA 0 (208) and L_AD
    /// (212) before the descriptors (216).
    fn entry(&mut self, block: u32, shape: EntryShape<'_>) {
        let size = self.block_size();
        let mut fe = vec![0u8; size];
        let header = if self.options.extended { 216 } else { 176 };
        put32(&mut fe, 16, 0);
        put16(&mut fe, 20, shape.strategy);
        put16(&mut fe, 24, if shape.strategy == 4096 { 2 } else { 1 });
        fe[27] = shape.file_type;
        put16(&mut fe, 34, shape.flags);
        put32(&mut fe, 36, u32::MAX);
        put32(&mut fe, 40, u32::MAX);
        put32(&mut fe, 44, 0x14a5);
        put16(&mut fe, 48, 1);
        put64(&mut fe, 56, shape.information_length);
        let information = usize::try_from(shape.information_length).expect("small file");
        let recorded = units_for(information, size) as u64;
        let ad_length = u32::try_from(shape.descriptors.len()).expect("short field");
        let implementation = regid("*zrax synthetic", [0; 8]);
        if self.options.extended {
            put64(&mut fe, 64, shape.information_length);
            put64(&mut fe, 72, recorded);
            if shape.streams {
                fe[152..168].copy_from_slice(&long_ad(size as u32, 0, 0));
            }
            fe[168..200].copy_from_slice(&implementation);
            put64(&mut fe, 200, self.unique);
            put32(&mut fe, 208, 0);
            put32(&mut fe, 212, ad_length);
        } else {
            put64(&mut fe, 64, recorded);
            fe[128..160].copy_from_slice(&implementation);
            put64(&mut fe, 160, self.unique);
            put32(&mut fe, 168, 0);
            put32(&mut fe, 172, ad_length);
        }
        self.unique += 1;
        fe[header..header + shape.descriptors.len()].copy_from_slice(shape.descriptors);
        let identifier = if self.options.extended {
            TAG_EXTENDED_FILE_ENTRY
        } else {
            TAG_FILE_ENTRY
        };
        seal(
            &mut fe,
            identifier,
            block,
            header + shape.descriptors.len() - 16,
        );
        self.write_space(block, &fe);
    }

    /// `data` in new consecutive physical blocks; the first one's number.
    fn stored(&mut self, data: &[u8]) -> u32 {
        let size = self.block_size();
        let first = self.data_blocks(units_for(data.len(), size).max(1));
        for (i, part) in data.chunks(size).enumerate() {
            self.write_physical(first + u32::try_from(i).expect("small"), part);
        }
        first
    }

    /// `requested`, or for data that does not fit in an entry when it
    /// should be embedded, the form a file of the metadata space needs:
    /// one `short_ad` in a physical space, one `long_ad` otherwise.
    fn fitting(&self, requested: Data, length: usize) -> Data {
        let header = if self.options.extended { 216 } else { 176 };
        match requested {
            Data::Embedded if header + length > self.block_size() => {
                if self.uses_physical_space() {
                    Data::Short
                } else {
                    Data::Long
                }
            }
            other => other,
        }
    }

    /// Write `data` and the entry that describes it at `block`, recorded as
    /// `requested` says where the data fits.
    fn file(&mut self, block: u32, file_type: u8, data: &[u8], requested: Data, flags: u16) {
        let size = self.block_size();
        let length = u32::try_from(data.len()).expect("small file");
        let block_length = u32::try_from(size).expect("small");
        let mut descriptors = Vec::new();
        let kind = match self.fitting(requested, data.len()) {
            Data::Embedded => {
                descriptors.extend_from_slice(data);
                AD_EMBEDDED
            }
            Data::Short => {
                let first = self.stored(data);
                descriptors.extend(short_ad(length, first));
                AD_SHORT
            }
            Data::Long => {
                let first = self.stored(data);
                descriptors.extend(long_ad(length, first, 0));
                AD_LONG
            }
            Data::Extended => {
                let first = self.stored(data);
                descriptors.extend(ext_ad(length, length, length, first));
                AD_EXTENDED
            }
            Data::Fragmented => {
                let first = self.stored(&data[..size]);
                self.data_blocks(1);
                let rest = self.stored(&data[size..]);
                descriptors.extend(short_ad(block_length, first));
                descriptors.extend(short_ad(length - block_length, rest));
                AD_SHORT
            }
            Data::Sparse => {
                assert!(data[size..2 * size].iter().all(|&b| b == 0), "a zero block");
                let first = self.stored(&data[..size]);
                let rest = self.stored(&data[2 * size..]);
                descriptors.extend(short_ad(block_length, first));
                descriptors.extend(short_ad(EXTENT_ALLOCATED | block_length, 0));
                descriptors.extend(short_ad(length - 2 * block_length, rest));
                AD_SHORT
            }
            Data::Continued => {
                // The allocation extent descriptor's block lies between
                // the two extents.
                let first = self.stored(&data[..size]);
                let aed = self.space_block();
                let rest = self.stored(&data[size..]);
                self.allocation_extent(aed, &short_ad(length - block_length, rest));
                descriptors.extend(short_ad(block_length, first));
                descriptors.extend(short_ad(EXTENT_CONTINUATION | block_length, aed));
                AD_SHORT
            }
        };
        self.entry(
            block,
            EntryShape {
                file_type,
                flags: kind | flags,
                information_length: data.len() as u64,
                descriptors: &descriptors,
                strategy: 4,
                streams: false,
            },
        );
    }

    /// An allocation extent descriptor at metadata space block `block`
    /// (4/14.5; UDF 2.60 2.3.11): previous location 0 (16), L_AD (20), the
    /// descriptors from 24.
    fn allocation_extent(&mut self, block: u32, descriptors: &[u8]) {
        let mut aed = vec![0u8; self.block_size()];
        put32(
            &mut aed,
            20,
            u32::try_from(descriptors.len()).expect("short"),
        );
        aed[24..24 + descriptors.len()].copy_from_slice(descriptors);
        seal(
            &mut aed,
            TAG_ALLOCATION_EXTENT,
            block,
            8 + descriptors.len(),
        );
        self.write_space(block, &aed);
    }

    /// Write the directory `items` with its entry at `block` and its parent
    /// entry at `parent`.
    fn directory(&mut self, block: u32, parent: u32, items: &[Item]) {
        let reference = self.space_reference();
        let mut fids = vec![fid(FID_DIRECTORY | FID_PARENT, &[], parent, reference)];
        for item in items {
            let named = self.item(block, item);
            fids.push(fid(
                named.characteristics,
                &named.name,
                named.icb,
                reference,
            ));
        }
        let size = self.block_size();
        let length: usize = fids.iter().map(Vec::len).sum();
        let embedded = self.fitting(self.options.directories, length) == Data::Embedded;
        let data_block = if embedded { block } else { self.space_block() };
        let mut data = Vec::new();
        for mut descriptor in fids {
            let location = data_block + u32::try_from(data.len() / size).expect("small");
            let crc_length = descriptor.len() - 16;
            seal(&mut descriptor, TAG_FILE_IDENTIFIER, location, crc_length);
            data.extend_from_slice(&descriptor);
        }
        let (flags, descriptors) = if embedded {
            (AD_EMBEDDED, data.clone())
        } else {
            assert!(data.len() <= size, "one block of directory data");
            self.write_space(data_block, &data);
            let length = u32::try_from(data.len()).expect("small directory");
            (AD_SHORT, short_ad(length, data_block))
        };
        self.entry(
            block,
            EntryShape {
                file_type: FILE_TYPE_DIRECTORY,
                flags,
                information_length: data.len() as u64,
                descriptors: &descriptors,
                strategy: 4,
                streams: false,
            },
        );
    }

    /// Write one item of the directory at `directory`; how its directory
    /// entry names it.
    fn item(&mut self, directory: u32, item: &Item) -> Named {
        let files = self.options.files;
        let file = |builder: &mut Self, name: &str, file_type: u8, data: &[u8], flags: u16| {
            let block = builder.space_block();
            builder.file(block, file_type, data, files, flags);
            Named::file(name, block)
        };
        match item {
            Item::File(name, data) => file(self, name, FILE_TYPE_BYTES, data, 0),
            Item::Dir(name, items) => {
                let block = self.space_block();
                self.directory(block, directory, items);
                Named {
                    characteristics: FID_DIRECTORY,
                    name: cs0(name),
                    icb: block,
                }
            }
            // A path component of type 5 ("the parent"), the target of the
            // link (4/14.16.1).
            Item::Link(name) => file(self, name, FILE_TYPE_SYMLINK, b"\x05\x00\x00\x00", 0),
            Item::Fifo(name) => file(self, name, FILE_TYPE_FIFO, &[], 0),
            Item::RealTime(name, data) => file(self, name, FILE_TYPE_REAL_TIME, data, 0),
            Item::Transformed(name, data) => {
                file(self, name, FILE_TYPE_BYTES, data, FLAG_TRANSFORMED)
            }
            Item::Deleted(name) => {
                // UDF 2.60 2.3.4.2.1: a deleted name's compression ID 8
                // becomes 254.
                let mut deleted = cs0(name);
                deleted[0] = 254;
                Named {
                    characteristics: FID_DELETED,
                    name: deleted,
                    icb: 0,
                }
            }
            Item::Loop(name) => Named {
                characteristics: FID_DIRECTORY,
                name: cs0(name),
                icb: self.root_block(),
            },
            Item::Chained(name, data) => {
                let stale = self.space_block();
                self.chained(stale, data);
                Named::file(name, stale)
            }
            Item::Streams(name, data) => {
                let block = self.space_block();
                let first = self.stored(data);
                let length = u32::try_from(data.len()).expect("small");
                let descriptors = long_ad(length, first, 0);
                self.entry(
                    block,
                    EntryShape {
                        file_type: FILE_TYPE_BYTES,
                        flags: AD_LONG,
                        information_length: data.len() as u64,
                        descriptors: &descriptors,
                        strategy: 4,
                        streams: true,
                    },
                );
                Named::file(name, block)
            }
        }
    }

    /// The root directory's entry block: the second block of the metadata
    /// space, after the file set descriptor.
    fn root_block(&self) -> u32 {
        1
    }

    /// A strategy 4096 ICB chain from `stale`: a stale entry holding text,
    /// the indirect entry in the next block (4/14.7: ICB tag with file type
    /// 3 at 16, indirect ICB `long_ad` at 36), and the entry it names,
    /// which holds `data` with strategy 4096 too.
    fn chained(&mut self, stale: u32, data: &[u8]) {
        let indirect = self.space_block();
        assert_eq!(
            indirect,
            stale + 1,
            "the indirect entry follows the stale one"
        );
        let current = self.space_block();
        let reference = self.space_reference();
        for (block, contents) in [(stale, b"stale text".as_slice()), (current, data)] {
            self.entry(
                block,
                EntryShape {
                    file_type: FILE_TYPE_BYTES,
                    flags: AD_EMBEDDED,
                    information_length: contents.len() as u64,
                    descriptors: contents,
                    strategy: 4096,
                    streams: false,
                },
            );
        }
        let mut ie = vec![0u8; self.block_size()];
        put16(&mut ie, 20, 4096);
        put16(&mut ie, 24, 2);
        ie[27] = FILE_TYPE_INDIRECT;
        let length = u32::try_from(self.block_size()).expect("small");
        ie[36..52].copy_from_slice(&long_ad(length, current, reference));
        seal(&mut ie, TAG_INDIRECT, indirect, 52 - 16);
        self.write_space(indirect, &ie);
    }
}

/// How a directory entry names an item: file characteristics, the CS0
/// identifier and the ICB block in the metadata space.
struct Named {
    characteristics: u8,
    name: Vec<u8>,
    icb: u32,
}

impl Named {
    fn file(name: &str, icb: u32) -> Self {
        Self {
            characteristics: 0,
            name: cs0(name),
            icb,
        }
    }
}

/// The fields of one synthetic file entry.
struct EntryShape<'a> {
    file_type: u8,
    flags: u16,
    information_length: u64,
    descriptors: &'a [u8],
    strategy: u16,
    streams: bool,
}

/// Consecutive physical blocks of the metadata space.
struct Run {
    start: u32,
    count: u32,
}

/// An unsealed file identifier descriptor (4/14.4): file version 1 (16),
/// characteristics (18), L_FI (19), ICB `long_ad` (20), L_IU 0 (36), the
/// identifier (38) and zero padding to a multiple of 4.
fn fid(characteristics: u8, name: &[u8], block: u32, reference: u16) -> Vec<u8> {
    let length = units_for(38 + name.len(), 4) * 4;
    let mut descriptor = vec![0u8; length];
    put16(&mut descriptor, 16, 1);
    descriptor[18] = characteristics;
    descriptor[19] = u8::try_from(name.len()).expect("short name");
    let icb_length = if block == 0 && characteristics & FID_DELETED != 0 {
        0
    } else {
        2048
    };
    descriptor[20..36].copy_from_slice(&long_ad(icb_length, block, reference));
    descriptor[38..38 + name.len()].copy_from_slice(name);
    descriptor
}

/// Build a synthetic volume of `items` in the root directory.
fn build(options: Options, items: &[Item]) -> Volume {
    let mut builder = Builder::new(options);
    let file_set = builder.space_block();
    let root = builder.space_block();
    assert_eq!(root, builder.root_block());
    builder.directory(root, root, items);
    builder.file_set(file_set, root);
    builder.finish(root)
}

impl Builder {
    /// The file set descriptor at metadata space block `block` (4/14.1):
    /// recording time (16), interchange levels 3 (28, 30), character set
    /// lists 1 (32, 36), file set number 0 (40), logical volume identifier
    /// (112), file set identifier (304), root directory ICB (400), domain
    /// (416).
    fn file_set(&mut self, block: u32, root: u32) {
        let size = self.block_size();
        let mut fsd = vec![0u8; size];
        put16(&mut fsd, 28, 3);
        put16(&mut fsd, 30, 3);
        put32(&mut fsd, 32, 1);
        put32(&mut fsd, 36, 1);
        fsd[112..240].copy_from_slice(&dstring(128, "ZRAX_SYNTHETIC"));
        fsd[304..336].copy_from_slice(&dstring(32, "ZRAX file set"));
        let reference = self.space_reference();
        fsd[400..416].copy_from_slice(&long_ad(size as u32, root, reference));
        fsd[416..448].copy_from_slice(&regid("*OSTA UDF Compliant", revision_suffix(0x0250)));
        seal(&mut fsd, TAG_FILE_SET, block, 512 - 16);
        self.write_space(block, &fsd);
    }

    /// The metadata file (and its mirror, which shares its extents) at
    /// physical blocks 0 and 1: extended file entries of file types 250
    /// and 251 whose `short_ad` extents record the metadata space's blocks,
    /// merged where they are consecutive.
    fn metadata_files(&mut self) {
        let size = u32::try_from(self.block_size()).expect("small");
        let mut runs: Vec<Run> = Vec::new();
        for &physical in &self.mapped {
            match runs.last_mut() {
                Some(run) if run.start + run.count == physical => run.count += 1,
                _ => runs.push(Run {
                    start: physical,
                    count: 1,
                }),
            }
        }
        let descriptors: Vec<u8> = runs
            .iter()
            .flat_map(|run| short_ad(run.count * size, run.start))
            .collect();
        let blocks = self.mapped.len() as u64;
        let space = self.options.space;
        // The metadata files live in the physical partition.
        self.options.space = Space::Physical;
        for (block, file_type) in [(0, FILE_TYPE_METADATA), (1, FILE_TYPE_MIRROR)] {
            self.entry(
                block,
                EntryShape {
                    file_type,
                    flags: AD_SHORT,
                    information_length: blocks * u64::from(size),
                    descriptors: &descriptors,
                    strategy: 4,
                    streams: false,
                },
            );
        }
        self.options.space = space;
    }

    /// The VAT ICB in a new last block of the partition: for UDF 2.00 a
    /// file entry of type 248 holding the header (UDF 2.60 2.2.11: L_HD 152
    /// (0), L_IU 0 (2), logical volume identifier (4), previous VAT ICB
    /// `FFFFFFFF` (132), file and directory counts (136, 140), revisions
    /// (144-148)) and the entries; for UDF 1.50 a file entry of type 0
    /// holding the entries, the identifier `*UDF Virtual Alloc Tbl` and the
    /// previous VAT ICB (UDF 1.50 2.2.10).
    fn vat(&mut self) {
        let entries: Vec<u8> = self.mapped.iter().flat_map(|e| e.to_le_bytes()).collect();
        let (file_type, table) = if self.options.space == Space::Virtual {
            let mut header = vec![0u8; 152];
            put16(&mut header, 0, 152);
            header[4..132].copy_from_slice(&dstring(128, "ZRAX_SYNTHETIC"));
            put32(&mut header, 132, u32::MAX);
            put16(&mut header, 144, 0x0200);
            put16(&mut header, 146, 0x0200);
            put16(&mut header, 148, 0x0200);
            header.extend_from_slice(&entries);
            (FILE_TYPE_VAT, header)
        } else {
            let mut table = entries;
            table.extend_from_slice(&regid("*UDF Virtual Alloc Tbl", [0; 8]));
            table.extend_from_slice(&u32::MAX.to_le_bytes());
            (0, table)
        };
        let block = self.data_blocks(1);
        let space = self.options.space;
        self.options.space = Space::Physical;
        self.entry(
            block,
            EntryShape {
                file_type,
                flags: AD_EMBEDDED,
                information_length: table.len() as u64,
                descriptors: &table,
                strategy: 4,
                streams: false,
            },
        );
        self.options.space = space;
    }

    /// Lay out the volume: the recognition sequence, both descriptor
    /// sequences, the integrity descriptor, the anchors at 256 and (unless
    /// the volume has a VAT in its last sector) N, and the partition.
    fn finish(mut self, root: u32) -> Volume {
        match self.options.space {
            Space::Metadata => self.metadata_files(),
            Space::Virtual | Space::Virtual150 => self.vat(),
            Space::Physical => {}
        }
        let sector = self.options.sector;
        let places = Places::for_sector(sector);
        let partition_blocks = self.blocks.len();
        let virtual_space = matches!(self.options.space, Space::Virtual | Space::Virtual150);
        let sectors = PARTITION_START as usize + partition_blocks + usize::from(!virtual_space);
        let mut image = vec![0u8; sectors * sector];
        recognition_sequence(&mut image, sector, &[b"BEA01", b"NSR03", b"TEA01"]);
        for start in [places.main, places.reserve] {
            self.descriptor_sequence(&mut image, start, partition_blocks, places);
        }
        integrity(&mut image, sector, places.integrity);
        anchor(&mut image, sector, ANCHOR_SECTOR, places);
        if !virtual_space {
            anchor(&mut image, sector, sectors - 1, places);
        }
        for (i, block) in self.blocks.iter().enumerate() {
            let at = (PARTITION_START as usize + i) * sector;
            image[at..at + sector].copy_from_slice(block);
        }
        let mapped = if self.uses_physical_space() {
            (0..u32::try_from(partition_blocks).expect("small")).collect()
        } else {
            self.mapped.clone()
        };
        Volume {
            image,
            sector,
            places,
            mapped,
            root,
        }
    }

    /// The primary volume, partition, logical volume and terminating
    /// descriptors from sector `start`.
    fn descriptor_sequence(
        &self,
        image: &mut [u8],
        start: usize,
        partition_blocks: usize,
        places: Places,
    ) {
        let sector = self.options.sector;
        let at = |n: usize| (start + n) * sector;
        let location = |n: usize| u32::try_from(start + n).expect("small volume");
        // Primary volume descriptor (3/10.1): sequence number (16), volume
        // identifier (24), volume sequence numbers 1 (56, 58), interchange
        // levels (60, 62), character set lists (64, 68), volume set
        // identifier (72), application (344), implementation (388).
        let pvd = at(0);
        put32(image, pvd + 16, 1);
        image[pvd + 24..pvd + 56].copy_from_slice(&dstring(32, "ZRAX_PVD"));
        put16(image, pvd + 56, 1);
        put16(image, pvd + 58, 1);
        put16(image, pvd + 60, 2);
        put16(image, pvd + 62, 3);
        put32(image, pvd + 64, 1);
        put32(image, pvd + 68, 1);
        image[pvd + 72..pvd + 200].copy_from_slice(&dstring(128, "0123ABCD synthetic set"));
        image[pvd + 388..pvd + 420].copy_from_slice(&regid("*zrax synthetic", [0; 8]));
        seal(&mut image[pvd..], TAG_PRIMARY, location(0), 512 - 16);
        // Partition descriptor (3/10.5): sequence number (16), flags 1
        // (20), number 0 (22), contents `+NSR03` (24), access type 1
        // read-only (184), start (188), length (192).
        let pd = at(1);
        put32(image, pd + 16, 2);
        put16(image, pd + 20, 1);
        put16(image, pd + 22, 0);
        image[pd + 24..pd + 56].copy_from_slice(&regid("+NSR03", [0; 8]));
        put32(image, pd + 184, 1);
        put32(image, pd + 188, PARTITION_START);
        put32(
            image,
            pd + 192,
            u32::try_from(partition_blocks).expect("small"),
        );
        seal(&mut image[pd..], TAG_PARTITION, location(1), 512 - 16);
        // Logical volume descriptor (3/10.6): sequence number (16),
        // identifier (84), block size (212), domain (216), file set extent
        // (248), map table length (264), map count (268), integrity
        // extent (432), maps (440).
        let lvd = at(2);
        let maps = self.partition_maps();
        put32(image, lvd + 16, 3);
        image[lvd + 84..lvd + 212].copy_from_slice(&dstring(128, "ZRAX_SYNTHETIC"));
        put32(image, lvd + 212, u32::try_from(sector).expect("small"));
        let revision = if self.options.space == Space::Virtual150 {
            0x0150
        } else {
            0x0250
        };
        image[lvd + 216..lvd + 248]
            .copy_from_slice(&regid("*OSTA UDF Compliant", revision_suffix(revision)));
        image[lvd + 248..lvd + 264].copy_from_slice(&long_ad(
            u32::try_from(sector).expect("small"),
            0,
            self.space_reference(),
        ));
        put32(image, lvd + 264, u32::try_from(maps.len()).expect("small"));
        put32(image, lvd + 268, 1 + u32::from(!self.uses_physical_space()));
        put32(image, lvd + 432, u32::try_from(sector).expect("small"));
        put32(
            image,
            lvd + 436,
            u32::try_from(places.integrity).expect("small"),
        );
        image[lvd + 440..lvd + 440 + maps.len()].copy_from_slice(&maps);
        seal(
            &mut image[lvd..],
            TAG_LOGICAL,
            location(2),
            440 + maps.len() - 16,
        );
        seal(&mut image[at(3)..], TAG_TERMINATING, location(3), 512 - 16);
    }

    /// A type 1 map of partition 0, followed by the metadata or virtual
    /// type 2 map (UDF 2.60 2.2.8, 2.2.10) for those spaces.
    fn partition_maps(&self) -> Vec<u8> {
        let mut maps = vec![1, 6, 1, 0, 0, 0];
        let (identifier, revision) = match self.options.space {
            Space::Physical => return maps,
            Space::Metadata => ("*UDF Metadata Partition", 0x0250),
            Space::Virtual => ("*UDF Virtual Partition", 0x0200),
            Space::Virtual150 => ("*UDF Virtual Partition", 0x0150),
        };
        let mut map = vec![0u8; 64];
        map[0] = 2;
        map[1] = 64;
        map[4..36].copy_from_slice(&regid(identifier, revision_suffix(revision)));
        put16(&mut map, 36, 1);
        put16(&mut map, 38, 0);
        if self.options.space == Space::Metadata {
            // Metadata file at block 0, mirror at block 1, no bitmap,
            // allocation unit 32, alignment unit 1.
            put32(&mut map, 40, 0);
            put32(&mut map, 44, 1);
            put32(&mut map, 48, u32::MAX);
            put32(&mut map, 52, 32);
            put16(&mut map, 56, 1);
        }
        maps.extend_from_slice(&map);
        maps
    }
}

/// Volume structure descriptors `ids` from 0x8000 (ECMA-167 2/9.1):
/// structure type 0, identifier (1), version 1 (6), one per 2048 bytes or
/// per sector when sectors are larger.
fn recognition_sequence(image: &mut [u8], sector: usize, ids: &[&[u8; 5]]) {
    let stride = sector.max(2048);
    for (i, id) in ids.iter().enumerate() {
        let at = 0x8000 + i * stride;
        image[at] = 0;
        image[at + 1..at + 6].copy_from_slice(id.as_slice());
        image[at + 6] = 1;
    }
}

/// A closed logical volume integrity descriptor (3/10.10; UDF 2.60 2.2.6):
/// integrity type 1 (28), one partition (72), 46 B of implementation use
/// (76) after the free space and size tables (80, 84): implementation
/// regid, 3 files, 2 directories, revisions 2.50.
fn integrity(image: &mut [u8], sector: usize, location: usize) {
    let at = location * sector;
    put32(image, at + 28, 1);
    put32(image, at + 72, 1);
    put32(image, at + 76, 46);
    let use_at = at + 88;
    image[use_at..use_at + 32].copy_from_slice(&regid("*zrax synthetic", [0; 8]));
    put32(image, use_at + 32, 3);
    put32(image, use_at + 36, 2);
    put16(image, use_at + 40, 0x0250);
    put16(image, use_at + 42, 0x0250);
    put16(image, use_at + 44, 0x0250);
    seal(
        &mut image[at..],
        TAG_INTEGRITY,
        u32::try_from(location).expect("small"),
        88 + 46 - 16,
    );
}

/// An anchor volume descriptor pointer at sector `location` (3/10.2): main
/// (16) and reserve (24) sequence extents of 16 sectors.
fn anchor(image: &mut [u8], sector: usize, location: usize, places: Places) {
    let at = location * sector;
    let length = u32::try_from(16 * sector).expect("small");
    put32(image, at + 16, length);
    put32(image, at + 20, u32::try_from(places.main).expect("small"));
    put32(image, at + 24, length);
    put32(
        image,
        at + 28,
        u32::try_from(places.reserve).expect("small"),
    );
    seal(
        &mut image[at..],
        TAG_ANCHOR,
        u32::try_from(location).expect("small"),
        512 - 16,
    );
}

/// The tree most synthetic tests use: an ELF in the root, the Mach-O two
/// directories down, a text file and a file outside Latin-1.
fn sample_tree() -> Vec<Item> {
    vec![
        Item::File("payload.elf", payload_elf()),
        Item::Dir(
            "deep",
            vec![Item::Dir(
                "a",
                vec![Item::File("kernel.macho", kernel_macho())],
            )],
        ),
        Item::File("readme.txt", b"zrax: not a recognized format\n".to_vec()),
        Item::File("caf\u{e9}-\u{20ac}.elf", payload_elf()),
    ]
}

const SAMPLE_MEMBERS: [&str; 3] = [
    "/payload.elf",
    "/caf\u{e9}-\u{20ac}.elf",
    "/deep/a/kernel.macho",
];

/// A 3-block file whose middle block is zero, for sparse extents.
fn sparse_elf() -> Vec<u8> {
    let mut data = payload_elf();
    data.resize(2048, b'a');
    data.extend_from_slice(&[0; 2048]);
    data.extend_from_slice(&[b'z'; 1000]);
    data
}

/// A 2-block file.
fn two_block_elf() -> Vec<u8> {
    let mut data = payload_elf();
    data.resize(2048 + 900, b'b');
    data
}

// ---------------------------------------------------------------------------
// Fixtures written by real tools (tests/fixtures/udf/README.md)
// ---------------------------------------------------------------------------

#[test]
fn hdiutil_udf_102_and_150_list_the_tree_with_short_allocation() {
    for (name, revision) in [("hdiutil-102.iso", "1.02"), ("hdiutil-150.iso", "1.50")] {
        let image = udf_fixture(name);
        assert!(is_udf(&image, Layout::Udf), "{name}");
        let c = parse(&image);
        assert_eq!(labels(&c), TREE_MEMBERS, "{name}");
        assert_tree_members(name, &c);
        assert_eq!(c.target, None);
        assert_eq!(c.consumed, image.len());
        assert!(
            has_note(
                &c,
                &format!("UDF revision {revision} (NSR02), 2 KiB logical blocks")
            ),
            "{name}: {}",
            notes(&c)
        );
        assert!(has_note(&c, "read-only"), "{name}");
        assert!(has_note(
            &c,
            "Anchor volume descriptor pointers at sectors 256 and 299 (N - 256)"
        ));
        assert!(has_note(
            &c,
            "4 regular files in 7 directories; 3 recognized members listed"
        ));
        assert!(has_note(
            &c,
            "Logical volume integrity: closed; 4 files and 7 directories"
        ));
        assert!(has_note(&c, "No processor field: UDF names no ISA"));

        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::Udf);
        assert_eq!(p.format.variant_name.as_deref(), Some("UDF"));
        // The first member in walk order supplies the primary ISA.
        assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::X86_64, 64));
        let macho = slice(&p, TREE_MEMBERS[1]);
        assert_eq!(macho.isa, Isa::AArch64);
        let offset = macho.offset as usize;
        assert_eq!(&image[offset..offset + 4], &[0xcf, 0xfa, 0xed, 0xfe]);
        assert_eq!(metadata(&p, "udf_revision"), revision);
        assert_eq!(metadata(&p, "udf_nsr"), "NSR02");
        assert_eq!(metadata(&p, "udf_partition_maps"), "type 1");
        assert_eq!(metadata(&p, "udf_access_type"), "read-only");
        assert_eq!(metadata(&p, "udf_member_count"), "3");
        assert_eq!(
            metadata(&p, "udf_implementation"),
            "*Apple Mac OS X DiscRec"
        );
    }
}

#[test]
fn hdiutil_bridge_disc_is_reported_as_udf_while_its_iso_9660_view_stays_readable() {
    let image = udf_fixture("hdiutil-bridge.iso");
    assert!(is_udf(&image, Layout::Bridge));
    assert_eq!(udf::detect(&image), Some(Layout::Bridge));
    let c = parse(&image);
    assert_eq!(c.variant, "UDF bridge (UDF and ISO 9660)");
    assert_eq!(labels(&c), TREE_MEMBERS);
    assert!(
        has_note(
            &c,
            "UDF bridge disc: an ECMA-119 (ISO 9660) volume descriptor set precedes"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(&c, "CD001 (ECMA-119 descriptor) at 0x8000"));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Udf);
    assert_eq!(
        metadata(&p, "udf_recognition_sequence"),
        "CD001, CD001, BEA01, NSR02, TEA01"
    );
    // The ISO 9660 family still reads the same disc on its own.
    let iso = iso9660::detect(&image).expect("an ISO 9660 volume");
    let iso_view = iso9660::parse_container(&image, iso).expect("parses as ISO 9660");
    assert!(iso_view.children.len() >= 2);
}

#[test]
fn iso_9660_family_bridge_fixture_is_udf_with_its_el_torito_record_noted() {
    // The hdiutil fixture of the ISO 9660 tests (-iso -joliet -udf with an
    // El Torito boot image).
    let image = gunzip(&fixture("iso9660/hdiutil.iso.gz"));
    assert!(is_udf(&image, Layout::Bridge));
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/bin/payload-with-a-long-name.elf",
            "/deep/l1/l2/l3/l4/l5/l6/l7/l8/deep.elf"
        ]
    );
    assert!(
        has_note(
            &c,
            "it holds an El Torito boot record at 0x8800, whose boot images the ISO 9660 \
             reading lists"
        ),
        "{}",
        notes(&c)
    );
}

#[test]
fn bridge_disc_whose_udf_part_does_not_open_stays_iso_9660() {
    let image = udf_fixture("hdiutil-bridge.iso");
    let c = parse(&image);
    assert!(has_note(
        &c,
        &format!("Partition 0 (+NSR02): sector {HDIUTIL_PARTITION},")
    ));
    // Block 2 of the partition is the root directory's file entry: break
    // its tag checksum.
    let mut damaged = image.clone();
    damaged[(HDIUTIL_PARTITION + 2) * 2048 + 4] ^= 0xff;
    assert_eq!(udf::detect(&damaged), None);
    assert!(matches!(
        detect_format(&damaged),
        DetectedFormat::Container {
            kind: Kind::Iso9660(_)
        }
    ));
    // A disc without the ECMA-119 set is strong: the same damage is a
    // parse error, not a missed volume.
    let mut plain = udf_fixture("hdiutil-102.iso");
    plain[(HDIUTIL_PARTITION + 2) * 2048 + 4] ^= 0xff;
    assert_eq!(udf::detect(&plain), Some(Layout::Udf));
    let message = parse_error(&plain);
    assert!(
        message.starts_with("UDF volume parse error: Invalid descriptor tag checksum at 0x89000"),
        "{message}"
    );
}

#[test]
fn newfs_udf_102_records_small_files_in_their_file_entries() {
    let image = udf_fixture("newfs-102.img");
    let c = parse(&image);
    assert_eq!(labels(&c), TREE_MEMBERS);
    assert_tree_members("newfs-102", &c);
    // Embedded data starts after the file entry's 176-byte header and its
    // extended attributes, inside a block.
    let elf = child(&c, TREE_MEMBERS[0]);
    assert_ne!(elf.offset % 2048, 0);
    assert!(has_note(&c, "UDF revision 1.02 (NSR02)"), "{}", notes(&c));
    assert!(has_note(&c, "overwritable"));
}

#[test]
fn newfs_udf_201_reassembles_a_fragmented_file() {
    let image = udf_fixture("newfs-201.img");
    let c = parse(&image);
    let mut expected = vec!["/fragmented.elf".to_string()];
    expected.extend(TREE_MEMBERS.iter().map(|s| s.to_string()));
    assert_eq!(labels(&c), expected);
    assert_tree_members("newfs-201", &c);
    let fragmented = child(&c, "/fragmented.elf");
    assert_eq!(fragmented.data.as_ref(), fragmented_elf().as_slice());
    assert_eq!(fragmented.transform, Some("UDF extents"));
    // The stored range is the first extent's: 4 KiB of the 40 KiB.
    assert_eq!(fragmented.stored_size, 4096);
    assert_eq!(&image[fragmented.offset..fragmented.offset + 4], b"\x7fELF");
    assert!(has_note(&c, "UDF revision 2.01 (NSR03)"), "{}", notes(&c));
    let p = classify(&image);
    let slice = slice(&p, "/fragmented.elf");
    let decoded = slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "UDF extents");
    assert_eq!(decoded.size, 40 << 10);
    assert_eq!(slice.size, 4096);
}

#[test]
fn newfs_udf_250_reads_the_metadata_partition() {
    let image = udf_fixture("newfs-250.img");
    let c = parse(&image);
    assert_eq!(labels(&c), TREE_MEMBERS);
    assert_tree_members("newfs-250", &c);
    assert!(
        has_note(
            &c,
            "1: metadata (partition 0; metadata file at block 1, mirror at block"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "metadata partition of 32 blocks in 1 extents of the metadata file"
    ));
    let p = classify(&image);
    assert_eq!(metadata(&p, "udf_partition_maps"), "type 1, metadata");
    assert_eq!(metadata(&p, "udf_revision"), "2.50");
    assert_eq!(metadata(&p, "udf_logical_volume_id"), "ZRAX_UDF250");
}

#[test]
fn newfs_udf_512_and_4096_byte_blocks_are_found_from_the_anchor() {
    let small = udf_fixture("newfs-512.img");
    let c = parse(&small);
    assert_eq!(labels(&c), TREE_MEMBERS);
    assert_tree_members("newfs-512", &c);
    assert!(has_note(&c, "512 B logical blocks"), "{}", notes(&c));
    assert!(has_note(
        &c,
        "Anchor volume descriptor pointers at sectors 256, 1791 (N - 256) and 2047 (N)"
    ));
    assert_eq!(metadata(&classify(&small), "udf_block_size"), "512");

    let large = udf_fixture("newfs-4k.img");
    let c = parse(&large);
    assert_eq!(c.children.len(), 0);
    assert!(has_note(&c, "4 KiB logical blocks"), "{}", notes(&c));
    assert!(has_note(
        &c,
        "NSR03 (ECMA-167 3rd edition volume) at 0x9000"
    ));
    assert!(has_note(&c, "0 regular files in 1 directories"));
    let p = classify(&large);
    assert_eq!(p.format.format, FileFormat::Udf);
    assert_eq!(p.primary.isa, Isa::Unknown(0));
}

#[test]
fn fixture_prefixes_are_truncated_volumes_that_list_only_members_inside_them() {
    for name in [
        "hdiutil-102.iso",
        "hdiutil-bridge.iso",
        "newfs-201.img",
        "newfs-250.img",
        "newfs-512.img",
    ] {
        let image = udf_fixture(name);
        prefix_sweep(name, &image);
    }
}

/// Parse prefixes of `image`: every one is either not detected (shorter
/// than the anchor), a parse error, or a truncated volume whose members are
/// members of the whole volume inside the prefix.
fn prefix_sweep(name: &str, image: &[u8]) {
    let whole = parse(image);
    let mut read = 0;
    for end in prefix_ends(image.len(), 0x8000 + 0x2000, 1009, 2048) {
        let prefix = &image[..end];
        let Some(layout) = udf::detect(prefix) else {
            continue;
        };
        match udf::parse_container(prefix, layout) {
            Ok(c) => {
                read += 1;
                assert_members_inside(name, &whole, &c, end);
                if c.children.len() < whole.children.len() {
                    assert!(
                        has_note(&c, "Volume truncated: ") || has_note(&c, "past the end of the"),
                        "{name}: prefix {end}: {}",
                        notes(&c)
                    );
                }
            }
            Err(e) => assert!(
                e.to_string().starts_with("UDF volume parse error: "),
                "{name}: prefix {end}: {e}"
            ),
        }
    }
    assert!(read > 0, "{name}: no prefix was read");
}

#[test]
fn truncated_volume_reads_the_members_before_the_cut() {
    let image = udf_fixture("hdiutil-102.iso");
    // Cut inside the Mach-O's data: the ELFs before it stay listed.
    let whole = parse(&image);
    let macho = child(&whole, TREE_MEMBERS[1]);
    let end = macho.offset + 4096;
    let c = parse(&image[..end]);
    assert_eq!(labels(&c), [TREE_MEMBERS[0], TREE_MEMBERS[2]]);
    assert!(has_note(&c, "Volume truncated: "), "{}", notes(&c));
    assert!(has_note(
        &c,
        "1 regular files were not listed: file data lies partly or wholly past the end"
    ));
    assert!(has_note(&c, "none at N - 256 or N of the input"));
    // Cut before the descriptor sequence's partition: a truncation error.
    let message = parse_error(&image[..HDIUTIL_PARTITION * 2048]);
    assert!(
        message.contains("Truncated UDF volume: the file set descriptor lies past the end"),
        "{message}"
    );
}

#[test]
fn fixture_mutations_of_the_metadata_never_panic() {
    // newfs-201.img lists 40 text files, each probed on every parse, so it
    // is swept more coarsely.
    for (name, coarseness) in [
        ("hdiutil-bridge.iso", 1),
        ("newfs-201.img", 8),
        ("newfs-250.img", 1),
        ("newfs-512.img", 1),
    ] {
        let image = udf_fixture(name);
        let sector = if name == "newfs-512.img" { 512 } else { 2048 };
        // The recognition sequence, the descriptor sequences, the anchor
        // and the first blocks of the partition, where the file set,
        // entries and directories are.
        let positions: Vec<usize> = (0x8000..0xb000)
            .step_by(7 * coarseness)
            .chain((16 * 2048..(40 * 2048).min(image.len())).step_by(13 * coarseness))
            .chain((256 * sector..256 * sector + 512).step_by(coarseness))
            .chain((257 * sector..(300 * sector).min(image.len())).step_by(11 * coarseness))
            .collect();
        mutation_sweep(&image, &positions, 199);
    }
}

/// Set each of `positions` to 0x00, 0xFF and its bit-0 flip in turn and
/// parse what is detected; every `classify_every`th position also goes
/// through the whole classifier. The image is mutated in place and
/// restored.
fn mutation_sweep(image: &[u8], positions: &[usize], classify_every: usize) {
    let mut mutated = image.to_vec();
    for (n, &position) in positions.iter().enumerate() {
        let original = image[position];
        for value in [0x00, 0xff, original ^ 0x01] {
            mutated[position] = value;
            if let Some(layout) = udf::detect(&mutated) {
                let _ = udf::parse_container(&mutated, layout);
            }
            if n % classify_every == 0 {
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
        mutated[position] = original;
    }
}

// ---------------------------------------------------------------------------
// Synthetic volumes
// ---------------------------------------------------------------------------

#[test]
fn layout_metadata_and_json_identifier() {
    assert_eq!(Layout::Udf.format(), FileFormat::Udf);
    assert_eq!(Layout::Udf.label(), "UDF");
    assert!(!Layout::Udf.is_weak());
    assert_eq!(serde_json::to_string(&FileFormat::Udf).unwrap(), "\"udf\"");
    assert_eq!(FileFormat::Udf.to_string(), "UDF volume");
    let volume = build(Options::default(), &sample_tree());
    assert!(is_udf(&volume.image, Layout::Udf));
    let c = container::parse(&volume.image, Kind::Udf(Layout::Udf)).expect("parses");
    assert_eq!(c.format, FileFormat::Udf);
}

#[test]
fn every_allocation_form_lists_its_files_with_entries_and_extended_entries() {
    for extended in [false, true] {
        for files in [Data::Embedded, Data::Short, Data::Long, Data::Extended] {
            let options = Options {
                extended,
                files,
                ..Options::default()
            };
            let volume = build(options, &sample_tree());
            let c = parse(&volume.image);
            let what = format!("{files:?}, extended {extended}");
            assert_eq!(labels(&c), SAMPLE_MEMBERS, "{what}: {}", notes(&c));
            assert_eq!(
                child(&c, "/payload.elf").data.as_ref(),
                payload_elf().as_slice(),
                "{what}"
            );
            assert_eq!(
                child(&c, "/deep/a/kernel.macho").data.as_ref(),
                kernel_macho().as_slice(),
                "{what}"
            );
            assert!(
                matches!(child(&c, "/payload.elf").data, Cow::Borrowed(_)),
                "{what}"
            );
            assert!(has_note(&c, "3 recognized members listed"), "{what}");
        }
    }
}

#[test]
fn several_extents_unrecorded_extents_and_continuations_are_reassembled() {
    for (files, data) in [
        (Data::Fragmented, two_block_elf()),
        (Data::Sparse, sparse_elf()),
        (Data::Continued, two_block_elf()),
    ] {
        let options = Options {
            files,
            ..Options::default()
        };
        let volume = build(options, &[Item::File("split.elf", data.clone())]);
        let c = parse(&volume.image);
        let member = child(&c, "/split.elf");
        assert_eq!(member.data.as_ref(), data.as_slice(), "{files:?}");
        assert_eq!(member.transform, Some("UDF extents"), "{files:?}");
        assert_eq!(member.stored_size, 2048, "{files:?}");
        assert_eq!(&volume.image[member.offset..member.offset + 4], b"\x7fELF");
    }
}

#[test]
fn directories_recorded_in_blocks_and_512_or_4096_byte_sectors_read_the_same() {
    for sector in [512, 2048, 4096] {
        for directories in [Data::Embedded, Data::Short] {
            let options = Options {
                sector,
                directories,
                files: Data::Long,
                ..Options::default()
            };
            let volume = build(options, &sample_tree());
            let c = parse(&volume.image);
            assert_eq!(
                labels(&c),
                SAMPLE_MEMBERS,
                "{sector} {directories:?}: {}",
                notes(&c)
            );
            let p = classify(&volume.image);
            assert_eq!(metadata(&p, "udf_block_size"), sector.to_string());
        }
    }
}

#[test]
fn metadata_partition_maps_blocks_through_the_metadata_file_or_its_mirror() {
    let options = Options {
        space: Space::Metadata,
        files: Data::Long,
        ..Options::default()
    };
    let volume = build(options, &sample_tree());
    let c = parse(&volume.image);
    assert_eq!(labels(&c), SAMPLE_MEMBERS, "{}", notes(&c));
    assert!(has_note(&c, "of the metadata file"), "{}", notes(&c));
    // The entries were interleaved with file data, so the metadata file
    // records several extents.
    assert!(!has_note(&c, "in 1 extents"), "{}", notes(&c));

    // Damage the metadata file's entry: the mirror supplies the extents.
    let mut damaged = volume.image.clone();
    let main = volume.physical_offset(0);
    damaged[main + 20] ^= 0xff;
    let c = parse(&damaged);
    assert_eq!(labels(&c), SAMPLE_MEMBERS);
    assert!(
        has_note(
            &c,
            "metadata mirror file (the metadata file could not be read)"
        ),
        "{}",
        notes(&c)
    );

    // Both damaged: a parse error naming both.
    let mirror = volume.physical_offset(1);
    damaged[mirror + 20] ^= 0xff;
    let message = parse_error(&damaged);
    assert!(
        message.contains("Invalid metadata partition: metadata file: "),
        "{message}"
    );
    assert!(message.contains("; mirror file: "), "{message}");
}

#[test]
fn virtual_partitions_read_entries_through_the_vat() {
    for space in [Space::Virtual, Space::Virtual150] {
        let options = Options {
            space,
            files: Data::Long,
            ..Options::default()
        };
        let volume = build(options, &sample_tree());
        let c = parse(&volume.image);
        assert_eq!(labels(&c), SAMPLE_MEMBERS, "{space:?}: {}", notes(&c));
        let revision = if space == Space::Virtual {
            "2.00"
        } else {
            "1.50"
        };
        assert!(
            has_note(
                &c,
                &format!("1: virtual (partition 0, VAT of UDF {revision})")
            ),
            "{space:?}: {}",
            notes(&c)
        );
        assert!(has_note(&c, "VAT ICB at sector"), "{space:?}");
        // Without its last sector the VAT is missing.
        let cut = &volume.image[..volume.image.len() - volume.sector];
        let message = parse_error(cut);
        assert!(
            message.contains("Missing virtual allocation table"),
            "{space:?}: {message}"
        );
    }
}

#[test]
fn sparable_partitions_follow_the_sparing_table() {
    let volume = build(
        Options {
            files: Data::Long,
            ..Options::default()
        },
        &sample_tree(),
    );
    let mut image = volume.image.clone();
    // Rewrite the type 1 map as a sparable map (UDF 2.60 2.2.9: packet
    // length 16 (40), one sparing table (42) of one block (44) at sector
    // 200 (48)), in both descriptor sequences.
    let mut map = vec![0u8; 64];
    map[0] = 2;
    map[1] = 64;
    map[4..36].copy_from_slice(&regid("*UDF Sparable Partition", revision_suffix(0x0150)));
    put16(&mut map, 36, 1);
    put16(&mut map, 38, 0);
    put16(&mut map, 40, 16);
    map[42] = 1;
    put32(&mut map, 44, 2048);
    put32(&mut map, 48, 200);
    for start in [volume.places.main, volume.places.reserve] {
        let lvd = (start + 2) * 2048;
        put32(&mut image, lvd + 264, 64);
        image[lvd + 440..lvd + 504].copy_from_slice(&map);
        put16(&mut image, lvd + 10, 440 + 64 - 16);
        reseal(&mut image, lvd);
    }
    // The sparing table (UDF 2.60 2.2.12): tag 0 at sector 200, identifier
    // (16), one entry (48) relocating packet 0 of the partition to sector
    // 160 (56).
    let table = 200 * 2048;
    image[table + 16..table + 48]
        .copy_from_slice(&regid("*UDF Sparing Table", revision_suffix(0x0150)));
    put16(&mut image, table + 48, 1);
    put32(&mut image, table + 56, 0);
    put32(&mut image, table + 60, 160);
    seal(&mut image[table..], TAG_SPARING_TABLE, 200, 64 - 16);
    // Move packet 0 (blocks 0-15: the file set, the root and its files)
    // there and wipe the original.
    let packet = volume.physical_offset(0)..volume.physical_offset(16);
    let moved = image[packet.clone()].to_vec();
    image[160 * 2048..176 * 2048].copy_from_slice(&moved);
    image[packet].fill(0);
    let c = parse(&image);
    assert_eq!(labels(&c), SAMPLE_MEMBERS, "{}", notes(&c));
    assert!(
        has_note(&c, "sparing table at sector 200 relocates 1 packets"),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "0: sparable (partition 0, packets of 16 blocks, 1 sparing tables)"
    ));
}

#[test]
fn strategy_4096_entries_follow_their_indirect_entries() {
    let volume = build(
        Options::default(),
        &[Item::Chained("chained.elf", payload_elf())],
    );
    let c = parse(&volume.image);
    assert_eq!(labels(&c), ["/chained.elf"], "{}", notes(&c));
    assert_eq!(
        child(&c, "/chained.elf").data.as_ref(),
        payload_elf().as_slice()
    );
}

#[test]
fn deleted_entries_links_special_files_and_loops_are_skipped_and_counted() {
    let volume = build(
        Options::default(),
        &[
            Item::Deleted("gone.elf"),
            Item::Link("link"),
            Item::Fifo("fifo"),
            Item::RealTime("video.elf", payload_elf()),
            Item::Transformed("packed.elf", payload_elf()),
            Item::Streams("streams.elf", payload_elf()),
            Item::Dir("sub", vec![Item::Loop("back")]),
        ],
    );
    let c = parse(&volume.image);
    assert_eq!(labels(&c), ["/streams.elf"], "{}", notes(&c));
    for expected in [
        "1 deleted directory entries are skipped",
        "1 symbolic links are not followed",
        "1 devices, FIFOs, sockets and other special files are not read",
        "1 real-time files (file type 249) are not read",
        "1 files with transformed data",
        "1 entries carry named streams",
        "1 directory entries name an ICB already examined",
    ] {
        assert!(has_note(&c, expected), "{expected}: {}", notes(&c));
    }
}

#[test]
fn reserve_sequence_is_read_when_the_main_one_is_damaged() {
    let volume = build(Options::default(), &sample_tree());
    let mut image = volume.image.clone();
    // Break the main logical volume descriptor's CRC.
    let main_lvd = (volume.places.main + 2) * 2048;
    image[main_lvd + 100] ^= 0xff;
    let c = parse(&image);
    assert_eq!(labels(&c), SAMPLE_MEMBERS);
    assert!(
        has_note(
            &c,
            "descriptors from the reserve volume descriptor sequence"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "Main volume descriptor sequence not used: no logical volume descriptor"
    ));
    // Both broken.
    let reserve_lvd = (volume.places.reserve + 2) * 2048;
    image[reserve_lvd + 100] ^= 0xff;
    let message = parse_error(&image);
    assert!(
        message.contains("Invalid volume descriptor sequences: main: no logical volume descriptor"),
        "{message}"
    );
}

#[test]
fn volume_descriptor_pointers_continue_the_main_sequence() {
    let volume = build(Options::default(), &sample_tree());
    let mut image = volume.image.clone();
    // Move the main sequence's four descriptors to sector 112 and leave a
    // volume descriptor pointer (3/10.3: sequence number (16), next extent
    // (20)) in the main extent's first sector.
    let main = volume.places.main;
    let moved = 112;
    for n in 0..4 {
        let from = (main + n) * 2048;
        let to = (moved + n) * 2048;
        let descriptor = image[from..from + 2048].to_vec();
        image[to..to + 2048].copy_from_slice(&descriptor);
        put32(
            &mut image,
            to + 12,
            u32::try_from(moved + n).expect("small"),
        );
        reseal(&mut image, to);
    }
    let pointer = main * 2048;
    image[pointer..pointer + 2048].fill(0);
    put32(&mut image, pointer + 16, 9);
    put32(&mut image, pointer + 20, 4 * 2048);
    put32(
        &mut image,
        pointer + 24,
        u32::try_from(moved).expect("small"),
    );
    seal(
        &mut image[pointer..],
        TAG_POINTER,
        u32::try_from(main).expect("small"),
        512 - 16,
    );
    let c = parse(&image);
    assert_eq!(labels(&c), SAMPLE_MEMBERS);
    assert!(
        has_note(&c, "descriptors from the main volume descriptor sequence"),
        "{}",
        notes(&c)
    );
    // A pointer to itself is followed at most 64 times.
    put32(
        &mut image,
        pointer + 24,
        u32::try_from(main).expect("small"),
    );
    put32(&mut image, pointer + 20, 2048);
    seal(
        &mut image[pointer..],
        TAG_POINTER,
        u32::try_from(main).expect("small"),
        512 - 16,
    );
    let c = parse(&image);
    assert!(
        has_note(&c, "more than 64 volume descriptor pointers"),
        "{}",
        notes(&c)
    );
}

#[test]
fn corrupted_recognition_and_anchor_are_not_detected() {
    let volume = build(Options::default(), &sample_tree());
    let mut image = volume.image.clone();
    image[0x8801..0x8806].copy_from_slice(b"XXXXX");
    assert_eq!(udf::detect(&image), None);
    assert!(parse_error(&image).contains("Missing NSR02 or NSR03 descriptor"));

    let mut image = volume.image.clone();
    image[ANCHOR_SECTOR * 2048 + 20] ^= 0x01;
    assert_eq!(udf::detect(&image), None);
    let message = parse_error(&image);
    assert!(
        message.contains("Missing anchor volume descriptor pointer at sector 256"),
        "{message}"
    );
    assert!(
        message.contains("Invalid descriptor CRC at 0x80000"),
        "{message}"
    );

    // An anchor whose location field names another sector.
    let mut image = volume.image.clone();
    let at = ANCHOR_SECTOR * 2048;
    put32(&mut image, at + 12, 257);
    reseal_checksum(&mut image[at..]);
    assert_eq!(udf::detect(&image), None);
}

#[test]
fn corrupted_volume_descriptors_are_parse_errors() {
    let volume = build(Options::default(), &sample_tree());
    let lvd = |start: usize| (start + 2) * 2048;
    let both = |image: &mut Vec<u8>, at: usize, value: u32| {
        for start in [volume.places.main, volume.places.reserve] {
            put32(image, lvd(start) + at, value);
            reseal(image, lvd(start));
        }
    };

    // A logical block size other than the sector size.
    let mut image = volume.image.clone();
    both(&mut image, 212, 4096);
    let message = parse_error(&image);
    assert!(
        message.contains("Unsupported logical block size 4096 B"),
        "{message}"
    );

    // A file set descriptor in a partition reference that has no map.
    let mut image = volume.image.clone();
    for start in [volume.places.main, volume.places.reserve] {
        put16(&mut image, lvd(start) + 248 + 8, 5);
        reseal(&mut image, lvd(start));
    }
    let message = parse_error(&image);
    assert!(
        message.contains("Invalid partition reference 5"),
        "{message}"
    );

    // Partition contents that ECMA-167 Part 4 does not interpret.
    let mut image = volume.image.clone();
    for start in [volume.places.main, volume.places.reserve] {
        let pd = (start + 1) * 2048;
        image[pd + 24..pd + 56].copy_from_slice(&regid("+CD001", [0; 8]));
        reseal(&mut image, pd);
    }
    let message = parse_error(&image);
    assert!(
        message.contains("partition contents \"+CD001\" are not ECMA-167 Part 4"),
        "{message}"
    );

    // A map table that does not fit the descriptor.
    let mut image = volume.image.clone();
    both(&mut image, 264, 4000);
    let message = parse_error(&image);
    assert!(
        message.contains("a map table of 4000 B does not fit"),
        "{message}"
    );

    // A damaged file set descriptor.
    let mut image = volume.image.clone();
    image[volume.space_offset(0) + 300] ^= 0xff;
    let message = parse_error(&image);
    assert!(
        message.contains("Invalid file set descriptor at block 0 of partition 0"),
        "{message}"
    );

    // A root ICB that names a regular file.
    let mut image = volume.image.clone();
    let fsd = volume.space_offset(0);
    let file_block = volume.root + 1;
    put32(&mut image, fsd + 404, file_block);
    reseal(&mut image, fsd);
    let message = parse_error(&image);
    assert!(message.contains("expected a directory"), "{message}");
}

#[test]
fn damage_below_the_root_directory_is_noted() {
    let volume = build(
        Options {
            files: Data::Long,
            ..Options::default()
        },
        &sample_tree(),
    );
    // The first file's entry is the block after the root's.
    let mut image = volume.image.clone();
    let payload_entry = volume.space_offset(volume.root + 1);
    image[payload_entry + 60] ^= 0xff;
    let c = parse(&image);
    assert_eq!(labels(&c), &SAMPLE_MEMBERS[1..], "{}", notes(&c));
    assert!(
        has_note(
            &c,
            "/payload.elf: file entry not read: Invalid descriptor CRC"
        ),
        "{}",
        notes(&c)
    );

    // A broken descriptor in the root directory ends its reading.
    let mut image = volume.image.clone();
    let root = volume.space_offset(volume.root);
    // The parent descriptor (40 B) is first; break the next one's CRC.
    let header = 216;
    image[root + header + 40 + 20] ^= 0xff;
    reseal(&mut image, root);
    let c = parse(&image);
    assert_eq!(c.children.len(), 0, "{}", notes(&c));
    assert!(has_note(&c, "/: Invalid descriptor CRC"), "{}", notes(&c));
    assert!(has_note(&c, "the rest of the directory is not read"));
}

#[test]
fn deep_hierarchies_stop_at_the_depth_limit() {
    let mut tree = vec![Item::File("deepest.elf", payload_elf())];
    for _ in 0..70 {
        tree = vec![Item::Dir("d", tree)];
    }
    let volume = build(
        Options {
            files: Data::Embedded,
            ..Options::default()
        },
        &tree,
    );
    let c = parse(&volume.image);
    assert_eq!(c.children.len(), 0);
    assert!(
        has_note(&c, "1 directories or files nested deeper than 64 levels"),
        "{}",
        notes(&c)
    );
}

#[test]
fn synthetic_prefixes_and_mutations_never_claim_missing_bytes_or_panic() {
    for space in [Space::Physical, Space::Metadata, Space::Virtual] {
        let volume = build(
            Options {
                space,
                files: Data::Long,
                ..Options::default()
            },
            &sample_tree(),
        );
        let name = format!("{space:?}");
        if space != Space::Virtual {
            prefix_sweep(&name, &volume.image);
        }
        let positions: Vec<usize> = (0x8000..volume.image.len()).step_by(17).collect();
        mutation_sweep(&volume.image, &positions, 307);
    }
}

// ---------------------------------------------------------------------------
// Samples outside the repository, read in place
// ---------------------------------------------------------------------------

/// The regular files under `dir`, down to `depth` directory levels.
fn files_under(dir: &std::path::Path, depth: usize, files: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() && depth > 0 {
            files_under(&entry.path(), depth - 1, files);
        } else if kind.is_file() {
            files.push(entry.path());
        }
    }
}

/// `IDA_INPUT_DIR` names IDA Pro's test inputs, none of which is a UDF
/// volume (a scan of their recognition areas on 2026-10-13 found no NSR
/// descriptor): none of them, in any directory up to 16 levels below, may
/// be detected as one. Skips without the variable.
#[test]
fn ida_inputs_are_not_udf_volumes() {
    let Ok(dir) = std::env::var("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR not set; skipped");
        return;
    };
    let mut files = Vec::new();
    files_under(std::path::Path::new(&dir), 16, &mut files);
    // Detection reads the recognition sequence and the anchor at sector
    // 256, at most 1 MiB + 4 KiB in.
    let mut head = vec![0u8; (1 << 20) + 4096];
    let mut scanned = 0;
    for path in files {
        let Ok(mut file) = std::fs::File::open(&path) else {
            continue;
        };
        let mut read = 0;
        while read < head.len() {
            match std::io::Read::read(&mut file, &mut head[read..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => read += n,
            }
        }
        scanned += 1;
        assert_eq!(
            udf::detect(&head[..read]),
            None,
            "{} detected",
            path.display()
        );
    }
    eprintln!("{scanned} IDA inputs scanned");
}

/// `UDF_SAMPLE` names a real UDF image (a DVD or Blu-ray image, for
/// example), read in place and never committed: it is detected, parses,
/// and its members lie inside it. Skips without the variable.
#[test]
fn a_udf_sample_named_by_the_environment_parses() {
    let Ok(path) = std::env::var("UDF_SAMPLE") else {
        eprintln!("UDF_SAMPLE not set; skipped");
        return;
    };
    let image = std::fs::read(&path).expect("UDF_SAMPLE is readable");
    let c = parse(&image);
    for member in &c.children {
        assert!(
            member.offset + member.stored_size <= image.len(),
            "{}",
            member.label
        );
    }
    eprintln!("{path}: {} members\n{}", c.children.len(), notes(&c));
}
