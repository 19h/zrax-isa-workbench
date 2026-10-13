//! Disc image containers: synthetic GCZ, CISO, WBFS, CSO and ZSO images
//! built from the documented layouts (Dolphin `DiscIO`, Wiimms ISO Tools,
//! maxcso, PPSSPP) around a synthetic GameCube disc, a synthetic Wii disc
//! and a committed ISO 9660 image, covering detection, the decoded discs and
//! their own classification, block hashes, blocks that are not stored,
//! corrupted fields, and truncation and mutation sweeps; plus real images
//! from `IDA_INPUT_DIR` when it is set.

use std::path::PathBuf;
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::{self, Container, Kind};
use zrax::formats::discimg::{Cso, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The decode limit (`MAX_PAYLOAD`, 64 MiB).
const MAX_PAYLOAD: usize = 64 << 20;

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// The synthetic x86-64 ELF header of the compressed-stream fixtures.
fn elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

/// The committed bsdtar ISO 9660 image (`tests/fixtures/iso9660`), stored
/// with `gzip -9 -n`: 83968 B, 41 sectors of 2048 B.
fn iso_image() -> Vec<u8> {
    compressed::decode(Codec::Gzip, &fixture("iso9660/joliet.iso.gz"))
        .expect("the fixture decodes")
        .data
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    container::parse(data, Kind::DiscImage(layout)).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    container::parse(data, Kind::DiscImage(layout))
        .expect_err("is a parse error")
        .to_string()
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

fn payload_has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> String {
    p.metadata
        .iter()
        .find(|m| m.key == zrax::MetadataKey::Custom(key.into()))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
        .to_string()
}

/// The layout `detect_format` reports, when it is a disc container.
fn detected(data: &[u8]) -> Option<Layout> {
    match zrax::formats::detect_format(data) {
        zrax::formats::DetectedFormat::Container {
            kind: Kind::DiscImage(layout),
        } => Some(layout),
        _ => None,
    }
}

/// The decoded bytes of the only child, or `None` for a parse error.
fn decoded_disc(data: &[u8], layout: Layout) -> Option<Vec<u8>> {
    let c = container::parse(data, Kind::DiscImage(layout)).ok()?;
    c.children.first().map(|child| child.data.to_vec())
}

fn put_be16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_le64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn u32_of(value: usize) -> u32 {
    u32::try_from(value).expect("fixture value fits in u32")
}

fn le32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("four bytes"))
}

/// Adler-32 (RFC 1950, section 8.2), written out so the fixtures do not
/// reuse the parser's checksum code.
fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

/// Number of blocks of `block_size` that hold `size` bytes.
fn blocks_for(size: usize, block_size: usize) -> usize {
    size / block_size + usize::from(size % block_size != 0)
}

/// `value` rounded up to a multiple of `alignment`.
fn align(value: usize, alignment: usize) -> usize {
    blocks_for(value, alignment) * alignment
}

/// Block `i` of `disc` in blocks of `block_size`, zero-padded to the block
/// size.
fn padded_block(disc: &[u8], i: usize, block_size: usize) -> Vec<u8> {
    let start = (i * block_size).min(disc.len());
    let end = ((i + 1) * block_size).min(disc.len());
    let mut block = disc[start..end].to_vec();
    block.resize(block_size, 0);
    block
}

/// Mutation values for a byte: zero, erased and one bit flipped.
fn mutations(byte: u8) -> [u8; 3] {
    [0x00, 0xff, byte ^ 0x01]
}

/// Parse and classify every mutation of the bytes at `positions`; nothing
/// may panic.
fn mutation_sweep(file: &[u8], layout: Layout, positions: impl Iterator<Item = usize>) {
    for at in positions {
        for value in mutations(file[at]) {
            let mut mutated = file.to_vec();
            mutated[at] = value;
            let _ = container::parse(&mutated, Kind::DiscImage(layout));
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

/// Every prefix at `ends` must be a parse error or decode the same disc as
/// the whole file: a prefix never claims different contents.
fn truncation_sweep(file: &[u8], layout: Layout, ends: impl Iterator<Item = usize>) {
    let whole = decoded_disc(file, layout).expect("the whole file decodes");
    for end in ends {
        if let Some(disc) = decoded_disc(&file[..end], layout) {
            assert_eq!(disc, whole, "prefix {end} decodes other contents");
        }
        let _ = detect_payload(&file[..end], &ClassifierOptions::new());
    }
}

// ---------------------------------------------------------------------------
// Discs inside the containers (YAGCD chapter 13; Dolphin DiscIO)
// ---------------------------------------------------------------------------

/// PowerPC big-endian code: `stwu r1,-16(r1)`, `mflr r0`, `lwz r0,20(r1)`,
/// `mtlr r0`, `addi r1,r1,16`, `blr`, repeated.
fn ppc_code(size: usize) -> Vec<u8> {
    let words: [u32; 6] = [
        0x9421_fff0,
        0x7c08_02a6,
        0x8001_0014,
        0x7c08_03a6,
        0x3821_0010,
        0x4e80_0020,
    ];
    words
        .iter()
        .cycle()
        .flat_map(|w| w.to_be_bytes())
        .take(size)
        .collect()
}

/// A DOL (Dolphin `DolReader.h`): text section 0 at file 0x100 with
/// `text_size` bytes of PowerPC code loaded at 0x80003100, data section 0
/// after it (0x40 B at 0x80100000) and the entry point at the start of the
/// text.
fn dol(text_size: usize) -> Vec<u8> {
    let mut dol = vec![0u8; 0x100];
    // Section offsets: text 0 at 0x00, data 0 at 0x1C.
    put_be32(&mut dol, 0x00, 0x100);
    put_be32(&mut dol, 0x1C, u32_of(0x100 + text_size));
    // Section addresses: text 0 at 0x48, data 0 at 0x64.
    put_be32(&mut dol, 0x48, 0x8000_3100);
    put_be32(&mut dol, 0x64, 0x8010_0000);
    // Section sizes: text 0 at 0x90, data 0 at 0xAC; entry point at 0xE0.
    put_be32(&mut dol, 0x90, u32_of(text_size));
    put_be32(&mut dol, 0xAC, 0x40);
    put_be32(&mut dol, 0xE0, 0x8000_3100);
    dol.extend(ppc_code(text_size));
    dol.extend([0x5a; 0x40]);
    dol
}

/// The GameCube fixture's size and where its FST file lies.
const GAMECUBE_SIZE: usize = 0x6200;
const GAMECUBE_PAYLOAD: usize = 0x6000;

/// A GameCube image (YAGCD 13.1-13.4): game code and maker code `GZRE01`,
/// version 1, the title at 0x20 and the magic 0xC2339F3D at 0x1C; boot DOL
/// offset (0x420), FST offset, size and maximum size (0x424-0x42C); the
/// apploader header at 0x2440 (date, entry 0x81200000, 0x100 B of code, no
/// trailer) and its PowerPC code; the boot DOL at 0x3000; the FST at 0x4000:
/// the root (3 entries), `payload.elf` (the ELF fixture at 0x6000) and
/// `opening.bnr` (0x40 B of zeros at 0x5000).
fn gamecube_disc() -> Vec<u8> {
    let mut image = vec![0u8; GAMECUBE_SIZE];
    image[..6].copy_from_slice(b"GZRE01");
    image[7] = 1;
    image[0x20..0x33].copy_from_slice(b"ZRAX SYNTHETIC DISC");
    put_be32(&mut image, 0x1C, 0xC233_9F3D);
    image[0x2440..0x244A].copy_from_slice(b"2026/10/13");
    put_be32(&mut image, 0x2450, 0x8120_0000);
    put_be32(&mut image, 0x2454, 0x100);
    image[0x2460..0x2560].copy_from_slice(&ppc_code(0x100));
    let boot = dol(0x200);
    image[0x3000..0x3000 + boot.len()].copy_from_slice(&boot);
    let mut fst = vec![0u8; 3 * 12];
    // Root: directory flag and name offset 0, parent 0, 3 entries.
    put_be32(&mut fst, 0, 0x0100_0000);
    put_be32(&mut fst, 8, 3);
    // Files: name offset, data offset, size.
    put_be32(&mut fst, 12, 1);
    put_be32(&mut fst, 16, u32_of(GAMECUBE_PAYLOAD));
    put_be32(&mut fst, 20, 256);
    put_be32(&mut fst, 24, 13);
    put_be32(&mut fst, 28, 0x5000);
    put_be32(&mut fst, 32, 0x40);
    fst.extend_from_slice(b"\0payload.elf\0opening.bnr\0");
    image[0x4000..0x4000 + fst.len()].copy_from_slice(&fst);
    put_be32(&mut image, 0x420, 0x3000);
    put_be32(&mut image, 0x424, 0x4000);
    put_be32(&mut image, 0x428, u32_of(fst.len()));
    put_be32(&mut image, 0x42C, u32_of(fst.len()));
    let elf = elf();
    image[GAMECUBE_PAYLOAD..GAMECUBE_PAYLOAD + elf.len()].copy_from_slice(&elf);
    image
}

/// The Wii fixture's size.
const WII_SIZE: usize = 0x5A000;

/// A Wii image (Dolphin `VolumeWii.cpp`): game ID `RZRP01`, the magic
/// 0x5D1C9EA3 at 0x18; partition group 0 at 0x40000 with two entries in a
/// table at 0x40020 (offsets stored >> 2): UPDATE (type 1) at 0x50000 and
/// DATA (type 0) at 0x58000; each partition header names 0x1000 B of data
/// at 0x1000 (both >> 2), which hold an ELF header that stays opaque.
fn wii_disc() -> Vec<u8> {
    let mut image = vec![0u8; WII_SIZE];
    image[..6].copy_from_slice(b"RZRP01");
    image[7] = 1;
    image[0x20..0x2D].copy_from_slice(b"ZRAX WII DISC");
    put_be32(&mut image, 0x18, 0x5D1C_9EA3);
    put_be32(&mut image, 0x40000, 2);
    put_be32(&mut image, 0x40004, 0x40020 >> 2);
    put_be32(&mut image, 0x40020, 0x50000 >> 2);
    put_be32(&mut image, 0x40024, 1);
    put_be32(&mut image, 0x40028, 0x58000 >> 2);
    put_be32(&mut image, 0x4002C, 0);
    let elf = elf();
    for partition in [0x50000, 0x58000] {
        put_be32(&mut image, partition + 0x2B8, 0x1000 >> 2);
        put_be32(&mut image, partition + 0x2BC, 0x1000 >> 2);
        image[partition + 0x1000..partition + 0x1000 + elf.len()].copy_from_slice(&elf);
    }
    image
}

// ---------------------------------------------------------------------------
// GCZ (Dolphin CompressedBlob.h and CompressedBlob.cpp)
// ---------------------------------------------------------------------------

const GCZ_MAGIC: u32 = 0xB10B_C001;
const GCZ_BLOCK_SIZE: usize = 0x1000;
const GCZ_UNCOMPRESSED: u64 = 1 << 63;

/// A GCZ image and where its parts lie.
struct Gcz {
    file: Vec<u8>,
    /// Start of the block data (`32 + 12 * blocks`).
    data_offset: usize,
    /// Offset of each block from the data start, without the flag.
    offsets: Vec<usize>,
}

impl Gcz {
    /// File offset of block `i`'s pointer and hash.
    fn pointer_at(i: usize) -> usize {
        0x20 + 8 * i
    }

    fn hash_at(&self, i: usize) -> usize {
        0x20 + 8 * self.offsets.len() + 4 * i
    }
}

/// GCZ: the 32-byte little-endian header (magic, sub-type, compressed data
/// size, data size, block size, block count), the block pointers (offset
/// from the data start, bit 63 for a block stored as-is), the Adler-32 of
/// each block's stored bytes, then the blocks: each block of `disc`,
/// zero-padded to the block size, as a zlib stream (level 9), or as-is for
/// the blocks in `stored`, as `ConvertToGCZ` writes them.
fn gcz_with(disc: &[u8], block_size: usize, stored: &[usize]) -> Gcz {
    let count = blocks_for(disc.len(), block_size);
    let mut pointers = Vec::new();
    let mut hashes = Vec::new();
    let mut offsets = Vec::new();
    let mut data = Vec::new();
    for i in 0..count {
        let block = padded_block(disc, i, block_size);
        let (bytes, flag) = if stored.contains(&i) {
            (block, GCZ_UNCOMPRESSED)
        } else {
            (miniz_oxide::deflate::compress_to_vec_zlib(&block, 9), 0)
        };
        offsets.push(data.len());
        pointers.push(data.len() as u64 | flag);
        hashes.push(adler32(&bytes));
        data.extend(bytes);
    }
    let mut file = vec![0u8; 0x20];
    put_le32(&mut file, 0, GCZ_MAGIC);
    put_le32(&mut file, 4, 0);
    put_le64(&mut file, 8, data.len() as u64);
    put_le64(&mut file, 0x10, disc.len() as u64);
    put_le32(&mut file, 0x18, u32_of(block_size));
    put_le32(&mut file, 0x1C, u32_of(count));
    for pointer in &pointers {
        file.extend_from_slice(&pointer.to_le_bytes());
    }
    for hash in &hashes {
        file.extend_from_slice(&hash.to_le_bytes());
    }
    let data_offset = file.len();
    file.extend(data);
    Gcz {
        file,
        data_offset,
        offsets,
    }
}

/// The GameCube disc in 4 KiB blocks, block 3 stored as-is.
fn gcz() -> Gcz {
    gcz_with(&gamecube_disc(), GCZ_BLOCK_SIZE, &[3])
}

#[test]
fn gcz_decodes_the_disc_and_classifies_the_gamecube_disc_inside() {
    let image = gcz();
    assert_eq!(detected(&image.file), Some(Layout::Gcz));
    let c = parse(&image.file, Layout::Gcz);
    assert_eq!(c.format, FileFormat::Gcz);
    assert_eq!(c.variant, "GCZ disc image");
    assert_eq!(c.target, None);
    assert_eq!(labels(&c), ["Disc image"]);
    let disc = &c.children[0];
    assert_eq!(disc.data.as_ref(), gamecube_disc().as_slice());
    assert_eq!(disc.transform, Some("GCZ"));
    assert_eq!(disc.offset, image.data_offset);
    assert_eq!(disc.stored_size, image.file.len() - image.data_offset);
    assert_eq!(disc.target, None);
    assert!(!disc.opaque);
    assert_eq!(c.consumed, image.file.len());

    let p = classify(&image.file);
    assert_eq!(p.format.format, FileFormat::Gcz);
    assert_eq!(p.format.variant_name.as_deref(), Some("GCZ disc image"));
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert_eq!(p.slices.len(), 1);
    let slice = &p.slices[0];
    assert_eq!(slice.label.as_deref(), Some("Disc image"));
    assert_eq!(slice.isa, Isa::Ppc);
    assert_eq!(slice.offset, image.data_offset as u64);
    let decoded = slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "GCZ");
    assert_eq!(decoded.size, GAMECUBE_SIZE as u64);
    assert!(payload_has_note(
        &p,
        "Disc image: ppc (contained GameCube disc)"
    ));
    assert!(payload_has_note(&p, "Primary ISA selected from Disc image"));
}

#[test]
fn gcz_header_tables_and_hashes_are_reported() {
    let image = gcz();
    let c = parse(&image.file, Layout::Gcz);
    assert!(
        has_note(
            &c,
            "GCZ: 7 blocks of 4 KiB; 6 zlib-compressed, 1 stored uncompressed; disc size 25088 B; sub-type 0 (GameCube disc)"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "Adler-32 of the stored bytes verified for all 7 blocks"
    ));
    assert!(has_note(
        &c,
        "GCZ names no ISA; each decoded disc is classified on its own"
    ));
    let p = classify(&image.file);
    assert_eq!(metadata(&p, "gcz_block_size"), "4096");
    assert_eq!(metadata(&p, "gcz_blocks"), "7");
    assert_eq!(metadata(&p, "gcz_stored_blocks"), "1");
    assert_eq!(metadata(&p, "gcz_disc_size"), GAMECUBE_SIZE.to_string());
    assert_eq!(metadata(&p, "gcz_sub_type"), "0");
    assert_eq!(metadata(&p, "gcz_image_size"), image.file.len().to_string());
}

#[test]
fn gcz_hash_mismatch_is_a_note_because_dolphin_still_reads_the_block() {
    let image = gcz();
    let mut corrupt = image.file.clone();
    let at = image.hash_at(2);
    let stored = le32(&corrupt, at);
    put_le32(&mut corrupt, at, stored ^ 1);
    let c = parse(&corrupt, Layout::Gcz);
    assert_eq!(c.children[0].data.as_ref(), gamecube_disc().as_slice());
    assert!(has_note(
        &c,
        "Adler-32 of the stored bytes verified for 6 of 7 blocks"
    ));
    let expected = format!(
        "Adler-32 mismatch in 1 block (first: block 2, stored 0x{:08X}, computed 0x{stored:08X}); Dolphin logs the mismatch and still reads the block",
        stored ^ 1
    );
    assert!(has_note(&c, &expected), "{}", notes(&c));
}

#[test]
fn gcz_block_that_does_not_inflate_is_a_parse_error() {
    let image = gcz();
    let mut corrupt = image.file.clone();
    // Block 1's zlib stream: break its Adler-32 trailer, then make the
    // table hash match the damaged bytes so only the stream is at fault.
    let start = image.data_offset + image.offsets[1];
    let end = image.data_offset + image.offsets[2];
    corrupt[end - 1] ^= 0x55;
    let hash = adler32(&corrupt[start..end]);
    let at = image.hash_at(1);
    put_le32(&mut corrupt, at, hash);
    let message = parse_error(&corrupt, Layout::Gcz);
    assert_eq!(
        message,
        format!(
            "Disc image container parse error: Invalid GCZ block 1 at 0x{start:X}: Invalid zlib Adler-32"
        )
    );
}

#[test]
fn gcz_header_and_table_corruptions_are_parse_errors() {
    let image = gcz();
    // Not a power of two: detection refuses it, the parser names it.
    let mut odd = image.file.clone();
    put_le32(&mut odd, 0x18, 0x1800);
    assert_eq!(detected(&odd), None);
    assert!(parse_error(&odd, Layout::Gcz)
        .contains("Invalid GCZ block size 6144 B: not a power of two"));
    // A block count the data size does not need.
    let mut count = image.file.clone();
    put_le32(&mut count, 0x1C, 8);
    assert_eq!(detected(&count), None);
    assert!(parse_error(&count, Layout::Gcz)
        .contains("Invalid GCZ block count 8 at 0x1C: 25088 B of data in 4096 B blocks need 7"));
    // A block size past the decode limit.
    let mut huge = gcz_with(&[0; 16], 16, &[]).file;
    put_le32(&mut huge, 0x18, 1 << 30);
    put_le32(&mut huge, 0x1C, 1);
    assert!(parse_error(&huge, Layout::Gcz).contains("Unsupported GCZ block size 1073741824 B"));
    // Pointers out of order.
    let mut order = image.file.clone();
    let pointer = Gcz::pointer_at(2);
    order[pointer..pointer + 8].copy_from_slice(&0x7FFF_FFFFu64.to_le_bytes());
    assert!(parse_error(&order, Layout::Gcz)
        .contains("Invalid GCZ block pointer 2 at 0x30: block data at 0x7FFFFFFF end at 0x"));
    // A stored block shorter than the block size.
    let mut short = image.file.clone();
    let pointer = Gcz::pointer_at(4);
    let next = image.offsets[4] as u64 - 1;
    short[pointer..pointer + 8].copy_from_slice(&next.to_le_bytes());
    assert!(parse_error(&short, Layout::Gcz).contains(
        "Invalid GCZ block 3: stored uncompressed in 4095 B instead of the 4096 B block size"
    ));
    // Trailing data that is not padding.
    let mut trailing = image.file.clone();
    trailing.extend_from_slice(b"junk");
    assert_eq!(
        parse_error(&trailing, Layout::Gcz),
        format!(
            "Disc image container parse error: Unexpected 4 B after the GCZ block data at 0x{:X}",
            image.file.len()
        )
    );
    // Truncated tables.
    assert!(parse_error(&image.file[..0x40], Layout::Gcz)
        .contains("Truncated GCZ block table: 7 blocks need 84 B at 0x20; the file holds 64 B"));
    assert!(parse_error(&image.file[..0x10], Layout::Gcz).contains("Truncated GCZ header"));
}

#[test]
fn gcz_disc_past_the_decode_limit_is_cut_at_64_mib() {
    // 65 blocks of 1 MiB of zeros; only the first 64 are decoded.
    let block_size = 1 << 20;
    let zeros = vec![0u8; block_size];
    let stream = miniz_oxide::deflate::compress_to_vec_zlib(&zeros, 9);
    let count = 65usize;
    let mut file = vec![0u8; 0x20];
    put_le32(&mut file, 0, GCZ_MAGIC);
    put_le64(&mut file, 8, (stream.len() * count) as u64);
    put_le64(&mut file, 0x10, (block_size * count) as u64);
    put_le32(&mut file, 0x18, u32_of(block_size));
    put_le32(&mut file, 0x1C, u32_of(count));
    for i in 0..count {
        file.extend_from_slice(&((i * stream.len()) as u64).to_le_bytes());
    }
    for _ in 0..count {
        file.extend_from_slice(&adler32(&stream).to_le_bytes());
    }
    for _ in 0..count {
        file.extend_from_slice(&stream);
    }
    let c = parse(&file, Layout::Gcz);
    assert_eq!(c.children[0].data.len(), MAX_PAYLOAD);
    assert!(
        has_note(
            &c,
            "Disc image is 68157440 B; only the first 64 MiB were decoded and are analyzed"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "Adler-32 of the stored bytes verified for all 65 blocks"
    ));
}

#[test]
fn gcz_truncations_error_or_decode_the_same_disc() {
    let image = gcz();
    truncation_sweep(&image.file, Layout::Gcz, 0..image.file.len());
    for end in 0..image.file.len() {
        assert!(
            container::parse(&image.file[..end], Kind::DiscImage(Layout::Gcz)).is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn gcz_mutations_never_panic() {
    let image = gcz();
    mutation_sweep(&image.file, Layout::Gcz, 0..image.file.len());
}

// ---------------------------------------------------------------------------
// GameCube and Wii CISO (Dolphin CISOBlob; wit lib-ciso)
// ---------------------------------------------------------------------------

const CISO_HEADER_SIZE: usize = 0x8000;
const CISO_BLOCK_SIZE: usize = 0x8000;

/// CISO: `CISO`, the block size (little-endian) and a map of 0x7FF8 bytes
/// (1 for each block of `disc` except those in `unused`), then the used
/// blocks in map order, each zero-padded to the block size.
fn ciso_with(disc: &[u8], block_size: usize, unused: &[usize]) -> Vec<u8> {
    let mut file = vec![0u8; CISO_HEADER_SIZE];
    file[..4].copy_from_slice(b"CISO");
    put_le32(&mut file, 4, u32_of(block_size));
    for i in 0..blocks_for(disc.len(), block_size) {
        if unused.contains(&i) {
            continue;
        }
        file[8 + i] = 1;
        file.extend(padded_block(disc, i, block_size));
    }
    file
}

/// The GameCube disc in one 32 KiB block.
fn ciso() -> Vec<u8> {
    ciso_with(&gamecube_disc(), CISO_BLOCK_SIZE, &[])
}

#[test]
fn ciso_copies_the_used_blocks_and_classifies_the_gamecube_disc_inside() {
    let file = ciso();
    assert_eq!(detected(&file), Some(Layout::Ciso));
    let c = parse(&file, Layout::Ciso);
    assert_eq!(c.format, FileFormat::Ciso);
    assert_eq!(c.variant, "CISO disc image");
    let disc = &c.children[0];
    assert_eq!(disc.label, "Disc image");
    assert_eq!(disc.data.len(), CISO_BLOCK_SIZE);
    assert_eq!(&disc.data[..GAMECUBE_SIZE], gamecube_disc().as_slice());
    assert_eq!(disc.offset, CISO_HEADER_SIZE);
    assert_eq!(disc.stored_size, CISO_BLOCK_SIZE);
    assert_eq!(disc.transform, Some("CISO"));
    assert!(
        has_note(
            &c,
            "CISO: block size 32 KiB; 1 of 32760 map entries used; disc size 32768 B, to the end of the last used block; unused blocks read as zeros"
        ),
        "{}",
        notes(&c)
    );
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Ciso);
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert_eq!(metadata(&p, "ciso_block_size"), "32768");
    assert_eq!(metadata(&p, "ciso_used_blocks"), "1");
    assert_eq!(metadata(&p, "ciso_disc_size"), "32768");
}

#[test]
fn ciso_unused_blocks_read_as_zeros() {
    // Block 0 is the GameCube disc, block 1 is not stored, block 2 is 0x5A.
    let mut disc = gamecube_disc();
    disc.resize(2 * CISO_BLOCK_SIZE, 0x77);
    disc.resize(3 * CISO_BLOCK_SIZE, 0x5A);
    let file = ciso_with(&disc, CISO_BLOCK_SIZE, &[1]);
    let c = parse(&file, Layout::Ciso);
    let decoded = &c.children[0].data;
    assert_eq!(decoded.len(), 3 * CISO_BLOCK_SIZE);
    assert_eq!(&decoded[..GAMECUBE_SIZE], gamecube_disc().as_slice());
    assert!(decoded[CISO_BLOCK_SIZE..2 * CISO_BLOCK_SIZE]
        .iter()
        .all(|b| *b == 0));
    assert!(decoded[2 * CISO_BLOCK_SIZE..].iter().all(|b| *b == 0x5A));
    assert_eq!(c.children[0].stored_size, 2 * CISO_BLOCK_SIZE);
    assert_eq!(classify(&file).primary.isa, Isa::Ppc);
}

#[test]
fn ciso_and_psp_cso_are_told_apart_by_their_structure() {
    assert_eq!(detected(&ciso()), Some(Layout::Ciso));
    assert_eq!(
        detected(&cso(&iso_image(), &CsoOptions::v1())),
        Some(Layout::Cso(Cso::V1))
    );
    // A PSP header with a 64 KiB block size, a 16 MiB disc and 0x8000 in
    // its unreliable header size field reads like a GameCube block size
    // and has only 0 and 1 bytes up to 0x18, but its index holds offsets
    // past 0x18.
    let mut psp = cso(
        &vec![0u8; 16 << 20],
        &CsoOptions {
            block_size: 0x10000,
            ..CsoOptions::v1()
        },
    );
    put_le32(&mut psp, 4, 0x8000);
    assert!(
        psp[8..0x18].iter().all(|b| *b <= 1),
        "{:02X?}",
        &psp[..0x18]
    );
    assert_eq!(detected(&psp), Some(Layout::Cso(Cso::V1)));
    // A CISO map byte that is not 0 or 1 is not a GameCube CISO.
    let mut bad_map = ciso();
    bad_map[0x100] = 2;
    assert_eq!(detected(&bad_map), None);
    assert!(parse_error(&bad_map, Layout::Ciso)
        .contains("Invalid CISO map entry 0xF8 at 0x100: 0x02 (0 unused, 1 used)"));
}

#[test]
fn ciso_corruptions_are_parse_errors() {
    let file = ciso();
    let mut small = file.clone();
    put_le32(&mut small, 4, 0x4000);
    assert_eq!(detected(&small), None);
    assert!(parse_error(&small, Layout::Ciso)
        .contains("Invalid CISO block size 16384 B at 0x4: not a nonzero multiple of 32 KiB"));
    assert!(parse_error(&file[..0x4000], Layout::Ciso)
        .contains("Truncated CISO header: 16384 B of 0x8000 B"));
    assert_eq!(
        parse_error(&file[..CISO_HEADER_SIZE + 0x100], Layout::Ciso),
        "Disc image container parse error: Truncated CISO block 0x0 (stored block 0) at 0x8000 + 32768 B: it lies outside the file"
    );
    let mut trailing = file.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing, Layout::Ciso)
        .contains("Unexpected 4 B after the used CISO blocks at 0x10000"));
    let mut empty = file[..CISO_HEADER_SIZE].to_vec();
    empty[8] = 0;
    let c = parse(&empty, Layout::Ciso);
    assert!(c.children.is_empty());
    assert!(has_note(
        &c,
        "no used blocks, so there is no disc to decode"
    ));
}

#[test]
fn ciso_truncations_error_or_decode_the_same_disc() {
    let file = ciso();
    let ends = (0..0x40)
        .chain((0x40..file.len()).step_by(61))
        .chain(file.len() - 64..file.len());
    truncation_sweep(&file, Layout::Ciso, ends);
}

#[test]
fn ciso_mutations_never_panic() {
    let file = ciso();
    let positions = (0..0x40).chain((0x40..file.len()).step_by(37));
    mutation_sweep(&file, Layout::Ciso, positions);
}

// ---------------------------------------------------------------------------
// WBFS (wit libwbfs; Dolphin WbfsBlob)
// ---------------------------------------------------------------------------

/// The fixture geometry: 512 B hd sectors and 256 KiB WBFS sectors, so a
/// disc has `286864 >> 3 = 35858` blocks and a disc info of
/// `align(0x100 + 2 * 35858, 512) = 72192` B.
const HD_SHIFT: u8 = 9;
const WBFS_SHIFT: u8 = 18;
const HD_SECTOR: usize = 1 << HD_SHIFT;
const WBFS_SECTOR: usize = 1 << WBFS_SHIFT;
const BLOCKS_PER_DISC: usize = 35_858;
const DISC_INFO_SIZE: usize = 72_192;

/// A disc in a WBFS slot: its bytes and the WBFS sector of each of its
/// blocks (0 for a block that is not allocated).
struct WbfsDisc {
    slot: usize,
    disc: Vec<u8>,
    sectors: Vec<u16>,
}

/// WBFS: the head (`WBFS`, the partition size in hd sectors, big-endian;
/// the two shifts; version 1; the disc table with 1 for each used slot);
/// the disc info of each slot at `512 + slot * 72192` (a copy of the disc's
/// first 0x100 bytes and the big-endian WBFS sector of each block); each
/// allocated block at its sector. The partition ends with the last sector
/// used, plus `extra_sectors` free ones.
fn wbfs_with(discs: &[WbfsDisc], extra_sectors: usize) -> Vec<u8> {
    let last = discs
        .iter()
        .flat_map(|d| d.sectors.iter())
        .copied()
        .max()
        .unwrap_or(0) as usize;
    let size = (last + 1 + extra_sectors) * WBFS_SECTOR;
    let mut file = vec![0u8; size];
    file[..4].copy_from_slice(b"WBFS");
    put_be32(&mut file, 4, u32_of(size / HD_SECTOR));
    file[8] = HD_SHIFT;
    file[9] = WBFS_SHIFT;
    file[10] = 1;
    for d in discs {
        file[0x0C + d.slot] = 1;
        let info = HD_SECTOR + d.slot * DISC_INFO_SIZE;
        file[info..info + 0x100].copy_from_slice(&d.disc[..0x100]);
        for (block, sector) in d.sectors.iter().enumerate() {
            put_be16(&mut file, info + 0x100 + 2 * block, *sector);
            if *sector == 0 {
                continue;
            }
            let bytes = padded_block(&d.disc, block, WBFS_SECTOR);
            let at = usize::from(*sector) * WBFS_SECTOR;
            file[at..at + WBFS_SECTOR].copy_from_slice(&bytes);
        }
    }
    file
}

/// The Wii disc in slot 0 (WBFS sectors 1 and 2) and the GameCube disc in
/// slot 2 (sector 3).
fn wbfs() -> Vec<u8> {
    wbfs_with(
        &[
            WbfsDisc {
                slot: 0,
                disc: wii_disc(),
                sectors: vec![1, 2],
            },
            WbfsDisc {
                slot: 2,
                disc: gamecube_disc(),
                sectors: vec![3],
            },
        ],
        0,
    )
}

#[test]
fn wbfs_lists_one_disc_per_used_slot_each_classified_on_its_own() {
    let file = wbfs();
    assert_eq!(detected(&file), Some(Layout::Wbfs));
    let c = parse(&file, Layout::Wbfs);
    assert_eq!(c.format, FileFormat::Wbfs);
    assert_eq!(c.variant, "WBFS image");
    assert_eq!(labels(&c), ["Disc slot 0 (RZRP01)", "Disc slot 2 (GZRE01)"]);
    let wii = &c.children[0];
    assert_eq!(wii.data.len(), 2 * WBFS_SECTOR);
    assert_eq!(&wii.data[..WII_SIZE], wii_disc().as_slice());
    assert_eq!(wii.offset, WBFS_SECTOR);
    assert_eq!(wii.stored_size, 2 * WBFS_SECTOR);
    assert_eq!(wii.transform, Some("WBFS"));
    let gamecube = &c.children[1];
    assert_eq!(&gamecube.data[..GAMECUBE_SIZE], gamecube_disc().as_slice());
    assert_eq!(gamecube.offset, 3 * WBFS_SECTOR);
    assert!(
        has_note(
            &c,
            "WBFS version 1: 2048 hd sectors of 512 B (1048576 B); WBFS sector size 256 KiB; 4 WBFS sectors; 2 of 500 disc slots used"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        &format!("Disc slot 0 (RZRP01): 2 of {BLOCKS_PER_DISC} blocks allocated; disc size 524288 B, to the end of the last allocated block")
    ));

    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Wbfs);
    let slices: Vec<(Option<&str>, Isa)> = p
        .slices
        .iter()
        .map(|s| (s.label.as_deref(), s.isa))
        .collect();
    assert_eq!(
        slices,
        [
            (Some("Disc slot 0 (RZRP01)"), Isa::Unknown(0)),
            (Some("Disc slot 2 (GZRE01)"), Isa::Ppc)
        ]
    );
    // The Wii disc's partitions are encrypted, so the GameCube disc supplies
    // the primary ISA.
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert!(payload_has_note(
        &p,
        "Primary ISA selected from Disc slot 2 (GZRE01)"
    ));
    assert!(payload_has_note(
        &p,
        "Disc slot 0 (RZRP01): unknown(0x0000) (contained Wii disc)"
    ));
    assert_eq!(metadata(&p, "wbfs_sector_size"), "262144");
    assert_eq!(metadata(&p, "wbfs_used_slots"), "2");
}

#[test]
fn wbfs_unallocated_blocks_read_as_zeros() {
    let mut disc = gamecube_disc();
    disc.resize(2 * WBFS_SECTOR, 0x77);
    disc.resize(3 * WBFS_SECTOR, 0x5A);
    let file = wbfs_with(
        &[WbfsDisc {
            slot: 0,
            disc,
            sectors: vec![2, 0, 1],
        }],
        0,
    );
    let c = parse(&file, Layout::Wbfs);
    let decoded = &c.children[0].data;
    assert_eq!(decoded.len(), 3 * WBFS_SECTOR);
    assert_eq!(&decoded[..GAMECUBE_SIZE], gamecube_disc().as_slice());
    assert!(decoded[WBFS_SECTOR..2 * WBFS_SECTOR]
        .iter()
        .all(|b| *b == 0));
    assert!(decoded[2 * WBFS_SECTOR..].iter().all(|b| *b == 0x5A));
    // Sectors 2 and 1 are not consecutive: the first run is sector 2 alone.
    assert_eq!(c.children[0].offset, 2 * WBFS_SECTOR);
    assert_eq!(c.children[0].stored_size, WBFS_SECTOR);
    assert_eq!(classify(&file).primary.isa, Isa::Ppc);
}

#[test]
fn wbfs_slot_and_table_problems_are_reported() {
    let file = wbfs();
    // A block naming a WBFS sector past the partition.
    let mut past = file.clone();
    put_be16(&mut past, HD_SECTOR + 0x100 + 2, 9);
    assert_eq!(
        parse_error(&past, Layout::Wbfs),
        format!(
            "Disc image container parse error: Invalid WBFS disc slot 0 block 1 at 0x{:X}: WBFS sector 9 is past the 4 sectors of the partition",
            HD_SECTOR + 0x102
        )
    );
    // A used slot whose disc info would lie past WBFS sector 0, and a used
    // slot with no allocated block.
    let mut slots = file.clone();
    slots[0x0C + 3] = 1;
    slots[0x0C + 1] = 1;
    let c = parse(&slots, Layout::Wbfs);
    assert_eq!(labels(&c), ["Disc slot 0 (RZRP01)", "Disc slot 2 (GZRE01)"]);
    assert!(has_note(
        &c,
        "Not read: 1 used slot whose disc info would lie outside WBFS sector 0; first: slot 3"
    ));
    assert!(has_note(
        &c,
        "No disc: 1 used slot with no allocated block; first: slot 1"
    ));
    // Bad shifts.
    let mut shifts = file.clone();
    shifts[9] = 14;
    assert_eq!(detected(&shifts), None);
    assert!(parse_error(&shifts, Layout::Wbfs).contains("Invalid WBFS sector shifts at 0x8"));
    // Trailing data after the partition.
    let mut trailing = file.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing, Layout::Wbfs)
        .contains("Unexpected 4 B after the WBFS partition at 0x100000"));
}

#[test]
fn wbfs_partition_past_the_end_of_the_file_is_a_note_when_the_discs_are_present() {
    // Two free WBFS sectors after the last used one, cut off the file: a
    // split image's first part looks like this.
    let file = wbfs_with(
        &[WbfsDisc {
            slot: 0,
            disc: gamecube_disc(),
            sectors: vec![1],
        }],
        2,
    );
    let cut = &file[..2 * WBFS_SECTOR];
    let c = parse(cut, Layout::Wbfs);
    assert_eq!(labels(&c), ["Disc slot 0 (GZRE01)"]);
    assert!(
        has_note(
            &c,
            "The file holds 524288 B of the 1048576 B up to the end of the WBFS partition; blocks past the end of the file are not in it"
        ),
        "{}",
        notes(&c)
    );
    assert_eq!(c.consumed, cut.len());
    // Cutting into the disc's block is an error.
    assert_eq!(
        parse_error(&file[..WBFS_SECTOR + 0x100], Layout::Wbfs),
        "Disc image container parse error: Truncated WBFS disc slot 0 block 0 (WBFS sector 1) at 0x40000 + 262144 B: it lies outside the file"
    );
}

#[test]
fn wbfs_truncations_error_or_decode_the_same_discs() {
    let file = wbfs_with(
        &[WbfsDisc {
            slot: 0,
            disc: gamecube_disc(),
            sectors: vec![1],
        }],
        0,
    );
    let ends = (0..0x40)
        .chain((0x40..file.len()).step_by(1021))
        .chain(file.len() - 64..file.len());
    truncation_sweep(&file, Layout::Wbfs, ends);
}

#[test]
fn wbfs_mutations_never_panic() {
    let file = wbfs();
    // The head, the start of both disc infos and the first bytes of each
    // block.
    let positions = (0..0x20)
        .chain(HD_SECTOR..HD_SECTOR + 0x110)
        .chain(HD_SECTOR + 2 * DISC_INFO_SIZE..HD_SECTOR + 2 * DISC_INFO_SIZE + 0x104)
        .chain((WBFS_SECTOR..file.len()).step_by(4099));
    mutation_sweep(&file, Layout::Wbfs, positions);
}

// ---------------------------------------------------------------------------
// PSP CSO and ZSO (maxcso README_CSO.md, README_ZSO.md; PPSSPP BlockDevices)
// ---------------------------------------------------------------------------

/// How [`cso`] stores an ISO.
#[derive(Clone)]
struct CsoOptions {
    magic: &'static [u8; 4],
    version: u8,
    block_size: usize,
    index_shift: u8,
    /// Blocks stored uncompressed.
    plain: Vec<usize>,
}

impl CsoOptions {
    fn v1() -> Self {
        Self {
            magic: b"CISO",
            version: 1,
            block_size: 0x800,
            index_shift: 0,
            plain: vec![16],
        }
    }

    fn v2() -> Self {
        Self {
            version: 2,
            ..Self::v1()
        }
    }

    fn zso() -> Self {
        Self {
            magic: b"ZISO",
            index_shift: 2,
            ..Self::v1()
        }
    }
}

/// A CSO or ZSO image (little-endian): the magic, header size 0x18, the
/// uncompressed size, the block size, version, index shift and two zero
/// bytes; `blocks + 1` index entries (position >> shift, high bit as the
/// version uses it); the blocks, each aligned to `1 << shift` with zero
/// padding. CSO v1 blocks are raw DEFLATE (level 9), ZSO blocks raw LZ4;
/// version 2 stores even blocks as LZ4 (high bit) and odd ones as
/// DEFLATE. Blocks in `plain` are stored as-is (high bit in v1 and ZSO,
/// a full block in v2).
fn cso(iso: &[u8], options: &CsoOptions) -> Vec<u8> {
    let block_size = options.block_size;
    let count = blocks_for(iso.len(), block_size);
    let alignment = 1usize << options.index_shift;
    let mut file = vec![0u8; 0x18];
    file[..4].copy_from_slice(options.magic);
    put_le32(&mut file, 4, 0x18);
    put_le64(&mut file, 8, iso.len() as u64);
    put_le32(&mut file, 0x10, u32_of(block_size));
    file[0x14] = options.version;
    file[0x15] = options.index_shift;
    let index_at = file.len();
    file.resize(align(index_at + 4 * (count + 1), alignment), 0);
    let lz4 = |block: &[u8]| lz4_flex::block::compress(block);
    let deflate = |block: &[u8]| miniz_oxide::deflate::compress_to_vec(block, 9);
    for i in 0..count {
        let block = &iso[i * block_size..((i + 1) * block_size).min(iso.len())];
        let (bytes, flag) = match (options.magic, options.version) {
            (_, 2) if options.plain.contains(&i) => (block.to_vec(), 0),
            (_, 2) if i % 2 == 0 => (lz4(block), 0x8000_0000),
            (_, 2) => (deflate(block), 0),
            _ if options.plain.contains(&i) => (block.to_vec(), 0x8000_0000),
            (b"ZISO", _) => (lz4(block), 0),
            _ => (deflate(block), 0),
        };
        let entry = u32_of(file.len() >> options.index_shift) | flag;
        put_le32(&mut file, index_at + 4 * i, entry);
        file.extend(bytes);
        file.resize(align(file.len(), alignment), 0);
    }
    let end = u32_of(file.len() >> options.index_shift);
    put_le32(&mut file, index_at + 4 * count, end);
    file
}

#[test]
fn cso_v1_decodes_the_iso_and_classifies_the_iso_9660_image_inside() {
    let iso = iso_image();
    let file = cso(&iso, &CsoOptions::v1());
    assert_eq!(detected(&file), Some(Layout::Cso(Cso::V1)));
    let c = parse(&file, Layout::Cso(Cso::V1));
    assert_eq!(c.format, FileFormat::Cso);
    assert_eq!(c.variant, "CSO v1 image");
    let disc = &c.children[0];
    assert_eq!(disc.label, "Disc image");
    assert_eq!(disc.data.as_ref(), iso.as_slice());
    assert_eq!(disc.transform, Some("CSO"));
    assert_eq!(disc.offset, 0x18 + 4 * 42);
    assert_eq!(disc.offset + disc.stored_size, file.len());
    assert!(
        has_note(
            &c,
            "CSO version 1: 41 blocks of 2 KiB; 40 DEFLATE, 0 LZ4, 1 stored uncompressed; index shift 0; disc size 83968 B; header size field 0x18"
        ),
        "{}",
        notes(&c)
    );
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Cso);
    assert_eq!(p.format.variant_name.as_deref(), Some("CSO v1 image"));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(payload_has_note(
        &p,
        "Disc image: x86_64 (contained ISO 9660)"
    ));
    assert_eq!(metadata(&p, "cso_block_size"), "2048");
    assert_eq!(metadata(&p, "cso_version"), "1");
    assert_eq!(metadata(&p, "cso_disc_size"), "83968");
}

#[test]
fn cso_v2_mixes_lz4_deflate_and_full_size_stored_blocks() {
    let iso = iso_image();
    let file = cso(&iso, &CsoOptions::v2());
    assert_eq!(detected(&file), Some(Layout::Cso(Cso::V2)));
    let c = parse(&file, Layout::Cso(Cso::V2));
    assert_eq!(c.variant, "CSO v2 image");
    assert_eq!(c.children[0].data.as_ref(), iso.as_slice());
    assert!(
        has_note(&c, "20 DEFLATE, 20 LZ4, 1 stored uncompressed"),
        "{}",
        notes(&c)
    );
    // Version 2 headers are strict.
    let mut header_size = file.clone();
    put_le32(&mut header_size, 4, 0);
    assert!(parse_error(&header_size, Layout::Cso(Cso::V2))
        .contains("Invalid CSO v2 header size 0x0 at 0x4: it must be 0x18"));
    let mut unused = file.clone();
    unused[0x16] = 1;
    assert!(parse_error(&unused, Layout::Cso(Cso::V2)).contains("unused bytes at 0x16 are 01 00"));
    let mut last = file.clone();
    let at = 0x18 + 4 * 41;
    let entry = le32(&last, at);
    put_le32(&mut last, at, entry | 0x8000_0000);
    assert!(
        parse_error(&last, Layout::Cso(Cso::V2)).contains("the final entry has the high bit set")
    );
}

#[test]
fn zso_lz4_blocks_with_alignment_padding_decode() {
    let iso = iso_image();
    let file = cso(&iso, &CsoOptions::zso());
    assert_eq!(detected(&file), Some(Layout::Cso(Cso::Zso)));
    let c = parse(&file, Layout::Cso(Cso::Zso));
    assert_eq!(c.format, FileFormat::Cso);
    assert_eq!(c.variant, "ZSO image");
    assert_eq!(c.children[0].data.as_ref(), iso.as_slice());
    assert_eq!(c.children[0].transform, Some("ZSO"));
    assert!(has_note(
        &c,
        "ZSO version 1: 41 blocks of 2 KiB; 0 DEFLATE, 40 LZ4, 1 stored uncompressed; index shift 2"
    ));
    let p = classify(&file);
    assert_eq!(p.format.variant_name.as_deref(), Some("ZSO image"));
    assert_eq!(p.primary.isa, Isa::X86_64);
}

#[test]
fn cso_index_and_block_corruptions_are_parse_errors() {
    let iso = iso_image();
    let file = cso(&iso, &CsoOptions::v1());
    let layout = Layout::Cso(Cso::V1);
    // Index entries out of order, and block 0 inside the index.
    let mut order = file.clone();
    put_le32(&mut order, 0x18 + 4 * 5, 0xC1);
    assert!(parse_error(&order, layout)
        .contains("Invalid CSO index entry 5 at 0x2C: position 0xC1 is before the previous"));
    let mut inside = file.clone();
    put_le32(&mut inside, 0x18, 0x20);
    assert!(parse_error(&inside, layout).contains("Invalid CSO index entry 0 at 0x18: block 0 at 0x20 lies inside the index, which ends at 0xC0"));
    // An index longer than the file.
    let mut size = file.clone();
    put_le64(&mut size, 8, 1 << 40);
    assert!(parse_error(&size, layout).contains("Truncated CSO index: 536870913 entries at 0x18"));
    // A DEFLATE block that does not decode.
    let mut stream = file.clone();
    let block_3 = le32(&file, 0x18 + 12) as usize;
    stream[block_3] = 0xFF;
    assert!(parse_error(&stream, layout).starts_with(&format!(
        "Disc image container parse error: Invalid CSO block 3 at 0x{block_3:X}: "
    )));
    // A stored block shorter than a block.
    let mut short = file.clone();
    let entry_17 = 0x18 + 4 * 17;
    let next = le32(&file, entry_17);
    put_le32(&mut short, entry_17, next - 1);
    assert!(parse_error(&short, layout).contains("Invalid CSO block 16 at 0x"));
    // Header fields.
    let mut version = file.clone();
    version[0x14] = 3;
    assert_eq!(detected(&version), None);
    assert!(parse_error(&version, layout).contains("Unsupported CSO version 3 at 0x14"));
    let mut shift = file.clone();
    shift[0x15] = 40;
    assert!(
        parse_error(&shift, layout).contains("Unsupported CSO index shift 40 at 0x15 (at most 32)")
    );
    let mut block = file.clone();
    put_le32(&mut block, 0x10, 0x200);
    assert_eq!(detected(&block), None);
    assert!(parse_error(&block, layout).contains("Invalid CSO block size 512 B at 0x10"));
    // An empty disc has no child.
    let empty = cso(&[], &CsoOptions::v1());
    let c = parse(&empty, layout);
    assert!(c.children.is_empty());
    assert!(has_note(
        &c,
        "The CSO holds an empty disc (uncompressed size 0)"
    ));
}

#[test]
fn cso_and_zso_truncations_error_or_decode_the_same_disc() {
    let iso = iso_image();
    for (options, layout) in [
        (CsoOptions::v1(), Layout::Cso(Cso::V1)),
        (CsoOptions::v2(), Layout::Cso(Cso::V2)),
        (CsoOptions::zso(), Layout::Cso(Cso::Zso)),
    ] {
        let file = cso(&iso, &options);
        truncation_sweep(&file, layout, 0..file.len());
        for end in 0..file.len() {
            assert!(
                container::parse(&file[..end], Kind::DiscImage(layout)).is_err(),
                "{layout:?} prefix {end}"
            );
        }
    }
}

#[test]
fn cso_and_zso_mutations_never_panic() {
    let iso = iso_image();
    for (options, layout) in [
        (CsoOptions::v1(), Layout::Cso(Cso::V1)),
        (CsoOptions::v2(), Layout::Cso(Cso::V2)),
        (CsoOptions::zso(), Layout::Cso(Cso::Zso)),
    ] {
        let file = cso(&iso, &options);
        let positions =
            (0..0x18 + 4 * 42 + 0x10).chain((0x18 + 4 * 42 + 0x10..file.len()).step_by(7));
        mutation_sweep(&file, layout, positions);
    }
}

// ---------------------------------------------------------------------------
// Real images
// ---------------------------------------------------------------------------

/// Disc containers among IDA's test inputs (`IDA_INPUT_DIR`), read in place:
/// every file that starts with one of the four magics parses or fails with
/// a bounded error, and classification never panics. On 2026-10-13 the
/// directory held none. Skipped without the variable.
#[test]
fn ida_input_disc_containers_parse_or_fail_with_bounded_errors() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR").map(PathBuf::from) else {
        eprintln!("skipped: IDA_INPUT_DIR is not set");
        return;
    };
    let magics: [&[u8; 4]; 4] = [b"\x01\xC0\x0B\xB1", b"CISO", b"WBFS", b"ZISO"];
    let mut checked = 0;
    let mut directories = vec![dir.clone()];
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        let entries = std::fs::read_dir(&directory).expect("IDA_INPUT_DIR is readable");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                directories.push(path);
            } else {
                files.push(path);
            }
        }
    }
    for path in files {
        let Ok(mut file) = std::fs::File::open(&path) else {
            continue;
        };
        let mut head = [0u8; 4];
        if std::io::Read::read_exact(&mut file, &mut head).is_err() || !magics.contains(&&head) {
            continue;
        }
        let data = std::fs::read(&path).expect("readable");
        if let Some(layout) = detected(&data) {
            let _ = container::parse(&data, Kind::DiscImage(layout));
        }
        let _ = detect_payload(&data, &ClassifierOptions::new());
        checked += 1;
    }
    eprintln!("checked {checked} disc containers in {}", dir.display());
}
