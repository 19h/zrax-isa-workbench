//! HFS Plus and HFSX volumes: macOS fixtures (journal, hard and symbolic
//! links, decmpfs LZVN in the attribute and the resource fork, extents
//! overflow, case-sensitive HFSX with 512 B blocks), synthetic volumes built
//! from the TN1150 layouts for what the fixtures do not cover (HFS wrapper,
//! zlib, LZFSE and stored decmpfs files, unsupported types, damaged B-trees,
//! depth limits), corrupted fields, and truncation and mutation sweeps.

#[path = "support/truncated_volume.rs"]
mod truncated_volume;

use std::borrow::Cow;
use truncated_volume::{assert_members_inside, prefix_ends};
use zrax::formats::container::{self, Child, Container};
use zrax::formats::dmg;
use zrax::formats::hfsplus::{self, Layout};
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

fn hfsplus_img() -> Vec<u8> {
    gunzip(&fixture("hfsplus/hfsplus.img.gz"))
}

fn hfsx_img() -> Vec<u8> {
    gunzip(&fixture("hfsplus/hfsx.img.gz"))
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse a volume that must be valid.
fn parse(image: &[u8]) -> Container<'_> {
    let layout = hfsplus::detect(image).expect("detected as HFS+");
    hfsplus::parse_container(image, layout).expect("parses")
}

/// The error text of a volume that is detected but does not parse.
fn parse_error(image: &[u8]) -> String {
    let layout = hfsplus::detect(image).expect("detected as HFS+");
    hfsplus::parse_container(image, layout)
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

fn be16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(data[at..at + 2].try_into().expect("2 bytes"))
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

/// UTF-16BE code units of `text`.
fn units(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

// ---------------------------------------------------------------------------
// Fixture members (tests/fixtures/hfsplus/README.md)
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

fn payload_elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

fn zrax_macho() -> Vec<u8> {
    padded(
        &fixture("apple/kernel.macho"),
        24 << 10,
        b"zrax synthetic inline member ",
    )
}

fn large_macho() -> Vec<u8> {
    padded(
        &fixture("apple/kernel.macho"),
        200 << 10,
        b"zrax synthetic resource fork member ",
    )
}

fn fragmented_elf() -> Vec<u8> {
    padded(
        &payload_elf(),
        40 << 10,
        b"zrax synthetic fragmented member ",
    )
}

/// The recognized members of `hfsplus.img`, in walk order: the root's
/// files, then subfolders in key order.
const MEMBERS: [&str; 4] = [
    "/payload.elf",
    "/Applications/Zrax.app/Contents/MacOS/Zrax",
    "/bin/fragmented.elf",
    "/Library/large.macho",
];

/// The recognized members of `hfsx.img`, in binary key order.
const HFSX_MEMBERS: [&str; 3] = [
    "/CASE/payload.elf",
    "/case/large.macho",
    "/case/payload.elf",
];

// ---------------------------------------------------------------------------
// Reading the fixtures' layout (TN1150), for checks and targeted mutations
// ---------------------------------------------------------------------------

/// Volume header fields: `blockSize` at 40, fork data records at 192
/// (extents), 272 (catalog) and 352 (attributes); a fork data record's
/// first extent is at its offset 16.
const VOLUME_HEADER: usize = 1024;
const EXTENTS_FILE: usize = VOLUME_HEADER + 192;
const CATALOG_FILE: usize = VOLUME_HEADER + 272;
const ATTRIBUTES_FILE: usize = VOLUME_HEADER + 352;

/// The bytes of a special file stored in one extent, as the fixtures store
/// them: file offset and size.
struct Run {
    offset: usize,
    size: usize,
}

fn special_file(image: &[u8], fork_data: usize) -> Run {
    let block_size = be32(image, VOLUME_HEADER + 40) as usize;
    let logical = u64::from_be_bytes(image[fork_data..fork_data + 8].try_into().unwrap()) as usize;
    let start = be32(image, fork_data + 16) as usize;
    let count = be32(image, fork_data + 20) as usize;
    assert!(count * block_size >= logical, "one extent holds the file");
    Run {
        offset: start * block_size,
        size: logical,
    }
}

/// A leaf record found in a B-tree file: the file offsets of its key
/// (after `keyLength`) and of its data.
struct Found {
    key: usize,
    data: usize,
}

/// Every leaf record of the B-tree in `run`, read from the node
/// descriptors (kind at 8, `numRecords` at 10) and the record offsets at
/// the node ends.
fn leaf_records(image: &[u8], run: &Run) -> Vec<Found> {
    let node_size = usize::from(be16(image, run.offset + 14 + 18));
    let mut found = Vec::new();
    for node in (run.offset..run.offset + run.size).step_by(node_size) {
        if image[node + 8] != 0xff {
            continue;
        }
        let count = usize::from(be16(image, node + 10));
        for i in 0..count {
            let record = node + usize::from(be16(image, node + node_size - 2 * (i + 1)));
            let key_length = usize::from(be16(image, record));
            let data = record + 2 + key_length + (2 + key_length) % 2;
            found.push(Found {
                key: record + 2,
                data,
            });
        }
    }
    found
}

/// The catalog record keyed (`parent`, `name`).
fn catalog_record(image: &[u8], parent: u32, name: &str) -> Found {
    let name = units(name);
    leaf_records(image, &special_file(image, CATALOG_FILE))
        .into_iter()
        .find(|r| {
            let length = usize::from(be16(image, r.key + 4));
            be32(image, r.key) == parent && image[r.key + 6..r.key + 6 + 2 * length] == name[..]
        })
        .expect("catalog record exists")
}

/// The CNID of a catalog file or folder record (at data offset 8).
fn cnid(image: &[u8], record: &Found) -> u32 {
    be32(image, record.data + 8)
}

// ---------------------------------------------------------------------------
// macOS fixtures
// ---------------------------------------------------------------------------

#[test]
fn macos_volumes_are_detected_by_signature_and_named_by_layout() {
    assert_eq!(hfsplus::detect(&hfsplus_img()), Some(Layout::HfsPlus));
    assert_eq!(hfsplus::detect(&hfsx_img()), Some(Layout::Hfsx));
    for (image, format, variant) in [
        (hfsplus_img(), FileFormat::HfsPlus, "HFS+"),
        (hfsx_img(), FileFormat::Hfsx, "HFSX"),
    ] {
        let p = classify(&image);
        assert_eq!(p.format.format, format);
        assert_eq!(p.format.variant_name.as_deref(), Some(variant));
        // The volume header lies in the first 4 KiB.
        assert!(container::is_recognized(&image[..4096]));
    }
    assert_eq!(
        serde_json::to_string(&FileFormat::HfsPlus).unwrap(),
        "\"hfsplus\""
    );
    assert_eq!(
        serde_json::to_string(&FileFormat::Hfsx).unwrap(),
        "\"hfsx\""
    );
}

#[test]
fn recognized_files_are_listed_by_path_and_classified_on_their_own() {
    let p = classify(&hfsplus_img());
    let listed: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(
        listed, MEMBERS,
        "notes.txt, the journal files and the links are not listed"
    );
    let isa = |label: &str| {
        p.slices
            .iter()
            .find(|s| s.label.as_deref() == Some(label))
            .map(|s| s.isa)
            .expect("listed")
    };
    assert_eq!(isa("/payload.elf"), Isa::X86_64);
    assert_eq!(isa("/bin/fragmented.elf"), Isa::X86_64);
    assert_eq!(
        isa("/Applications/Zrax.app/Contents/MacOS/Zrax"),
        Isa::AArch64
    );
    assert_eq!(isa("/Library/large.macho"), Isa::AArch64);
    // The volume names no processor: the first member decides.
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(
        p.notes
            .iter()
            .any(|n| n.message.contains("Primary ISA selected from /payload.elf")),
        "{:?}",
        p.notes
    );

    let image = hfsplus_img();
    let c = parse(&image);
    assert_eq!(c.target, None, "the volume header names no ISA");
    assert_eq!(c.format, FileFormat::HfsPlus);
    assert_eq!(c.consumed, 1 << 20);
    assert!(c
        .children
        .iter()
        .all(|m| m.classify == container::Classify::IfRecognized));
}

#[test]
fn stored_members_keep_their_file_offsets_and_reassembled_ones_their_first_run() {
    let image = hfsplus_img();
    let c = parse(&image);
    let elf = child(&c, "/payload.elf");
    assert_eq!(elf.transform, None, "one extent: borrowed from the image");
    assert_eq!(&elf.data[..], &payload_elf()[..]);
    assert_eq!(
        &image[elf.offset..elf.offset + elf.stored_size],
        &payload_elf()[..]
    );

    // Ten one-block extents, two of them in the extents overflow file.
    let fragmented = child(&c, "/bin/fragmented.elf");
    assert_eq!(fragmented.transform, Some("HFS+ extents"));
    assert_eq!(&fragmented.data[..], &fragmented_elf()[..]);
    assert_eq!(fragmented.stored_size, 4096, "the first run is one block");
    assert_eq!(&image[fragmented.offset..fragmented.offset + 4], b"\x7fELF");
    let record = catalog_record(
        &image,
        cnid(&image, &catalog_record(&image, 2, "bin")),
        "fragmented.elf",
    );
    let catalog_extents = (0..8)
        .filter(|i| be32(&image, record.data + 88 + 16 + 8 * i + 4) != 0)
        .count();
    assert_eq!(catalog_extents, 8, "the catalog record holds eight extents");
    let overflow = leaf_records(&image, &special_file(&image, EXTENTS_FILE));
    assert_eq!(overflow.len(), 1, "one extents overflow record");
    assert_eq!(be32(&image, overflow[0].key + 2), cnid(&image, &record));
    assert_eq!(
        be32(&image, overflow[0].key + 6),
        8,
        "it continues at fork block 8"
    );
}

#[test]
fn decmpfs_lzvn_files_decode_from_the_attribute_and_the_resource_fork() {
    let image = hfsplus_img();
    let c = parse(&image);
    let inline = child(&c, "/Applications/Zrax.app/Contents/MacOS/Zrax");
    assert_eq!(inline.transform, Some("decmpfs LZVN"));
    assert_eq!(&inline.data[..], &zrax_macho()[..]);
    // The stored bytes follow the 16-byte decmpfs header in the attribute:
    // `cmpf` little-endian, type 7, the uncompressed size.
    let header = &image[inline.offset - 16..inline.offset];
    assert_eq!(&header[..4], b"fpmc");
    assert_eq!(u32::from_le_bytes(header[4..8].try_into().unwrap()), 7);
    assert_eq!(
        u64::from_le_bytes(header[8..16].try_into().unwrap()),
        24 << 10
    );
    assert_eq!(inline.stored_size, 300 - 16);

    let fork = child(&c, "/Library/large.macho");
    assert_eq!(fork.transform, Some("decmpfs LZVN"));
    assert_eq!(&fork.data[..], &large_macho()[..]);
    // The resource fork starts with five offsets for four 64 KiB chunks.
    assert_eq!(fork.stored_size, 1799);
    assert_eq!(&image[fork.offset..fork.offset + 4], &20u32.to_le_bytes());
    assert!(has_note(
        &c,
        "2 decmpfs-compressed files were decoded for examination (LZVN: 2)"
    ));
}

#[test]
fn hard_links_resolve_to_one_indirect_node_and_symlinks_are_counted() {
    let image = hfsplus_img();
    let c = parse(&image);
    assert!(has_note(
        &c,
        "2 hard links were resolved to indirect node files"
    ));
    assert!(has_note(
        &c,
        "1 further link was skipped as it leads to a file already examined"
    ));
    assert!(has_note(&c, "1 symbolic link was counted, not followed"));
    assert!(!labels(&c).iter().any(|label| label.starts_with("/links")));
    assert!(
        !labels(&c).iter().any(|label| label.contains("Private")),
        "the metadata folder is reached only through links"
    );
    assert!(has_note(
        &c,
        "Catalog walk: 8 folders, 7 regular files; members in a recognized format: 4"
    ));
}

#[test]
fn the_journal_is_located_and_never_replayed() {
    let image = hfsplus_img();
    assert!(has_note(
        &parse(&image),
        "Journaled volume: journal of 512 KiB at 0x3000, empty (no transactions); not replayed"
    ));
    // The journal header at 0x3000 was written little-endian on AArch64:
    // magic, endian, start (8), end (16).
    let mut busy = image.clone();
    busy[0x3000 + 16] ^= 0x10;
    assert!(has_note(
        &parse(&busy),
        "holds transactions that were not replayed; metadata may be stale"
    ));
    let mut damaged = image.clone();
    damaged[0x3000] ^= 0xff;
    let c = parse(&damaged);
    assert!(has_note(
        &c,
        "the journal could not be read: Invalid journal header magic"
    ));
    assert_eq!(
        labels(&c),
        MEMBERS,
        "the journal is not needed to read the volume"
    );
    // The journaled attribute bit off: no journal note.
    let mut plain = image;
    plain[VOLUME_HEADER + 6] &= !0x20;
    assert!(!has_note(&parse(&plain), "Journaled"));
}

#[test]
fn hfsx_names_differ_by_case_and_nodes_span_small_blocks() {
    let image = hfsx_img();
    let c = parse(&image);
    assert_eq!(labels(&c), HFSX_MEMBERS);
    assert!(has_note(
        &c,
        "HFSX catalog: case-sensitive names (keyCompareType 0xBC)"
    ));
    assert!(has_note(&c, "1024 allocation blocks of 512 B"));
    assert_eq!(&child(&c, "/CASE/payload.elf").data[..], &payload_elf()[..]);
    assert_eq!(&child(&c, "/case/payload.elf").data[..], &zrax_macho()[..]);
    let large = child(&c, "/case/large.macho");
    assert_eq!(&large.data[..], &large_macho()[..]);
    assert_eq!(large.transform, Some("decmpfs LZVN"));
    // The 1,799 B resource fork lies in four contiguous 512 B blocks.
    assert_eq!(large.stored_size, 1799);

    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let isas: Vec<Isa> = p.slices.iter().map(|s| s.isa).collect();
    assert_eq!(isas, [Isa::X86_64, Isa::AArch64, Isa::AArch64]);
}

#[test]
fn metadata_reports_the_volume_header_and_the_walk() {
    let image = hfsplus_img();
    let c = parse(&image);
    let value = |key: &str| {
        c.metadata
            .iter()
            .find(|m| m.key == zrax::MetadataKey::Custom(key.into()))
            .map(|m| m.value.to_string())
            .unwrap_or_else(|| panic!("{key} is reported"))
    };
    assert_eq!(value("hfsplus_signature"), "H+");
    assert_eq!(value("hfsplus_version"), "4");
    assert_eq!(value("hfsplus_last_mounted_version"), "HFSJ");
    assert_eq!(value("hfsplus_block_size"), "4096");
    assert_eq!(value("hfsplus_total_blocks"), "256");
    assert_eq!(value("hfsplus_catalog_node_size"), "4096");
    assert_eq!(value("hfsplus_volume_name"), "ZRAX");
    assert_eq!(value("hfsplus_directory_count"), "8");
    assert_eq!(value("hfsplus_regular_file_count"), "7");
    assert_eq!(value("hfsplus_member_count"), "4");
    let entries = c.metadata();
    let component = entries
        .iter()
        .find(|e| e.label == "/Library/large.macho")
        .expect("component entry");
    assert!(component
        .value
        .to_string()
        .ends_with("1799 B stored; 204800 B decoded (decmpfs LZVN)"));
}

// ---------------------------------------------------------------------------
// Corrupted fields in the fixtures
// ---------------------------------------------------------------------------

#[test]
fn detection_requires_a_consistent_volume_header() {
    let image = hfsplus_img();
    let detected = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut copy = image.clone();
        edit(&mut copy);
        hfsplus::detect(&copy)
    };
    assert_eq!(detected(&|_| {}), Some(Layout::HfsPlus));
    // blockSize not a power of two, or below 512.
    assert_eq!(detected(&|d| put32(d, VOLUME_HEADER + 40, 3000)), None);
    assert_eq!(detected(&|d| put32(d, VOLUME_HEADER + 40, 256)), None);
    // freeBlocks above totalBlocks; no blocks at all.
    assert_eq!(detected(&|d| put32(d, VOLUME_HEADER + 48, 257)), None);
    assert_eq!(detected(&|d| put32(d, VOLUME_HEADER + 44, 0)), None);
    // A catalog extent beyond the volume, an empty catalog file.
    assert_eq!(detected(&|d| put32(d, CATALOG_FILE + 16, 250)), None);
    assert_eq!(detected(&|d| put64(d, CATALOG_FILE, 0)), None);
    assert_eq!(detected(&|d| put32(d, EXTENTS_FILE + 20, 0)), None);
    // H+ is version 4 only; HX starts at version 5.
    assert_eq!(detected(&|d| put16(d, VOLUME_HEADER + 2, 5)), None);
    assert_eq!(detected(&|d| d[VOLUME_HEADER + 1] = b'X'), None);
    assert_eq!(detected(&|d| d[VOLUME_HEADER] = b'B'), None);
}

#[test]
fn an_unknown_hfsx_version_is_refused() {
    let mut image = hfsx_img();
    put16(&mut image, VOLUME_HEADER + 2, 6);
    assert_eq!(hfsplus::detect(&image), Some(Layout::Hfsx));
    assert_eq!(
        parse_error(&image),
        "HFS+ volume parse error: Unsupported HFSX version 6"
    );
}

#[test]
fn volumes_cut_at_their_end_are_truncated_and_trailing_data_must_be_padding() {
    let image = hfsplus_img();
    // The last byte belongs to the alternate volume header, which is not
    // read; every member is present.
    let cut = parse(&image[..image.len() - 1]);
    assert_eq!(labels(&cut), MEMBERS);
    assert_eq!(cut.consumed, image.len() - 1);
    assert!(
        has_note(
            &cut,
            "Volume truncated: 1048575 B of 1 MiB present; files are listed only when all of \
             their data is present"
        ),
        "{:?}",
        cut.notes
    );
    let mut padded = image.clone();
    padded.extend(vec![0u8; 1 << 20]);
    let c = parse(&padded);
    assert_eq!(labels(&c), MEMBERS);
    assert_eq!(c.consumed, 1 << 20, "padding is not part of the volume");
    // Less than a block after the volume is the remainder of a disk that
    // is not a multiple of the block size.
    let mut remainder = image.clone();
    remainder.extend(vec![0x5a; 1024]);
    assert_eq!(parse(&remainder).consumed, remainder.len());
    let mut junk = image;
    junk.extend(vec![0x5a; 4096]);
    assert_eq!(
        parse_error(&junk),
        "HFS+ volume parse error: Invalid trailing data: 4096 B after the volume at 0x100000 \
         are not padding"
    );
}

/// The members of `hfsplus.img` whose data lies before 0xC0000: the
/// attribute-compressed `Zrax` (in the attributes B-tree at 0x8B000) and
/// `/bin/fragmented.elf` (from 0xAC000). `/payload.elf` (0xF3000) and the
/// resource fork of `/Library/large.macho` (0xF5000) lie after it.
const MEMBERS_BEFORE_0XC0000: [&str; 2] = [
    "/Applications/Zrax.app/Contents/MacOS/Zrax",
    "/bin/fragmented.elf",
];

#[test]
fn truncated_volumes_list_only_the_files_whose_data_is_present() {
    let image = hfsplus_img();
    let whole = parse(&image);
    let end = 0xc0000;
    let prefix = &image[..end];
    let c = parse(prefix);
    assert_eq!(labels(&c), MEMBERS_BEFORE_0XC0000);
    assert_members_inside("hfsplus.img", &whole, &c, end);
    assert_eq!(c.consumed, end);
    for note in [
        "Volume truncated: 768 KiB of 1 MiB present; files are listed only when all of their \
         data is present",
        // /payload.elf, /Library/large.macho and a text file.
        "3 regular files were not listed: file data, or B-tree records that locate it, lie \
         partly or wholly past the 768 KiB present",
        "Catalog walk: 8 folders, 7 regular files; members in a recognized format: 2",
    ] {
        assert!(has_note(&c, note), "{note}: {:?}", c.notes);
    }
    // The classifier lists the members of the prefix.
    let p = classify(prefix);
    assert_eq!(p.format.format, FileFormat::HfsPlus);
    assert_eq!(p.slices.len(), 2);
    for slice in &p.slices {
        assert!(slice.offset + slice.size <= end as u64, "{:?}", slice.label);
    }

    // HFSX: the resource fork of /case/large.macho and both payloads lie
    // past 128 KiB; the compressed file is not counted as decoded.
    let hfsx = hfsx_img();
    let c = parse(&hfsx[..128 << 10]);
    assert_eq!(c.children.len(), 0, "{:?}", labels(&c));
    assert!(has_note(
        &c,
        "3 regular files were not listed: file data, or B-tree records that locate it, lie \
         partly or wholly past the 128 KiB present"
    ));
    assert!(!has_note(&c, "decoded for examination"), "{:?}", c.notes);
}

#[test]
fn a_journal_past_the_end_of_the_input_is_noted() {
    let mut image = hfsplus_img();
    // The journal info block is allocation block 2 (`journalInfoBlock`);
    // its journal offset at 36 moves the journal header to 0xF0000.
    let info = 2 * 4096;
    put64(&mut image, info + 36, 0xf_0000);
    let c = parse(&image[..0xc0000]);
    assert!(
        has_note(
            &c,
            "Journaled volume; the journal lies past the 768 KiB present and was not read"
        ),
        "{:?}",
        c.notes
    );
    // Past the end of the volume it is invalid, truncated or not.
    put64(&mut image, info + 36, 1 << 20);
    assert!(has_note(
        &parse(&image[..0xc0000]),
        "Journaled volume; the journal could not be read: Invalid journal offset 0x100000"
    ));
}

#[test]
fn btree_header_damage_is_a_parse_error() {
    let image = hfsplus_img();
    let catalog = special_file(&image, CATALOG_FILE).offset;
    let header_record = catalog + 14;
    let error_of = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut copy = image.clone();
        edit(&mut copy);
        parse_error(&copy)
    };
    assert!(error_of(&|d| put16(d, header_record + 18, 2048))
        .contains("Invalid catalog B-tree node size 2048"));
    assert!(error_of(&|d| d[header_record + 36] = 128).contains("Invalid catalog B-tree type 128"));
    assert!(error_of(&|d| put16(d, header_record, 17)).contains("Invalid catalog B-tree: depth 17"));
    assert!(error_of(&|d| put32(d, header_record + 2, 16)).contains("root node 16 of 16"));
    assert!(error_of(&|d| put32(d, header_record + 38, 4))
        .contains("Unsupported catalog B-tree without 16-bit key lengths"));
    assert!(error_of(&|d| put32(d, header_record + 22, 17))
        .contains("17 nodes of 4096 B exceed its file of 65536 B"));
    // The header node's kind must be 1.
    assert!(error_of(&|d| d[catalog + 8] = 0).contains("Invalid catalog B-tree header node"));
    let attributes = special_file(&image, ATTRIBUTES_FILE).offset;
    assert!(error_of(&|d| put16(d, attributes + 14 + 18, 1024))
        .contains("Invalid attributes B-tree node size 1024"));
}

#[test]
fn a_missing_root_folder_is_a_parse_error() {
    let image = hfsplus_img();
    let root_thread = catalog_record(&image, 2, "");
    let mut no_thread = image.clone();
    // Re-key the root's thread record to another parent.
    put32(&mut no_thread, root_thread.key, 1_000_000);
    assert!(parse_error(&no_thread).contains("Missing root folder thread record"));
    let root = catalog_record(&image, 1, "ZRAX");
    let mut no_root = image;
    put32(&mut no_root, root.data + 8, 99);
    assert!(parse_error(&no_root).contains("Missing root folder record"));
}

#[test]
fn damage_below_the_root_skips_files_with_notes() {
    let image = hfsplus_img();
    // A missing extents overflow record: re-key it to another file.
    let overflow = &leaf_records(&image, &special_file(&image, EXTENTS_FILE))[0];
    let mut no_overflow = image.clone();
    let file_id = be32(&image, overflow.key + 2);
    put32(&mut no_overflow, overflow.key + 2, 9999);
    let c = parse(&no_overflow);
    assert!(!labels(&c).contains(&"/bin/fragmented.elf".to_string()));
    assert!(has_note(
        &c,
        &format!(
            "Skipped /bin/fragmented.elf: Missing extents overflow record for CNID {file_id} \
             data fork at block 8"
        )
    ));

    // A decmpfs attribute with a wrong magic.
    let attribute = leaf_records(&image, &special_file(&image, ATTRIBUTES_FILE))
        .into_iter()
        .find(|r| image[r.data + 16..r.data + 20] == *b"fpmc")
        .expect("an inline decmpfs attribute");
    let mut bad_magic = image.clone();
    bad_magic[attribute.data + 16] ^= 1;
    let c = parse(&bad_magic);
    assert!(c
        .notes
        .iter()
        .any(|n| n.starts_with("Skipped ") && n.contains("Invalid com.apple.decmpfs magic")));

    // A compressed file whose attribute is gone: re-key it to another file.
    let mut no_attribute = image.clone();
    put32(&mut no_attribute, attribute.key + 2, 9999);
    let c = parse(&no_attribute);
    assert!(has_note(
        &c,
        "Missing com.apple.decmpfs attribute of a compressed file"
    ));

    // A broken hard link: the indirect node renamed.
    let private = catalog_record(&image, 2, "\0\0\0\0HFS+ Private Data");
    let inode = catalog_record(&image, cnid(&image, &private), "iNode27");
    let mut broken = image;
    broken[inode.key + 6 + 2 * 5 + 1] = b'9';
    let c = parse(&broken);
    assert!(has_note(
        &c,
        "Skipped /payload.elf: hard link to the missing indirect node iNode27"
    ));
    assert!(has_note(&c, "2 links point to a missing indirect node"));
    assert!(!labels(&c).contains(&"/payload.elf".to_string()));
}

// ---------------------------------------------------------------------------
// HFS wrapper (TN1150 "HFS Wrapper")
// ---------------------------------------------------------------------------

/// An HFS volume whose master directory block at 1024 embeds `volume`:
/// `drSigWord` `BD` (0), `drNmAlBlks` (0x12), `drAlBlkSiz` (0x14),
/// `drAlBlSt` in 512 B sectors (0x1C), `drVN` (0x24), `drEmbedSigWord`
/// `H+` (0x7C) and `drEmbedExtent` start and count (0x7E, 0x80). The
/// wrapper's allocation blocks start at sector 16; the volume is in its
/// blocks 1 onward, so at file offset 16 * 512 + 4096.
fn wrapped(volume: &[u8]) -> Vec<u8> {
    const FIRST_SECTOR: usize = 16;
    let count = blocks_for(volume.len());
    let offset = FIRST_SECTOR * 512 + BLOCK;
    let mut image = vec![0u8; offset + (count + 1) * BLOCK + 1024];
    let mdb = 1024;
    image[mdb..mdb + 2].copy_from_slice(b"BD");
    put16(&mut image, mdb + 0x12, (count + 2) as u16);
    put32(&mut image, mdb + 0x14, BLOCK as u32);
    put16(&mut image, mdb + 0x1c, FIRST_SECTOR as u16);
    image[mdb + 0x24] = 4;
    image[mdb + 0x25..mdb + 0x29].copy_from_slice(b"WRAP");
    image[mdb + 0x7c..mdb + 0x7e].copy_from_slice(b"H+");
    put16(&mut image, mdb + 0x7e, 1);
    put16(&mut image, mdb + 0x80, count as u16);
    image[offset..offset + volume.len()].copy_from_slice(volume);
    image
}

#[test]
fn an_hfs_wrapper_is_unwrapped_to_its_embedded_volume() {
    let volume = hfsplus_img();
    let image = wrapped(&volume);
    assert_eq!(hfsplus::detect(&image), Some(Layout::HfsWrapper));
    let c = parse(&image);
    assert_eq!(c.format, FileFormat::HfsPlus);
    assert_eq!(c.variant, "HFS+ in an HFS wrapper");
    assert_eq!(labels(&c), MEMBERS);
    assert!(has_note(
        &c,
        "HFS wrapper \"WRAP\": embedded volume at 0x3000, 1 MiB; the wrapper's own files are not \
         read"
    ));
    let unwrapped = parse(&volume);
    for (inner, outer) in unwrapped.children.iter().zip(&c.children) {
        assert_eq!(outer.offset, inner.offset + 0x3000, "{}", inner.label);
        assert_eq!(outer.data, inner.data);
    }
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::HfsPlus);
    assert_eq!(p.primary.isa, Isa::X86_64);

    // The embedded signature must be H+, and the extent must fit.
    let mut no_embed = image.clone();
    no_embed[1024 + 0x7d] = b'X';
    assert_eq!(hfsplus::detect(&no_embed), None);
    let mut too_long = image.clone();
    put16(&mut too_long, 1024 + 0x12, 10);
    assert_eq!(hfsplus::detect(&too_long), None);
    // A wrapper truncated inside the embedded volume, before the catalog
    // (at volume offset 0x9B000), lists nothing.
    let truncated = &image[..0x3000 + (1 << 19)];
    assert_eq!(hfsplus::detect(truncated), Some(Layout::HfsWrapper));
    assert_eq!(
        parse_error(truncated),
        "HFS+ volume parse error: Truncated HFS wrapper: the embedded volume at 0x3000 needs \
         1048576 B, 524288 B present"
    );
    // Truncated after the members, the embedded volume is read up to the
    // end of the input.
    let end = 0x3000 + (1 << 20) - 1;
    let c = parse(&image[..end]);
    assert_eq!(labels(&c), MEMBERS);
    assert_members_inside("wrapped hfsplus.img", &parse(&image), &c, end);
    assert!(has_note(&c, "Volume truncated: 1048575 B of 1 MiB present"));
    // A cut before the embedded volume header is not detected, and its
    // parse is the wrapper's error.
    let headless = &image[..0x3000 + 1024];
    assert_eq!(hfsplus::detect(headless), None);
    let message = hfsplus::parse_container(headless, Layout::HfsWrapper)
        .expect_err("no volume header")
        .to_string();
    assert!(message.contains("Truncated HFS wrapper"), "{message}");
}

// ---------------------------------------------------------------------------
// Synthetic volumes built from the TN1150 layouts
// ---------------------------------------------------------------------------

/// Allocation block and B-tree node size of the synthetic volumes.
const BLOCK: usize = 4096;
const NODE: usize = 4096;

/// Blocks of the synthetic B-trees: the extents overflow file in block 1
/// (one header node), the catalog in blocks 2-17 and the attributes file in
/// blocks 18-21; file data from block 22.
const EXTENTS_START: u32 = 1;
const EXTENTS_NODES: u32 = 1;
const CATALOG_START: u32 = 2;
const CATALOG_NODES: u32 = 16;
const ATTRIBUTES_START: u32 = 18;
const ATTRIBUTES_NODES: u32 = 4;
const FIRST_DATA_BLOCK: u32 = 22;

/// Blocks of `BLOCK` bytes that hold `size` bytes.
fn blocks_for(size: usize) -> usize {
    size / BLOCK + usize::from(size % BLOCK != 0)
}

/// Blocks a synthetic fork occupies.
struct Extent {
    start: u32,
    count: u32,
}

/// Node kinds (`kBTLeafNode`, `kBTIndexNode`, `kBTHeaderNode`).
const LEAF: u8 = 0xff;
const INDEX: u8 = 0;
const HEADER: u8 = 1;

/// `UF_COMPRESSED`, `S_IFREG | 0644`, `S_IFDIR | 0755`.
const UF_COMPRESSED: u8 = 0x20;
const REGULAR_MODE: u16 = 0o100_644;
const FOLDER_MODE: u16 = 0o040_755;

/// A leaf record: the key without `keyLength`, and the data.
struct Record {
    key: Vec<u8>,
    data: Vec<u8>,
}

/// A synthetic volume of 4 KiB blocks.
struct Synthetic {
    image: Vec<u8>,
    next_block: u32,
    next_cnid: u32,
    catalog: Vec<Record>,
    attributes: Vec<Record>,
    /// Most records per catalog leaf; more leaves get an index root.
    records_per_leaf: usize,
}

/// A catalog key: `parentID` (4), name length (2), UTF-16BE name.
fn catalog_key(parent: u32, name: &str) -> Vec<u8> {
    let name = units(name);
    let mut key = parent.to_be_bytes().to_vec();
    key.extend(u16::try_from(name.len() / 2).unwrap().to_be_bytes());
    key.extend(name);
    key
}

/// A thread record (88 B folder, 248 B file layouts below): `recordType`
/// 3 or 4, reserved (2), `parentID` (4), `nodeName`.
fn thread_record(record_type: u16, parent: u32, name: &str) -> Vec<u8> {
    let mut data = record_type.to_be_bytes().to_vec();
    data.extend([0, 0]);
    data.extend(&catalog_key(parent, name)[..]);
    data
}

/// Fork data (80 B): `logicalSize` (0), `clumpSize` (8), `totalBlocks`
/// (12), then one extent (16) and seven unused ones.
fn fork_data(logical_size: u64, extent: &Extent) -> [u8; 80] {
    let mut fork = [0u8; 80];
    put64(&mut fork, 0, logical_size);
    put32(&mut fork, 12, extent.count);
    put32(&mut fork, 16, extent.start);
    put32(&mut fork, 20, extent.count);
    fork
}

/// A keyed record: `keyLength`, the key, a pad byte to an even offset, the
/// data, and a pad byte to an even size.
fn keyed(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut record = u16::try_from(key.len()).unwrap().to_be_bytes().to_vec();
    record.extend(key);
    if record.len() % 2 == 1 {
        record.push(0);
    }
    record.extend(data);
    if record.len() % 2 == 1 {
        record.push(0);
    }
    record
}

/// A node: descriptor (`fLink`, `bLink`, kind, height, `numRecords`), the
/// records from offset 14, and the record offsets in reverse order at the
/// end, the last one pointing at the free space.
fn node(kind: u8, height: u8, f_link: u32, b_link: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let mut node = vec![0u8; NODE];
    put32(&mut node, 0, f_link);
    put32(&mut node, 4, b_link);
    node[8] = kind;
    node[9] = height;
    put16(&mut node, 10, records.len() as u16);
    let mut at = 14;
    for (i, record) in records.iter().enumerate() {
        put16(&mut node, NODE - 2 * (i + 1), at as u16);
        node[at..at + record.len()].copy_from_slice(record);
        at += record.len();
    }
    put16(&mut node, NODE - 2 * (records.len() + 1), at as u16);
    assert!(at + 2 * (records.len() + 1) <= NODE, "records fit the node");
    node
}

/// A header node: the header record (`treeDepth`, `rootNode`,
/// `leafRecords`, `firstLeafNode`, `lastLeafNode`, `nodeSize`,
/// `maxKeyLength`, `totalNodes`, `freeNodes`, `reserved1`, `clumpSize`,
/// `btreeType`, `keyCompareType`, `attributes`, `reserved3`), the 128 B user
/// data record and the map record.
struct TreeHeader {
    depth: u16,
    root: u32,
    leaf_records: u32,
    first_leaf: u32,
    last_leaf: u32,
    max_key_length: u16,
    total_nodes: u32,
    attributes: u32,
}

fn header_node(header: &TreeHeader) -> Vec<u8> {
    let mut record = vec![0u8; 106];
    put16(&mut record, 0, header.depth);
    put32(&mut record, 2, header.root);
    put32(&mut record, 6, header.leaf_records);
    put32(&mut record, 10, header.first_leaf);
    put32(&mut record, 14, header.last_leaf);
    put16(&mut record, 18, NODE as u16);
    put16(&mut record, 20, header.max_key_length);
    put32(&mut record, 22, header.total_nodes);
    record[37] = 0xcf;
    put32(&mut record, 38, header.attributes);
    let map = vec![0u8; NODE - 14 - 106 - 128 - 8];
    node(HEADER, 0, 0, 0, &[record, vec![0u8; 128], map])
}

/// `kBTBigKeysMask | kBTVariableIndexKeysMask`, and the catalog and
/// attribute `maxKeyLength` values.
const VARIABLE_KEYS: u32 = 0x6;
const CATALOG_MAX_KEY: u16 = 516;
const ATTRIBUTES_MAX_KEY: u16 = 266;

impl Synthetic {
    /// An empty volume of `total_blocks` blocks with a root folder `ZRAX`.
    fn new(total_blocks: u32) -> Self {
        let mut s = Self {
            image: vec![0u8; total_blocks as usize * BLOCK],
            next_block: FIRST_DATA_BLOCK,
            next_cnid: 16,
            catalog: Vec::new(),
            attributes: Vec::new(),
            records_per_leaf: usize::MAX,
        };
        s.catalog.push(Record {
            key: catalog_key(1, "ZRAX"),
            data: folder_record(2),
        });
        s.catalog.push(Record {
            key: catalog_key(2, ""),
            data: thread_record(3, 1, "ZRAX"),
        });
        s
    }

    /// Write `bytes` into contiguous free blocks.
    fn store(&mut self, bytes: &[u8]) -> Extent {
        let count = blocks_for(bytes.len()) as u32;
        let start = self.next_block;
        let at = start as usize * BLOCK;
        self.image[at..at + bytes.len()].copy_from_slice(bytes);
        self.next_block += count;
        Extent { start, count }
    }

    fn cnid(&mut self) -> u32 {
        let id = self.next_cnid;
        self.next_cnid += 1;
        id
    }

    fn folder(&mut self, parent: u32, name: &str) -> u32 {
        let id = self.cnid();
        self.catalog.push(Record {
            key: catalog_key(parent, name),
            data: folder_record(id),
        });
        self.catalog.push(Record {
            key: catalog_key(id, ""),
            data: thread_record(3, parent, name),
        });
        id
    }

    /// A file record and its thread; `data` and `resource` fill the forks.
    fn file_record(
        &mut self,
        parent: u32,
        name: &str,
        owner_flags: u8,
        data: &[u8],
        resource: &[u8],
    ) -> u32 {
        let id = self.cnid();
        let data_extent = self.store(data);
        let resource_extent = self.store(resource);
        let mut record = vec![0u8; 248];
        put16(&mut record, 0, 2);
        put16(&mut record, 2, 0x0002);
        put32(&mut record, 8, id);
        record[41] = owner_flags;
        put16(&mut record, 42, REGULAR_MODE);
        record[88..168].copy_from_slice(&fork_data(data.len() as u64, &data_extent));
        record[168..248].copy_from_slice(&fork_data(resource.len() as u64, &resource_extent));
        self.catalog.push(Record {
            key: catalog_key(parent, name),
            data: record,
        });
        self.catalog.push(Record {
            key: catalog_key(id, ""),
            data: thread_record(4, parent, name),
        });
        id
    }

    fn file(&mut self, parent: u32, name: &str, data: &[u8]) -> u32 {
        self.file_record(parent, name, 0, data, &[])
    }

    /// A compressed file: the decmpfs attribute (`cmpf`, `compression_type`
    /// and `uncompressed_size` little-endian, then `payload`) and the
    /// resource fork.
    fn compressed(
        &mut self,
        parent: u32,
        name: &str,
        compression_type: u32,
        size: u64,
        payload: &[u8],
        resource: &[u8],
    ) -> u32 {
        let id = self.file_record(parent, name, UF_COMPRESSED, &[], resource);
        let mut attribute = b"fpmc".to_vec();
        attribute.extend(compression_type.to_le_bytes());
        attribute.extend(size.to_le_bytes());
        attribute.extend(payload);
        self.attribute(id, "com.apple.decmpfs", &attribute);
        id
    }

    /// An inline attribute: key `pad` (2), `fileID` (4), `startBlock` (4),
    /// `attrNameLen` (2), name; data `recordType` 0x10, reserved (8),
    /// `attrSize` (4), the bytes.
    fn attribute(&mut self, file_id: u32, name: &str, bytes: &[u8]) {
        let name = units(name);
        let mut key = vec![0, 0];
        key.extend(file_id.to_be_bytes());
        key.extend(0u32.to_be_bytes());
        key.extend(u16::try_from(name.len() / 2).unwrap().to_be_bytes());
        key.extend(name);
        let mut data = 0x10u32.to_be_bytes().to_vec();
        data.extend([0u8; 8]);
        data.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
        data.extend(bytes);
        self.attributes.push(Record { key, data });
    }

    /// Write the B-trees and the volume header.
    fn build(mut self) -> Vec<u8> {
        self.catalog.sort_by(|a, b| a.key.cmp(&b.key));
        self.attributes.sort_by(|a, b| a.key.cmp(&b.key));
        let catalog = btree(
            &self.catalog,
            self.records_per_leaf,
            CATALOG_MAX_KEY,
            CATALOG_NODES,
        );
        let attributes = btree(
            &self.attributes,
            usize::MAX,
            ATTRIBUTES_MAX_KEY,
            ATTRIBUTES_NODES,
        );
        let extents = header_node(&TreeHeader {
            depth: 0,
            root: 0,
            leaf_records: 0,
            first_leaf: 0,
            last_leaf: 0,
            max_key_length: 10,
            total_nodes: EXTENTS_NODES,
            attributes: 0x2,
        });
        for (start, nodes, tree) in [
            (EXTENTS_START, EXTENTS_NODES, vec![extents]),
            (CATALOG_START, CATALOG_NODES, catalog),
            (ATTRIBUTES_START, ATTRIBUTES_NODES, attributes),
        ] {
            assert!(tree.len() <= nodes as usize, "the tree fits its blocks");
            for (i, node) in tree.iter().enumerate() {
                let at = (start as usize + i) * BLOCK;
                self.image[at..at + NODE].copy_from_slice(node);
            }
        }
        let total_blocks = (self.image.len() / BLOCK) as u32;
        let header = VOLUME_HEADER;
        self.image[header..header + 2].copy_from_slice(b"H+");
        put16(&mut self.image, header + 2, 4);
        put32(&mut self.image, header + 4, 0x100);
        self.image[header + 8..header + 12].copy_from_slice(b"10.0");
        put32(&mut self.image, header + 40, BLOCK as u32);
        put32(&mut self.image, header + 44, total_blocks);
        put32(&mut self.image, header + 64, self.next_cnid);
        for (field, start, count) in [
            (192, EXTENTS_START, EXTENTS_NODES),
            (272, CATALOG_START, CATALOG_NODES),
            (352, ATTRIBUTES_START, ATTRIBUTES_NODES),
        ] {
            let fork = fork_data(u64::from(count) * NODE as u64, &Extent { start, count });
            self.image[header + field..header + field + 80].copy_from_slice(&fork);
        }
        self.image
    }
}

/// A folder record (88 B): `recordType` 1 (0), `folderID` (8), `bsdInfo`
/// with `fileMode` at 42.
fn folder_record(id: u32) -> Vec<u8> {
    let mut record = vec![0u8; 88];
    put16(&mut record, 0, 1);
    put32(&mut record, 8, id);
    put16(&mut record, 42, FOLDER_MODE);
    record
}

/// The nodes of a B-tree of `total_nodes` nodes holding `records` in key
/// order: the header node, leaves of at most `per_leaf` records chained by
/// `fLink`/`bLink`, and an index root over the leaves when there are
/// several.
fn btree(
    records: &[Record],
    per_leaf: usize,
    max_key_length: u16,
    total_nodes: u32,
) -> Vec<Vec<u8>> {
    let mut leaves: Vec<Vec<&Record>> = Vec::new();
    let mut size = NODE;
    for record in records {
        let length = keyed(&record.key, &record.data).len();
        let full = leaves.last().map_or(true, |leaf| {
            leaf.len() >= per_leaf || size + length + 2 * (leaf.len() + 2) > NODE
        });
        if full {
            leaves.push(Vec::new());
            size = 14;
        }
        leaves.last_mut().unwrap().push(record);
        size += length;
    }
    let leaf_count = leaves.len() as u32;
    let mut nodes = Vec::new();
    for (i, leaf) in leaves.iter().enumerate() {
        let number = i as u32 + 1;
        let f_link = if number < leaf_count { number + 1 } else { 0 };
        let b_link = number - 1;
        let records: Vec<Vec<u8>> = leaf.iter().map(|r| keyed(&r.key, &r.data)).collect();
        nodes.push(node(LEAF, 1, f_link, b_link, &records));
    }
    let (depth, root) = match leaf_count {
        0 => (0, 0),
        1 => (1, 1),
        _ => {
            let pointers: Vec<Vec<u8>> = leaves
                .iter()
                .enumerate()
                .map(|(i, leaf)| keyed(&leaf[0].key, &(i as u32 + 1).to_be_bytes()))
                .collect();
            nodes.push(node(INDEX, 2, 0, 0, &pointers));
            (2, leaf_count + 1)
        }
    };
    let header = header_node(&TreeHeader {
        depth,
        root,
        leaf_records: records.len() as u32,
        first_leaf: u32::from(leaf_count > 0),
        last_leaf: leaf_count,
        max_key_length,
        total_nodes,
        attributes: VARIABLE_KEYS,
    });
    let mut tree = vec![header];
    tree.extend(nodes);
    tree
}

/// File offset of catalog node `number` in a synthetic volume.
fn catalog_node(number: usize) -> usize {
    (CATALOG_START as usize + number) * BLOCK
}

#[test]
fn a_synthetic_volume_lists_its_members() {
    let mut s = Synthetic::new(64);
    let bin = s.folder(2, "bin");
    s.file(2, "payload.elf", &payload_elf());
    s.file(bin, "notes.txt", b"not a recognized format\n");
    s.file(bin, "zrax.macho", &zrax_macho());
    let image = s.build();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/payload.elf", "/bin/zrax.macho"]);
    assert_eq!(&child(&c, "/bin/zrax.macho").data[..], &zrax_macho()[..]);
    assert!(has_note(
        &c,
        "Catalog walk: 2 folders, 3 regular files; members in a recognized format: 2"
    ));
    assert!(!has_note(&c, "not unmounted cleanly"));
}

/// zlib, LZFSE and stored decmpfs files: in the attribute (types 1, 3, 11)
/// and in the resource fork (types 4, 12), with stored-marker units.
#[test]
fn zlib_lzfse_and_stored_decmpfs_files_are_decoded() {
    let elf = payload_elf();
    let lzfse = fixture("compressed/payload.elf.lzfse");
    let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&elf, 9);
    // 64 KiB of the padded ELF, then 256 B more: one zlib chunk and one
    // stored chunk (marker 0xFF).
    let two_chunks = padded(&elf, (64 << 10) + 256, b"zrax synthetic zlib chunk ");
    let chunk0 = miniz_oxide::deflate::compress_to_vec_zlib(&two_chunks[..64 << 10], 9);
    let mut chunk1 = vec![0xff];
    chunk1.extend(&two_chunks[64 << 10..]);
    // Type 4 resource fork: Resource Manager header (`dataOffset` 0x100),
    // then at 0x100 the resource length (4 B), the count and the (offset,
    // size) pairs from the table at 0x104.
    let table_size = 4 + 2 * 8;
    let mut zlib_fork = vec![0u8; 0x104];
    put32(&mut zlib_fork, 0, 0x100);
    zlib_fork.extend(2u32.to_le_bytes());
    for (offset, size) in [
        (table_size, chunk0.len()),
        (table_size + chunk0.len(), chunk1.len()),
    ] {
        zlib_fork.extend((offset as u32).to_le_bytes());
        zlib_fork.extend((size as u32).to_le_bytes());
    }
    zlib_fork.extend(&chunk0);
    zlib_fork.extend(&chunk1);
    // Type 12 resource fork: two offsets, then the LZFSE stream.
    let mut lzfse_fork = Vec::new();
    lzfse_fork.extend(8u32.to_le_bytes());
    lzfse_fork.extend((8 + lzfse.len() as u32).to_le_bytes());
    lzfse_fork.extend(&lzfse);

    let mut s = Synthetic::new(64);
    let size = elf.len() as u64;
    s.compressed(2, "type1.elf", 1, size, &elf, &[]);
    s.compressed(2, "type3.elf", 3, size, &zlib, &[]);
    let mut stored = vec![0xff];
    stored.extend(&elf);
    s.compressed(2, "type3-stored.elf", 3, size, &stored, &[]);
    s.compressed(2, "type4.elf", 4, two_chunks.len() as u64, &[], &zlib_fork);
    s.compressed(2, "type11.elf", 11, size, &lzfse, &[]);
    s.compressed(2, "type12.elf", 12, size, &[], &lzfse_fork);
    let image = s.build();
    let c = parse(&image);
    for (label, transform, data) in [
        ("/type1.elf", "decmpfs attribute data", &elf),
        ("/type3.elf", "decmpfs zlib", &elf),
        ("/type3-stored.elf", "decmpfs zlib", &elf),
        ("/type4.elf", "decmpfs zlib", &two_chunks),
        ("/type11.elf", "decmpfs LZFSE", &elf),
        ("/type12.elf", "decmpfs LZFSE", &elf),
    ] {
        let member = child(&c, label);
        assert_eq!(member.transform, Some(transform), "{label}");
        assert_eq!(&member.data[..], &data[..], "{label}");
    }
    assert!(has_note(
        &c,
        "6 decmpfs-compressed files were decoded for examination (LZFSE: 2, stored: 1, zlib: 3)"
    ));
    let p = classify(&image);
    assert!(p.slices.iter().all(|s| s.isa == Isa::X86_64));
    assert_eq!(
        p.slices
            .iter()
            .find(|s| s.label.as_deref() == Some("/type4.elf"))
            .unwrap()
            .decoded
            .as_ref()
            .unwrap()
            .size,
        two_chunks.len() as u64
    );
}

#[test]
fn unsupported_or_damaged_decmpfs_files_are_counted_or_noted() {
    let elf = payload_elf();
    let mut s = Synthetic::new(64);
    let size = elf.len() as u64;
    // LZBITMAP (13) and a dataless file (0x80000001) are not implemented.
    s.compressed(2, "lzbitmap.elf", 13, size, &elf, &[]);
    s.compressed(2, "dataless.elf", 0x8000_0001, size, &[], &[]);
    // Type 1 whose attribute holds less than the stated size.
    s.compressed(2, "short.elf", 1, size + 1, &elf, &[]);
    // A type 8 offset table that does not match the size's chunk count.
    let mut table = Vec::new();
    for offset in [12u32, 14, 16] {
        table.extend(offset.to_le_bytes());
    }
    table.extend(b"\x06a\x06b");
    s.compressed(2, "table.elf", 8, size, &[], &table);
    let image = s.build();
    let c = parse(&image);
    assert_eq!(labels(&c), Vec::<String>::new());
    assert!(has_note(
        &c,
        "1 file uses decmpfs compression type 13, which is not implemented"
    ));
    assert!(has_note(
        &c,
        "1 file uses decmpfs compression type 2147483649, which is not implemented"
    ));
    assert!(has_note(
        &c,
        "Skipped /short.elf: Invalid decmpfs data: 256 B decoded, 257 B expected"
    ));
    assert!(has_note(
        &c,
        "Skipped /table.elf: Invalid decmpfs chunk table: 12 B, 8 B expected"
    ));
}

#[test]
fn catalogs_with_index_nodes_are_searched_and_damage_is_noted() {
    let mut s = Synthetic::new(64);
    s.records_per_leaf = 3;
    let folders: Vec<u32> = (0..6).map(|i| s.folder(2, &format!("dir{i}"))).collect();
    for (i, &folder) in folders.iter().enumerate() {
        s.file(folder, &format!("payload{i}.elf"), &payload_elf());
    }
    let image = s.build();
    let c = parse(&image);
    assert_eq!(c.children.len(), 6);
    assert!(has_note(&c, "depth 2"));

    // A leaf whose fLink leads back to an earlier leaf: the root's
    // children span the first leaves, so the walk meets the cycle there.
    let mut cycle = image.clone();
    put32(&mut cycle, catalog_node(2), 1);
    let c = parse(&cycle);
    assert!(c
        .notes
        .iter()
        .any(|n| n.contains("Invalid catalog B-tree: the leaf chain returns to node 1")));

    // A leaf with the wrong height under the index root: every search
    // fails, the root's thread record included.
    let mut height = image.clone();
    height[catalog_node(1) + 9] = 2;
    assert!(parse_error(&height).contains("Invalid catalog B-tree node 1: kind -1 height 2"));

    // Record offsets out of order in one leaf: the folders whose records
    // it holds are skipped with a note, the others are walked.
    let mut offsets = image;
    let leaf = catalog_node(4);
    put16(&mut offsets, leaf + NODE - 4, 13);
    let c = parse(&offsets);
    assert!(c
        .notes
        .iter()
        .any(|n| n.contains("Invalid catalog B-tree node 4: record offsets out of order")));
    assert!(!c.children.is_empty());
}

#[test]
fn catalog_nodes_past_the_end_of_the_input_are_skipped_and_counted() {
    // Six folders of one ELF each, three records per leaf: leaf 5 holds
    // the thread and file of dir2 (CNID 18) and the thread of dir3, and
    // the index root (node 10) leads both searches to it.
    let mut s = Synthetic::new(65);
    s.records_per_leaf = 3;
    let folders: Vec<u32> = (0..6).map(|i| s.folder(2, &format!("dir{i}"))).collect();
    for (i, &folder) in folders.iter().enumerate() {
        s.file(folder, &format!("payload{i}.elf"), &payload_elf());
    }
    let mut image = s.build();
    // Move node 5 to the last block, 64: the catalog fork becomes the
    // extents (2, 5), (64, 1) and (8, 10), 16 blocks in all.
    let last = 64 * BLOCK;
    let node = catalog_node(5);
    image.copy_within(node..node + NODE, last);
    image[node..node + NODE].fill(0);
    let fork = VOLUME_HEADER + 272;
    for (i, (start, count)) in [(2u32, 5u32), (64, 1), (8, 10)].into_iter().enumerate() {
        put32(&mut image, fork + 16 + 8 * i, start);
        put32(&mut image, fork + 20 + 8 * i, count);
    }
    let whole = parse(&image);
    assert_eq!(whole.children.len(), 6, "the moved node is read");

    let c = parse(&image[..last]);
    assert_eq!(
        labels(&c),
        [
            "/dir0/payload0.elf",
            "/dir1/payload1.elf",
            "/dir4/payload4.elf",
            "/dir5/payload5.elf"
        ]
    );
    assert_members_inside("relocated catalog", &whole, &c, last);
    assert!(
        has_note(
            &c,
            "1 node of the catalog B-tree that the walk needed lies past the 256 KiB present; \
             its records were not read"
        ),
        "{:?}",
        c.notes
    );
    // Missing nodes are not damage: no problem is noted.
    assert!(
        !c.notes.iter().any(|n| n.starts_with("Skipped")),
        "{:?}",
        c.notes
    );
}

#[test]
fn folders_deeper_than_the_walk_limit_are_counted() {
    let mut s = Synthetic::new(64);
    let mut parent = 2;
    for depth in 0..70 {
        parent = s.folder(parent, &format!("d{depth}"));
    }
    s.file(parent, "payload.elf", &payload_elf());
    s.file(2, "top.elf", &payload_elf());
    let image = s.build();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/top.elf"]);
    assert!(
        has_note(&c, "1 folder deeper than 64 levels was not walked"),
        "{:?}",
        c.notes
    );
}

#[test]
fn volume_attribute_bits_are_noted() {
    // `attributes` at 4: clear kHFSVolumeUnmountedBit (0x100), set
    // kHFSVolumeInconsistentBit (0x4000) and kHFSContentProtectionBit
    // (0x40000000).
    let mut image = Synthetic::new(32).build();
    put32(&mut image, VOLUME_HEADER + 4, 0x4000_4000);
    let c = parse(&image);
    assert!(has_note(
        &c,
        "The volume was not unmounted cleanly (kHFSVolumeUnmountedBit clear)"
    ));
    assert!(has_note(
        &c,
        "The volume header marks the volume inconsistent"
    ));
    assert!(has_note(
        &c,
        "Content protection (kHFSContentProtectionBit): file contents may be encrypted"
    ));
    assert!(c.children.is_empty());
}

// ---------------------------------------------------------------------------
// Truncation and mutation sweeps
// ---------------------------------------------------------------------------

/// The error of a prefix of `end` bytes of a volume of `blocks` blocks of
/// `block_size` that lacks the structures a truncated volume is read from:
/// the volume header, or the B-tree header nodes and the root folder.
fn prefix_error(end: usize, blocks: usize, block_size: &str, size: usize) -> String {
    if end < VOLUME_HEADER + 512 {
        "HFS+ volume parse error: Truncated volume at 0x400 + 512 B".to_string()
    } else {
        format!(
            "HFS+ volume parse error: Truncated volume: {blocks} blocks of {block_size} need \
             {size} B, {end} B present"
        )
    }
}

#[test]
fn prefixes_are_truncated_volumes_that_list_only_members_inside_them() {
    for (name, image, blocks, block_size) in [
        ("hfsx.img", hfsx_img(), 1024, "512 B"),
        ("hfsplus.img", hfsplus_img(), 256, "4 KiB"),
    ] {
        let whole = parse(&image);
        let layout = hfsplus::detect(&image).expect("detected");
        // Every prefix up to the end of the catalog file, then a sample.
        let catalog = special_file(&image, CATALOG_FILE);
        let catalog_end = catalog.offset + catalog.size;
        let mut first_volume = None;
        for end in prefix_ends(image.len(), catalog_end, 61, 512) {
            let prefix = &image[..end];
            match hfsplus::parse_container(prefix, layout) {
                Ok(c) => {
                    first_volume.get_or_insert(end);
                    assert_members_inside(name, &whole, &c, end);
                    assert!(has_note(&c, "Volume truncated: "), "{name}: prefix {end}");
                }
                Err(e) => {
                    assert!(
                        first_volume.is_none(),
                        "{name}: prefix {end} after a volume"
                    );
                    assert_eq!(
                        e.to_string(),
                        prefix_error(end, blocks, block_size, image.len()),
                        "{name}"
                    );
                }
            }
        }
        // The first prefix read holds the catalog's header node and the
        // nodes of the root folder.
        let first = first_volume.expect("some prefix is read");
        assert!(
            first > catalog.offset + NODE && first <= catalog_end,
            "{name}: first {first:X}"
        );
        for end in (0..image.len()).step_by(65_537) {
            let prefix = &image[..end];
            if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
                for slice in &p.slices {
                    assert!(
                        slice.offset + slice.size <= end as u64,
                        "{name}: prefix {end}"
                    );
                }
            }
        }
    }
}

/// Parse `image` with `at` replaced by each of 0x00, 0xFF and the byte with
/// its low bit flipped; it must not panic.
fn mutate(image: &[u8], at: usize) {
    let original = image[at];
    for value in [0x00, 0xff, original ^ 0x01] {
        let mut copy = image.to_vec();
        copy[at] = value;
        if let Some(layout) = hfsplus::detect(&copy) {
            let _ = hfsplus::parse_container(&copy, layout);
        }
    }
}

#[test]
fn byte_mutations_of_the_metadata_never_panic() {
    for image in [hfsplus_img(), hfsx_img()] {
        for at in VOLUME_HEADER..VOLUME_HEADER + 512 {
            mutate(&image, at);
        }
        for fork in [EXTENTS_FILE, CATALOG_FILE, ATTRIBUTES_FILE] {
            let run = special_file(&image, fork);
            let node_size = usize::from(be16(&image, run.offset + 14 + 18));
            // Every byte of the header node's descriptor and header record,
            // and every third byte of the used nodes.
            for at in run.offset..run.offset + 120 {
                mutate(&image, at);
            }
            for node in (run.offset..run.offset + run.size).step_by(node_size) {
                if image[node..node + node_size].iter().all(|&b| b == 0) {
                    continue;
                }
                for at in (node..node + node_size).step_by(3) {
                    mutate(&image, at);
                }
            }
        }
    }
}

#[test]
fn byte_mutations_of_the_whole_image_never_panic_the_classifier() {
    let image = hfsplus_img();
    for at in (0..image.len()).step_by(997) {
        let mut copy = image.clone();
        copy[at] ^= 0xff;
        let _ = detect_payload(&copy, &ClassifierOptions::new());
    }
    // The stored bytes of the decoded and reassembled members.
    let c = parse(&image);
    let stored: Vec<Run> = c
        .children
        .iter()
        .filter(|m| matches!(m.data, Cow::Owned(_)))
        .map(|m| Run {
            offset: m.offset,
            size: m.stored_size,
        })
        .collect();
    for run in stored {
        for at in (run.offset..run.offset + run.size).step_by(7) {
            mutate(&image, at);
        }
    }
}

// ---------------------------------------------------------------------------
// A local disk image (not committed)
// ---------------------------------------------------------------------------

/// `MAX_PAYLOAD`: the DMG family decodes at most 64 MiB of a partition.
const EXTRACTION_LIMIT: usize = 64 << 20;

#[test]
fn a_local_dmg_lists_the_files_in_the_first_64_mib_of_its_cut_volume() {
    // Real disk images cannot be committed; point ZRAX_LOCAL_DMG at one
    // whose HFS+ partition is larger than 64 MiB (for example a downloaded
    // "Additional Tools for Xcode" image) to run this test.
    let Some(path) = std::env::var_os("ZRAX_LOCAL_DMG") else {
        eprintln!("ZRAX_LOCAL_DMG is not set; skipped");
        return;
    };
    let data = std::fs::read(&path).expect("ZRAX_LOCAL_DMG is readable");
    let layout = dmg::detect(&data).expect("an Apple disk image");
    let image = dmg::parse_container(&data, layout).expect("the disk image parses");
    let partition = image
        .children
        .iter()
        .find(|child| child.label == "Apple_HFS")
        .expect("an Apple_HFS partition");
    let volume = &partition.data[..];
    assert_eq!(volume.len(), EXTRACTION_LIMIT, "the partition is cut");
    let c = parse(volume);
    assert!(
        has_note(&c, "Volume truncated: 64 MiB of "),
        "{:?}",
        c.notes
    );
    let mut mach_o = 0;
    for member in &c.children {
        assert!(
            member.offset + member.stored_size <= volume.len(),
            "{}",
            member.label
        );
        let format = classify(&member.data).format.format;
        mach_o += usize::from(matches!(format, FileFormat::MachO | FileFormat::MachOFat));
        eprintln!("{} ({} B): {format:?}", member.label, member.data.len());
    }
    assert!(mach_o > 0, "no Mach-O file is listed: {:?}", c.notes);
    // The disk image takes its primary ISA from the volume's files.
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::AppleDmg);
    assert!(!matches!(p.primary.isa, Isa::Unknown(_)), "{:?}", p.primary);
    eprintln!("{} members; notes: {:#?}", c.children.len(), c.notes);
}
