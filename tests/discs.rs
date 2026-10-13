//! Console disc images: synthetic GameCube, Wii and XDVDFS images built from
//! the documented layouts (YAGCD chapter 13, Dolphin `DiscIO`, extract-xiso,
//! xdvdfs), covering the GameCube apploader, boot DOL and FST members, opaque
//! Wii partitions, XDVDFS trees at every documented game partition offset,
//! corrupted structures, and truncation and mutation sweeps.

use zrax::formats::container::{self, Child, Classify, Container, Kind};
use zrax::formats::discs::{Layout, XdvdfsImage};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The synthetic x86-64 ELF header of the compressed-stream fixtures.
fn elf() -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/compressed/payload.elf")).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    container::parse(data, Kind::Discs(layout)).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    container::parse(data, Kind::Discs(layout))
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

fn payload_has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
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

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_le16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn u32_of(value: usize) -> u32 {
    u32::try_from(value).expect("fixture value fits in u32")
}

/// `x(n+1) = (x(n) * 1103515245 + 12345) mod 2^31`; each byte is bits
/// 16-23 of `x(n+1)`.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = (x * 1_103_515_245 + 12345) % 2_147_483_648;
            u8::try_from((x >> 16) & 0xff).unwrap()
        })
        .collect()
}

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

/// Mutation values for a byte: zero, erased and one bit flipped.
fn mutations(byte: u8) -> [u8; 3] {
    [0x00, 0xff, byte ^ 0x01]
}

// ---------------------------------------------------------------------------
// GameCube (YAGCD chapter 13; Dolphin DiscUtils, VolumeGC, FileSystemGCWii)
// ---------------------------------------------------------------------------

/// Disc magics: GameCube at 0x1C, Wii at 0x18.
const GAMECUBE_MAGIC: u32 = 0xC233_9F3D;
const WII_MAGIC: u32 = 0x5D1C_9EA3;

/// File offsets of the GameCube fixture's parts.
const APPLOADER: usize = 0x2440;
const APPLOADER_CODE: usize = APPLOADER + 0x20;
const APPLOADER_CODE_SIZE: usize = 0x100;
const APPLOADER_TRAILER_SIZE: usize = 0x20;
const BOOT_DOL: usize = 0x3000;
const BOOT_DOL_TEXT: usize = 0x200;
const FST: usize = 0x4000;
const OPENING_BNR: usize = 0x5000;
const PAYLOAD_ELF: usize = 0x6000;
const EXTRA_DOL: usize = 0x7000;
const EXTRA_DOL_TEXT: usize = 0x80;
const GAMECUBE_SIZE: usize = 0x7400;

/// The disc header GameCube and Wii share (YAGCD 13.1): game code and
/// maker code (6 B) at 0, disc number 0 at 6, version 1 at 7, the title at
/// 0x20.
fn disc_header(game_id: &[u8; 6], title: &str) -> Vec<u8> {
    let mut header = vec![0u8; 0x440];
    header[..6].copy_from_slice(game_id);
    header[6] = 0;
    header[7] = 1;
    header[0x20..0x20 + title.len()].copy_from_slice(title.as_bytes());
    header
}

/// A DOL (Dolphin `DolReader.h`): text section 0 at file 0x100 with
/// `text_size` bytes of PowerPC code loaded at 0x80003100, data section 0
/// right after it (0x40 B at 0x80100000), bss 0x100 B at 0x80200000 and
/// the entry point at the start of the text.
fn dol(text_size: usize) -> Vec<u8> {
    let mut dol = vec![0u8; 0x100];
    // Section offsets: text 0 at 0x00, data 0 at 0x1C.
    put_be32(&mut dol, 0x00, 0x100);
    put_be32(&mut dol, 0x1C, u32_of(0x100 + text_size));
    // Section addresses: text 0 at 0x48, data 0 at 0x64.
    put_be32(&mut dol, 0x48, 0x8000_3100);
    put_be32(&mut dol, 0x64, 0x8010_0000);
    // Section sizes: text 0 at 0x90, data 0 at 0xAC.
    put_be32(&mut dol, 0x90, u32_of(text_size));
    put_be32(&mut dol, 0xAC, 0x40);
    // bss address and size, entry point.
    put_be32(&mut dol, 0xD8, 0x8020_0000);
    put_be32(&mut dol, 0xDC, 0x100);
    put_be32(&mut dol, 0xE0, 0x8000_3100);
    dol.extend(ppc_code(text_size));
    dol.extend([0x5a; 0x40]);
    dol
}

/// One FST entry for [`fst`]: a directory flag, the name, the file offset
/// or parent index, and the size or next index.
struct FstEntry {
    directory: bool,
    name: String,
    offset_or_parent: u32,
    size_or_next: u32,
}

fn fst_file(name: &str, offset: usize, size: usize) -> FstEntry {
    FstEntry {
        directory: false,
        name: name.into(),
        offset_or_parent: u32_of(offset),
        size_or_next: u32_of(size),
    }
}

fn fst_directory(name: &str, parent: usize, next: usize) -> FstEntry {
    FstEntry {
        directory: true,
        name: name.into(),
        offset_or_parent: u32_of(parent),
        size_or_next: u32_of(next),
    }
}

/// `depth` directories, each the parent of the next and all ending with
/// the last entry, then `payload.elf` in the innermost one.
fn nested_entries(depth: usize) -> Vec<FstEntry> {
    let count = depth + 2;
    let mut entries = vec![fst_directory("", 0, count)];
    for i in 0..depth {
        entries.push(fst_directory(&format!("d{i}"), i, count));
    }
    entries.push(fst_file("payload.elf", PAYLOAD_ELF, 256));
    entries
}

/// An FST (YAGCD 13.4): 12-byte entries, each a flags byte (1 for a
/// directory) and a 24-bit name offset, the offset or parent index, and the
/// size or next index; then the string table, which starts with the
/// root's empty name.
fn fst(entries: &[FstEntry]) -> Vec<u8> {
    let mut names = vec![0u8];
    let mut table = Vec::new();
    for entry in entries {
        let name_offset = if entry.name.is_empty() {
            0
        } else {
            let at = names.len();
            names.extend_from_slice(entry.name.as_bytes());
            names.push(0);
            u32_of(at)
        };
        let flags = if entry.directory { 1u32 << 24 } else { 0 };
        table.extend_from_slice(&(flags | name_offset).to_be_bytes());
        table.extend_from_slice(&entry.offset_or_parent.to_be_bytes());
        table.extend_from_slice(&entry.size_or_next.to_be_bytes());
    }
    table.extend(names);
    table
}

/// The fixture tree: the root (6 entries); `opening.bnr` (0x40 B of 0x11);
/// the directory `bin` (parent 0, next 5) holding `payload.elf` (the ELF
/// fixture) and `extra.dol` (a second DOL); `empty.bin` (0 B).
fn gamecube_entries() -> Vec<FstEntry> {
    vec![
        fst_directory("", 0, 6),
        fst_file("opening.bnr", OPENING_BNR, 0x40),
        fst_directory("bin", 0, 5),
        fst_file("payload.elf", PAYLOAD_ELF, 256),
        fst_file("extra.dol", EXTRA_DOL, 0x100 + EXTRA_DOL_TEXT + 0x40),
        fst_file("empty.bin", 0, 0),
    ]
}

/// A GameCube image: disc header `GZRE01` with the magic at 0x1C, the boot
/// DOL offset (0x420), FST offset (0x424), FST size and maximum size
/// (0x428, 0x42C); `bi2.bin` country code 1 at 0x458; the apploader header
/// at 0x2440 (date, entry 0x81200000, code and trailer sizes) and its
/// PowerPC code; the boot DOL at 0x3000; the FST at 0x4000 (or after the
/// file data when it does not fit before them); the file data.
fn gamecube_image_with(entries: &[FstEntry]) -> Vec<u8> {
    let table = fst(entries);
    let fst_offset = if table.len() <= OPENING_BNR - FST {
        FST
    } else {
        GAMECUBE_SIZE
    };
    let mut image = vec![0u8; GAMECUBE_SIZE.max(fst_offset + table.len())];
    image[..0x440].copy_from_slice(&disc_header(b"GZRE01", "ZRAX SYNTHETIC DISC"));
    put_be32(&mut image, 0x1C, GAMECUBE_MAGIC);
    put_be32(&mut image, 0x420, u32_of(BOOT_DOL));
    put_be32(&mut image, 0x424, u32_of(fst_offset));
    put_be32(&mut image, 0x428, u32_of(table.len()));
    put_be32(&mut image, 0x42C, u32_of(table.len()));
    put_be32(&mut image, 0x458, 1);
    image[APPLOADER..APPLOADER + 10].copy_from_slice(b"2026/10/13");
    put_be32(&mut image, APPLOADER + 0x10, 0x8120_0000);
    put_be32(&mut image, APPLOADER + 0x14, u32_of(APPLOADER_CODE_SIZE));
    put_be32(&mut image, APPLOADER + 0x18, u32_of(APPLOADER_TRAILER_SIZE));
    let apploader = ppc_code(APPLOADER_CODE_SIZE + APPLOADER_TRAILER_SIZE);
    image[APPLOADER_CODE..APPLOADER_CODE + apploader.len()].copy_from_slice(&apploader);
    let boot = dol(BOOT_DOL_TEXT);
    image[BOOT_DOL..BOOT_DOL + boot.len()].copy_from_slice(&boot);
    image[fst_offset..fst_offset + table.len()].copy_from_slice(&table);
    image[OPENING_BNR..OPENING_BNR + 0x40].fill(0x11);
    let elf = elf();
    image[PAYLOAD_ELF..PAYLOAD_ELF + elf.len()].copy_from_slice(&elf);
    let extra = dol(EXTRA_DOL_TEXT);
    image[EXTRA_DOL..EXTRA_DOL + extra.len()].copy_from_slice(&extra);
    image
}

fn gamecube_image() -> Vec<u8> {
    gamecube_image_with(&gamecube_entries())
}

/// Length of the fixture FST.
fn gamecube_fst_len() -> usize {
    fst(&gamecube_entries()).len()
}

#[test]
fn gamecube_image_lists_boot_dol_apploader_and_recognized_fst_files() {
    let image = gamecube_image();
    let c = parse(&image, Layout::GameCube);
    assert_eq!(c.format, FileFormat::GameCubeDisc);
    assert_eq!(c.variant, "GameCube disc image");
    assert_eq!(c.target, None);
    assert_eq!(
        labels(&c),
        [
            "Main executable (DOL)",
            "Apploader",
            "/bin/payload.elf",
            "/bin/extra.dol"
        ]
    );
    let apploader = child(&c, "Apploader");
    assert_eq!(apploader.offset, APPLOADER_CODE);
    assert_eq!(
        apploader.stored_size,
        APPLOADER_CODE_SIZE + APPLOADER_TRAILER_SIZE
    );
    assert_eq!(apploader.classify, Classify::Code);
    let target = apploader.target.expect("the apploader runs on the PowerPC");
    assert_eq!(target.isa, Isa::Ppc);
    assert_eq!(target.endianness, Some(Endianness::Big));
    let boot = child(&c, "Main executable (DOL)");
    assert_eq!(boot.offset, BOOT_DOL);
    assert_eq!(boot.stored_size, 0x100 + BOOT_DOL_TEXT + 0x40);
    assert_eq!(boot.classify, Classify::Always);
    assert_eq!(boot.target, None);
    let member = child(&c, "/bin/payload.elf");
    assert_eq!(member.offset, PAYLOAD_ELF);
    assert_eq!(member.data.as_ref(), elf().as_slice());
    assert_eq!(member.classify, Classify::IfRecognized);
    assert_eq!(child(&c, "/bin/extra.dol").offset, EXTRA_DOL);
    assert!(c.children.iter().all(|child| !child.opaque));
}

#[test]
fn gamecube_classification_takes_each_child_from_its_own_bytes() {
    let image = gamecube_image();
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::GameCubeDisc);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("GameCube disc image")
    );
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(
        slice_labels(&p),
        [
            "Main executable (DOL)",
            "Apploader",
            "/bin/payload.elf",
            "/bin/extra.dol"
        ]
    );
    let isas: Vec<Isa> = p.slices.iter().map(|s| s.isa).collect();
    assert_eq!(isas, [Isa::Ppc, Isa::Ppc, Isa::X86_64, Isa::Ppc]);
    let offsets: Vec<u64> = p.slices.iter().map(|s| s.offset).collect();
    assert_eq!(
        offsets,
        [BOOT_DOL, APPLOADER_CODE, PAYLOAD_ELF, EXTRA_DOL].map(|o| o as u64)
    );
    assert!(payload_has_note(
        &p,
        "Main executable (DOL): ppc (contained DOL)"
    ));
    assert!(payload_has_note(
        &p,
        "Primary ISA selected from Main executable (DOL)"
    ));
}

#[test]
fn gamecube_header_apploader_and_fst_are_reported() {
    let image = gamecube_image();
    let c = parse(&image, Layout::GameCube);
    assert!(has_note(
        &c,
        "Game ID GZRE01; disc 1; version 1; title \"ZRAX SYNTHETIC DISC\""
    ));
    assert!(has_note(&c, "Region code 1 (NTSC-U)"));
    assert!(has_note(
        &c,
        "Apploader 2026/10/13: entry 0x81200000; 256 B of code and 32 B of trailer loaded at 0x81200000"
    ));
    assert!(has_note(
        &c,
        "Main executable: 832 B DOL at 0x3000; entry 0x80003100"
    ));
    assert!(has_note(&c, "FST at 0x4000:"));
    assert!(has_note(&c, "6 entries, 1 directory"));
    assert!(has_note(&c, "4 files; 2 in a recognized format listed"));
    let p = classify(&image);
    assert_eq!(metadata(&p, "gamecube_game_id").to_string(), "GZRE01");
    assert_eq!(
        metadata(&p, "gamecube_title").to_string(),
        "ZRAX SYNTHETIC DISC"
    );
    assert_eq!(metadata(&p, "gamecube_region").to_string(), "1");
    assert_eq!(
        metadata(&p, "gamecube_apploader_date").to_string(),
        "2026/10/13"
    );
    assert_eq!(metadata(&p, "gamecube_dol_offset").to_string(), "12288");
    assert_eq!(metadata(&p, "gamecube_fst_offset").to_string(), "16384");
    assert_eq!(metadata(&p, "gamecube_files").to_string(), "4");
    assert_eq!(
        metadata(&p, "gamecube_image_size").to_string(),
        GAMECUBE_SIZE.to_string()
    );
}

#[test]
fn gamecube_detection_needs_the_magic_at_0x1c() {
    let image = gamecube_image();
    assert_eq!(zrax::formats::discs::detect(&image), Some(Layout::GameCube));
    let mut moved = image.clone();
    put_be32(&mut moved, 0x1C, 0);
    put_be32(&mut moved, 0x20, GAMECUBE_MAGIC);
    assert_eq!(zrax::formats::discs::detect(&moved), None);
    assert!(parse_error(&moved, Layout::GameCube).contains("Invalid GameCube disc magic"));
    // A header alone is still a GameCube disc: truncation is a parse error.
    assert_eq!(
        zrax::formats::discs::detect(&image[..0x20]),
        Some(Layout::GameCube)
    );
    assert!(detect_payload(&image[..0x440], &ClassifierOptions::new()).is_err());
}

#[test]
fn gamecube_datel_disc_without_dol_offset_has_no_main_executable() {
    let mut image = gamecube_image();
    put_be32(&mut image, 0x420, 0);
    let c = parse(&image, Layout::GameCube);
    assert!(has_note(&c, "No main executable: the DOL offset is 0"));
    assert_eq!(
        labels(&c),
        ["Apploader", "/bin/payload.elf", "/bin/extra.dol"]
    );
}

#[test]
fn gamecube_disc_without_fst_lists_no_files() {
    let mut image = gamecube_image();
    put_be32(&mut image, 0x428, 0);
    let c = parse(&image, Layout::GameCube);
    assert!(has_note(&c, "No FST: its size is 0"));
    assert_eq!(labels(&c), ["Main executable (DOL)", "Apploader"]);
}

#[test]
fn gamecube_empty_apploader_is_not_a_child() {
    let mut image = gamecube_image();
    put_be32(&mut image, APPLOADER + 0x14, 0);
    put_be32(&mut image, APPLOADER + 0x18, 0);
    let c = parse(&image, Layout::GameCube);
    assert!(has_note(&c, "Apploader 2026/10/13 is empty"));
    assert_eq!(labels(&c)[0], "Main executable (DOL)");
}

#[test]
fn gamecube_files_outside_a_truncated_image_are_counted() {
    let image = gamecube_image();
    let truncated = &image[..EXTRA_DOL + 0x10];
    let c = parse(truncated, Layout::GameCube);
    assert_eq!(
        labels(&c),
        ["Main executable (DOL)", "Apploader", "/bin/payload.elf"]
    );
    assert!(has_note(
        &c,
        "Not listed: 1 file outside the image; first: /bin/extra.dol at 0x7000 + 448 B"
    ));
}

#[test]
fn gamecube_header_and_apploader_corruptions_are_parse_errors() {
    let image = gamecube_image();
    let cases: [(&str, usize, u32); 6] = [
        ("Invalid apploader header", APPLOADER + 0x10, u32::MAX),
        ("Truncated apploader at 0x2460", APPLOADER + 0x14, 0x10_0000),
        ("Invalid apploader size", APPLOADER + 0x14, 0x7000_0000),
        ("Truncated main executable header at 0x7380", 0x420, 0x7380),
        (
            "Truncated main executable at 0x3000",
            BOOT_DOL + 0x90,
            0x10_0000,
        ),
        ("Invalid FST size 4 B", 0x428, 4),
    ];
    for (expected, at, value) in cases {
        let mut corrupt = image.clone();
        put_be32(&mut corrupt, at, value);
        let message = parse_error(&corrupt, Layout::GameCube);
        assert!(message.contains(expected), "{expected}: {message}");
        assert!(
            message.starts_with("Console disc parse error: "),
            "{message}"
        );
    }
    let mut empty_dol = image.clone();
    empty_dol[BOOT_DOL..BOOT_DOL + 0x100].fill(0);
    assert!(parse_error(&empty_dol, Layout::GameCube).contains("every DOL section is empty"));
    assert!(
        parse_error(&image[..0x2450], Layout::GameCube).contains("Truncated GameCube system area")
    );
    assert!(parse_error(&image[..0x100], Layout::GameCube).contains("Truncated disc header"));
}

#[test]
fn gamecube_fst_corruptions_are_parse_errors() {
    let len = gamecube_fst_len();
    let cases: [(&str, Vec<FstEntry>); 4] = [
        (
            "Invalid FST entry 3: parent index 0 instead of 2",
            vec![
                fst_directory("", 0, 5),
                fst_file("opening.bnr", OPENING_BNR, 0x40),
                fst_directory("bin", 0, 5),
                fst_directory("lib", 0, 5),
                fst_file("payload.elf", PAYLOAD_ELF, 256),
            ],
        ),
        (
            "Invalid FST entry 2: next index 9 outside 3..=6",
            vec![
                fst_directory("", 0, 6),
                fst_file("opening.bnr", OPENING_BNR, 0x40),
                fst_directory("bin", 0, 9),
                fst_file("payload.elf", PAYLOAD_ELF, 256),
                fst_file("extra.dol", EXTRA_DOL, 0x1C0),
                fst_file("empty.bin", 0, 0),
            ],
        ),
        (
            "Invalid FST entry 2: next index 2 outside 3..=4",
            vec![
                fst_directory("", 0, 4),
                fst_file("opening.bnr", OPENING_BNR, 0x40),
                fst_directory("bin", 0, 2),
                fst_file("payload.elf", PAYLOAD_ELF, 256),
            ],
        ),
        (
            "Invalid FST: the root entry is not a directory",
            vec![fst_file("", 0, 1)],
        ),
    ];
    for (expected, entries) in cases {
        let image = gamecube_image_with(&entries);
        let message = parse_error(&image, Layout::GameCube);
        assert!(message.contains(expected), "{expected}: {message}");
    }
    let image = gamecube_image();
    let mut no_nul = image.clone();
    no_nul[FST + len - 1] = b'x';
    assert!(parse_error(&no_nul, Layout::GameCube).contains("does not end with a NUL byte"));
    let mut too_many = image.clone();
    put_be32(&mut too_many, FST + 8, 1000);
    assert!(parse_error(&too_many, Layout::GameCube).contains("Invalid FST entry count 1000"));
    let mut far_name = image.clone();
    put_be32(&mut far_name, FST + 12, 0x0000_0FFF);
    assert!(parse_error(&far_name, Layout::GameCube)
        .contains("Invalid FST entry 1: name offset 0xFFF outside"));
    let mut huge = image.clone();
    put_be32(&mut huge, 0x428, (128 << 20) + 1);
    assert!(parse_error(&huge, Layout::GameCube).contains("Invalid FST size"));
    let mut outside = image;
    put_be32(&mut outside, 0x424, u32_of(GAMECUBE_SIZE - 8));
    assert!(parse_error(&outside, Layout::GameCube).contains("Truncated FST at 0x73F8"));
}

#[test]
fn gamecube_deep_directories_are_not_walked() {
    let image = gamecube_image_with(&nested_entries(70));
    let c = parse(&image, Layout::GameCube);
    assert!(has_note(
        &c,
        "Not walked: 1 directory nested deeper than 64 levels"
    ));
    assert!(!labels(&c).iter().any(|l| l.ends_with("payload.elf")));
    assert!(has_note(&c, "1 file; 0 in a recognized format listed"));
}

#[test]
fn gamecube_fst_nesting_is_validated_up_to_a_limit() {
    let image = gamecube_image_with(&nested_entries(1024));
    assert!(container::parse(&image, Kind::Discs(Layout::GameCube)).is_ok());
    let image = gamecube_image_with(&nested_entries(1025));
    assert!(parse_error(&image, Layout::GameCube)
        .contains("Unsupported FST: directories nested deeper than 1024 levels at entry 1025"));
}

#[test]
fn gamecube_fst_names_must_start_inside_the_string_table() {
    let image = gamecube_image();
    let names = 6 * 12;
    let names_len = gamecube_fst_len() - names;
    let mut at_end = image.clone();
    put_be32(&mut at_end, FST + 12, u32_of(names_len));
    assert!(parse_error(&at_end, Layout::GameCube).contains("Invalid FST entry 1: name offset"));
    let mut last = image;
    put_be32(&mut last, FST + 12, u32_of(names_len - 1));
    let c = parse(&last, Layout::GameCube);
    assert!(has_note(&c, "4 files"));
}

#[test]
fn gamecube_root_must_be_its_own_parent() {
    let mut image = gamecube_image();
    put_be32(&mut image, FST + 4, 3);
    assert!(parse_error(&image, Layout::GameCube)
        .contains("Invalid FST root: parent index 3 instead of 0"));
}

#[test]
fn gamecube_truncations_error_or_leave_out_what_is_missing() {
    let image = gamecube_image();
    let fst_end = FST + gamecube_fst_len();
    for end in 0..image.len() {
        let prefix = &image[..end];
        match container::parse(prefix, Kind::Discs(Layout::GameCube)) {
            Ok(c) => {
                assert!(end >= fst_end, "prefix {end} parsed");
                assert!(c
                    .children
                    .iter()
                    .all(|child| child.offset + child.stored_size <= end));
            }
            Err(_) => assert!(end < fst_end, "prefix {end} failed"),
        }
    }
}

#[test]
fn gamecube_mutations_never_panic() {
    let image = gamecube_image();
    let options = ClassifierOptions::new();
    let fst_end = FST + gamecube_fst_len();
    let is_structure = |i: usize| {
        i < 0x460
            || (APPLOADER..APPLOADER + 0x20).contains(&i)
            || (BOOT_DOL..BOOT_DOL + 0x100).contains(&i)
            || (FST..fst_end).contains(&i)
    };
    for i in (0..image.len()).filter(|&i| is_structure(i) || i % 61 == 0) {
        for value in mutations(image[i]) {
            let mut mutated = image.clone();
            mutated[i] = value;
            if let Ok(c) = container::parse(&mutated, Kind::Discs(Layout::GameCube)) {
                assert!(c
                    .children
                    .iter()
                    .filter(|child| child.label == "Apploader")
                    .all(|child| child.target.is_some_and(|t| t.isa == Isa::Ppc)));
            }
            if i % 97 == 0 {
                let _ = detect_payload(&mutated, &options);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Wii (Dolphin VolumeWii, DiscUtils, VolumeVerifier)
// ---------------------------------------------------------------------------

/// Partition offsets and sizes of the Wii fixture.
const UPDATE_PARTITION: usize = 0x50000;
const UPDATE_DATA_OFFSET: usize = 0x1000;
const UPDATE_DATA_SIZE: usize = 0x1000;
const DATA_PARTITION: usize = 0x58000;
const DATA_DATA_OFFSET: usize = 0x2000;
const DATA_DATA_SIZE: usize = 0x6000;
const WII_SIZE: usize = 0x60000;

/// A partition header at `offset`: a zero ticket and TMD fields, then the
/// data offset (>> 2) at 0x2B8 and the data size (>> 2) at 0x2BC.
fn put_partition_header(image: &mut [u8], offset: usize, data_offset: usize, data_size: usize) {
    put_be32(image, offset + 0x2B8, u32_of(data_offset >> 2));
    put_be32(image, offset + 0x2BC, u32_of(data_size >> 2));
}

/// A Wii image: disc header `RZRP01` with the magic at 0x18; partition
/// group 0 with two partitions in the table at 0x40020 (offsets >> 2 and
/// types: UPDATE at 0x50000, DATA at 0x58000); region 2 at 0x4E000; the two
/// partition headers; partition data of noise standing in for AES
/// ciphertext, with an ELF header at the start of the DATA partition's
/// data that must never be classified.
fn wii_image() -> Vec<u8> {
    let mut image = vec![0u8; WII_SIZE];
    image[..0x440].copy_from_slice(&disc_header(b"RZRP01", "ZRAX WII DISC"));
    put_be32(&mut image, 0x18, WII_MAGIC);
    put_be32(&mut image, 0x40000, 2);
    put_be32(&mut image, 0x40004, 0x40020 >> 2);
    put_be32(&mut image, 0x40020, u32_of(UPDATE_PARTITION >> 2));
    put_be32(&mut image, 0x40024, 1);
    put_be32(&mut image, 0x40028, u32_of(DATA_PARTITION >> 2));
    put_be32(&mut image, 0x4002C, 0);
    put_be32(&mut image, 0x4E000, 2);
    put_partition_header(
        &mut image,
        UPDATE_PARTITION,
        UPDATE_DATA_OFFSET,
        UPDATE_DATA_SIZE,
    );
    put_partition_header(&mut image, DATA_PARTITION, DATA_DATA_OFFSET, DATA_DATA_SIZE);
    let update_data = UPDATE_PARTITION + UPDATE_DATA_OFFSET;
    image[update_data..update_data + UPDATE_DATA_SIZE].copy_from_slice(&noise(3, UPDATE_DATA_SIZE));
    let data_data = DATA_PARTITION + DATA_DATA_OFFSET;
    image[data_data..data_data + DATA_DATA_SIZE].copy_from_slice(&noise(5, DATA_DATA_SIZE));
    let elf = elf();
    image[data_data..data_data + elf.len()].copy_from_slice(&elf);
    image
}

#[test]
fn wii_image_lists_partitions_as_opaque_children() {
    let image = wii_image();
    assert_eq!(zrax::formats::discs::detect(&image), Some(Layout::Wii));
    let c = parse(&image, Layout::Wii);
    assert_eq!(c.format, FileFormat::WiiDisc);
    assert_eq!(c.variant, "Wii disc image");
    assert_eq!(c.target, None);
    assert_eq!(
        labels(&c),
        ["Partition 0.0 (UPDATE)", "Partition 0.1 (DATA)"]
    );
    let update = child(&c, "Partition 0.0 (UPDATE)");
    assert_eq!(update.offset, UPDATE_PARTITION);
    assert_eq!(update.stored_size, UPDATE_DATA_OFFSET + UPDATE_DATA_SIZE);
    let data = child(&c, "Partition 0.1 (DATA)");
    assert_eq!(data.offset, DATA_PARTITION);
    assert_eq!(data.stored_size, DATA_DATA_OFFSET + DATA_DATA_SIZE);
    assert!(c.children.iter().all(|child| child.opaque));
    assert!(has_note(
        &c,
        "Game ID RZRP01; disc 1; version 1; title \"ZRAX WII DISC\""
    ));
    assert!(has_note(&c, "Region code 2 (PAL)"));
    assert!(has_note(
        &c,
        "Partition 0.1 (DATA) at 0x58000: data at 0x5A000, 24576 B"
    ));
    assert!(has_note(&c, "AES-encrypted"));
    assert!(has_note(&c, "not verified"));
}

#[test]
fn wii_partitions_never_reach_the_code_model() {
    let image = wii_image();
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::WiiDisc);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
    assert_eq!(
        slice_labels(&p),
        ["Partition 0.0 (UPDATE)", "Partition 0.1 (DATA)"]
    );
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
    assert!(p.slices.iter().all(|s| s.extensions.is_empty()));
    assert!(payload_has_note(
        &p,
        "Partition 0.1 (DATA): opaque; payload ISA analysis skipped"
    ));
    assert_eq!(metadata(&p, "wii_partitions").to_string(), "2");
    assert_eq!(metadata(&p, "wii_game_id").to_string(), "RZRP01");
}

#[test]
fn wii_partition_types_and_header_flags_are_named() {
    let mut image = wii_image();
    put_be32(&mut image, 0x40024, 2);
    put_be32(&mut image, 0x4002C, u32::from_be_bytes(*b"RSBJ"));
    image[0x61] = 1;
    image[0x60] = 1;
    let c = parse(&image, Layout::Wii);
    assert_eq!(
        labels(&c),
        ["Partition 0.0 (CHANNEL)", "Partition 0.1 (RSBJ)"]
    );
    assert!(has_note(&c, "disables partition encryption (0x61 = 0x01)"));
    assert!(has_note(&c, "disables hash verification (0x60 = 0x01)"));
    put_be32(&mut image, 0x4002C, 0xFF);
    assert_eq!(
        labels(&parse(&image, Layout::Wii))[1],
        "Partition 0.1 (255)"
    );
}

#[test]
fn wii_partition_groups_are_all_read() {
    let mut image = wii_image();
    // Move the DATA partition into group 2, as discs with many partitions do.
    put_be32(&mut image, 0x40000, 1);
    put_be32(&mut image, 0x40010, 1);
    put_be32(&mut image, 0x40014, 0x40028 >> 2);
    let c = parse(&image, Layout::Wii);
    assert_eq!(
        labels(&c),
        ["Partition 0.0 (UPDATE)", "Partition 2.0 (DATA)"]
    );
}

#[test]
fn wii_partition_table_corruptions_are_parse_errors() {
    let image = wii_image();
    let cases: [(&str, usize, u32); 5] = [
        ("Truncated partition table 0 at 0x40020", 0x40000, 0x10_0000),
        (
            "Invalid Partition 0.0 (UPDATE) offset 0x40000: inside the 0x50000 B disc header area",
            0x40020,
            0x40000 >> 2,
        ),
        (
            "Truncated Partition 0.1 (DATA) header at 0x5FF00",
            0x40028,
            0x5FF00 >> 2,
        ),
        (
            "Invalid Partition 0.0 (UPDATE) data offset 0x100: inside the partition header",
            UPDATE_PARTITION + 0x2B8,
            0x40,
        ),
        (
            "Truncated Partition 0.1 (DATA) at 0x58000: its data ends at 0x60004",
            DATA_PARTITION + 0x2BC,
            u32_of((DATA_DATA_SIZE + 4) >> 2),
        ),
    ];
    for (expected, at, value) in cases {
        let mut corrupt = image.clone();
        put_be32(&mut corrupt, at, value);
        let message = parse_error(&corrupt, Layout::Wii);
        assert!(message.contains(expected), "{expected}: {message}");
    }
    assert!(parse_error(&image[..0x40010], Layout::Wii)
        .contains("Truncated partition information at 0x40000"));
    assert!(
        parse_error(&image[..0x40030], Layout::Wii).contains("Truncated region data at 0x4E000")
    );
    let mut gamecube = image;
    put_be32(&mut gamecube, 0x18, 0);
    assert!(parse_error(&gamecube, Layout::Wii).contains("Invalid Wii disc magic"));
}

#[test]
fn wii_truncations_are_parse_errors() {
    let image = wii_image();
    let boundaries = [
        0x18, 0x1C, 0x440, 0x40020, 0x40030, 0x4E004, 0x502C0, 0x52000, 0x582C0,
    ];
    let ends = (0..image.len())
        .filter(|end| end % 251 == 0 || boundaries.iter().any(|b| end.abs_diff(*b) <= 1));
    for end in ends {
        assert!(
            container::parse(&image[..end], Kind::Discs(Layout::Wii)).is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn wii_mutations_never_panic_and_keep_partitions_opaque() {
    let image = wii_image();
    let options = ClassifierOptions::new();
    let is_structure = |i: usize| {
        i < 0x80
            || (0x40000..0x40030).contains(&i)
            || (0x4E000..0x4E004).contains(&i)
            || (UPDATE_PARTITION + 0x2B0..UPDATE_PARTITION + 0x2C0).contains(&i)
            || (DATA_PARTITION + 0x2B0..DATA_PARTITION + 0x2C0).contains(&i)
    };
    for i in (0..image.len()).filter(|&i| is_structure(i) || i % 509 == 0) {
        for value in mutations(image[i]) {
            let mut mutated = image.clone();
            mutated[i] = value;
            if let Ok(c) = container::parse(&mutated, Kind::Discs(Layout::Wii)) {
                assert!(c.children.iter().all(|child| child.opaque), "byte {i}");
            }
            if i % 97 == 0 {
                let _ = detect_payload(&mutated, &options);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// XDVDFS (extract-xiso, xdvdfs, xenia, XboxDevWiki)
// ---------------------------------------------------------------------------

const SECTOR: usize = 2048;

/// Sectors of the XDVDFS fixture, from the game partition start.
const ROOT_SECTOR: usize = 34;
const MEDIA_SECTOR: usize = 35;
const XBE_SECTOR: usize = 36;
const README_SECTOR: usize = 37;
const XEX_SECTOR: usize = 38;
const PARTITION_SECTORS: usize = 39;

const XBE_SIZE: usize = 0x200;
const XEX_SIZE: usize = 0x40;
const README: &[u8] = b"zrax xdvdfs fixture\n";

/// Directory entry attributes: archive file and directory.
const ATTRIBUTE_ARCHIVE: u8 = 0x20;
const ATTRIBUTE_DIRECTORY: u8 = 0x10;

/// One directory entry for [`dir_table`] (extract-xiso `traverse_xiso`):
/// left and right links in 4-byte units, start sector, size, attributes
/// and name.
struct Dirent {
    left: u16,
    right: u16,
    sector: usize,
    size: usize,
    attributes: u8,
    name: &'static str,
}

/// A directory table of one sector: each entry at its byte offset (a
/// multiple of 4) as links (2 + 2 B), sector (4), size (4), attributes,
/// name length and name; the rest 0xFF padding.
fn dir_table(entries: &[(usize, Dirent)]) -> Vec<u8> {
    let mut table = vec![0xffu8; SECTOR];
    for (at, entry) in entries {
        put_le16(&mut table, *at, entry.left);
        put_le16(&mut table, at + 2, entry.right);
        put_le32(&mut table, at + 4, u32_of(entry.sector));
        put_le32(&mut table, at + 8, u32_of(entry.size));
        table[at + 12] = entry.attributes;
        table[at + 13] = u8::try_from(entry.name.len()).unwrap();
        table[at + 14..at + 14 + entry.name.len()].copy_from_slice(entry.name.as_bytes());
    }
    table
}

/// The root table: `media` (a directory) at offset 0, its left subtree
/// `default.xbe` at offset 20 (link 5), its right subtree `readme.txt` at
/// offset 48 (link 12).
fn root_entries() -> Vec<(usize, Dirent)> {
    vec![
        (
            0,
            Dirent {
                left: 5,
                right: 12,
                sector: MEDIA_SECTOR,
                size: SECTOR,
                attributes: ATTRIBUTE_DIRECTORY,
                name: "media",
            },
        ),
        (
            20,
            Dirent {
                left: 0,
                right: 0,
                sector: XBE_SECTOR,
                size: XBE_SIZE,
                attributes: ATTRIBUTE_ARCHIVE,
                name: "default.xbe",
            },
        ),
        (
            48,
            Dirent {
                left: 0,
                right: 0,
                sector: README_SECTOR,
                size: README.len(),
                attributes: ATTRIBUTE_ARCHIVE,
                name: "readme.txt",
            },
        ),
    ]
}

/// An XBE (the layout `console.rs` reads): `XBEH`, base address 0x10000 at
/// 0x104, image size 0x1000 at 0x10C, the retail-keyed entry 0x11000 at
/// 0x128, then x86 `nop`s and `ret`.
fn xbe() -> Vec<u8> {
    let mut xbe = vec![0x90u8; XBE_SIZE];
    xbe[..0x178].fill(0);
    xbe[..4].copy_from_slice(b"XBEH");
    put_le32(&mut xbe, 0x104, 0x1_0000);
    put_le32(&mut xbe, 0x10C, 0x1000);
    put_le32(&mut xbe, 0x128, 0x1_1000 ^ 0xA8FC_57AB);
    xbe[XBE_SIZE - 1] = 0xc3;
    xbe
}

/// An XEX2 header: `XEX2`, module flags 1 (title), PE offset 0x40,
/// reserved, security offset 0x20, no optional headers.
fn xex() -> Vec<u8> {
    let mut xex = vec![0u8; XEX_SIZE];
    xex[..4].copy_from_slice(b"XEX2");
    put_be32(&mut xex, 4, 1);
    put_be32(&mut xex, 8, 0x40);
    put_be32(&mut xex, 16, 0x20);
    xex
}

/// An XDVDFS game partition: the volume descriptor at sector 32 (magic,
/// root table sector 34 and size 2048, FILETIME, the magic again at
/// 0x7EC); the root table; the `media` table holding `game.xex`; the files.
fn xdvdfs_partition_with(root: &[(usize, Dirent)]) -> Vec<u8> {
    let mut partition = vec![0u8; PARTITION_SECTORS * SECTOR];
    let descriptor = 32 * SECTOR;
    partition[descriptor..descriptor + 20].copy_from_slice(b"MICROSOFT*XBOX*MEDIA");
    put_le32(&mut partition, descriptor + 0x14, u32_of(ROOT_SECTOR));
    put_le32(&mut partition, descriptor + 0x18, u32_of(SECTOR));
    partition[descriptor + 0x1C..descriptor + 0x24]
        .copy_from_slice(&0x01D9_0000_0000_0000u64.to_le_bytes());
    partition[descriptor + 0x7EC..descriptor + 0x800].copy_from_slice(b"MICROSOFT*XBOX*MEDIA");
    let tables = [
        (ROOT_SECTOR, dir_table(root)),
        (
            MEDIA_SECTOR,
            dir_table(&[(
                0,
                Dirent {
                    left: 0,
                    right: 0,
                    sector: XEX_SECTOR,
                    size: XEX_SIZE,
                    attributes: ATTRIBUTE_ARCHIVE,
                    name: "game.xex",
                },
            )]),
        ),
    ];
    for (sector, table) in tables {
        partition[sector * SECTOR..(sector + 1) * SECTOR].copy_from_slice(&table);
    }
    let files: [(usize, Vec<u8>); 3] = [
        (XBE_SECTOR, xbe()),
        (README_SECTOR, README.to_vec()),
        (XEX_SECTOR, xex()),
    ];
    for (sector, file) in files {
        partition[sector * SECTOR..sector * SECTOR + file.len()].copy_from_slice(&file);
    }
    partition
}

/// An image with the fixture game partition at `partition_offset`.
fn xdvdfs_image(partition_offset: usize) -> Vec<u8> {
    let partition = xdvdfs_partition_with(&root_entries());
    let mut image = vec![0u8; partition_offset + partition.len()];
    image[partition_offset..].copy_from_slice(&partition);
    image
}

#[test]
fn xiso_lists_recognized_files_by_path() {
    let image = xdvdfs_image(0);
    let layout = Layout::Xdvdfs(XdvdfsImage::Xiso);
    assert_eq!(zrax::formats::discs::detect(&image), Some(layout));
    let c = parse(&image, layout);
    assert_eq!(c.format, FileFormat::XboxDvd);
    assert_eq!(c.variant, "XDVDFS image");
    assert_eq!(c.target, None);
    assert_eq!(labels(&c), ["/default.xbe", "/media/game.xex"]);
    let xbe_member = child(&c, "/default.xbe");
    assert_eq!(xbe_member.offset, XBE_SECTOR * SECTOR);
    assert_eq!(xbe_member.data.as_ref(), xbe().as_slice());
    assert_eq!(xbe_member.classify, Classify::IfRecognized);
    assert_eq!(child(&c, "/media/game.xex").offset, XEX_SECTOR * SECTOR);
    assert!(has_note(
        &c,
        "Game partition at 0x0; root directory table at sector 34, 2048 B"
    ));
    assert!(has_note(&c, "3 files; 2 in a recognized format listed"));
}

#[test]
fn xiso_members_are_classified_by_their_own_parsers() {
    let image = xdvdfs_image(0);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::XboxDvd);
    assert_eq!(p.format.variant_name.as_deref(), Some("XDVDFS image"));
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(slice_labels(&p), ["/default.xbe", "/media/game.xex"]);
    let isas: Vec<Isa> = p.slices.iter().map(|s| s.isa).collect();
    assert_eq!(isas, [Isa::X86, Isa::Ppc]);
    assert_eq!(metadata(&p, "xdvdfs_root_sector").to_string(), "34");
    assert_eq!(metadata(&p, "xdvdfs_files").to_string(), "3");
    assert_eq!(
        metadata(&p, "xdvdfs_filetime").to_string(),
        0x01D9_0000_0000_0000u64.to_string()
    );
}

/// Write a 32-bit value in both byte orders (ECMA-119 7.3.3).
fn put_both32(data: &mut [u8], at: usize, value: u32) {
    put_le32(data, at, value);
    put_be32(data, at + 4, value);
}

/// Write a 16-bit value in both byte orders (ECMA-119 7.2.3).
fn put_both16(data: &mut [u8], at: usize, value: u16) {
    put_le16(data, at, value);
    data[at + 2..at + 4].copy_from_slice(&value.to_be_bytes());
}

/// The ECMA-119 descriptors extract-xiso writes into an XISO's first 32
/// sectors. A primary volume descriptor at sector 16 (ECMA-119 8.4): type
/// 1, `CD001`, version 1, the volume space size in 2048-byte blocks at 80,
/// volume set size 1 at 120, sequence number 1 at 124, block size 2048 at
/// 128, the 34-byte root directory record at 156 (extent 18, one block,
/// directory flag, identifier 0x00) and file structure version 1 at 881.
/// A set terminator (type 255) at sector 17.
fn put_ecma119_descriptors(image: &mut [u8]) {
    let blocks = u32_of(image.len() / SECTOR);
    let primary = 16 * SECTOR;
    image[primary] = 1;
    image[primary + 1..primary + 6].copy_from_slice(b"CD001");
    image[primary + 6] = 1;
    put_both32(image, primary + 80, blocks);
    put_both16(image, primary + 120, 1);
    put_both16(image, primary + 124, 1);
    put_both16(image, primary + 128, 2048);
    let root = primary + 156;
    image[root] = 34;
    put_both32(image, root + 2, 18);
    put_both32(image, root + 10, u32_of(SECTOR));
    image[root + 25] = 0x02;
    put_both16(image, root + 28, 1);
    image[root + 32] = 1;
    image[primary + 881] = 1;
    let terminator = 17 * SECTOR;
    image[terminator] = 255;
    image[terminator + 1..terminator + 6].copy_from_slice(b"CD001");
    image[terminator + 6] = 1;
}

#[test]
fn xiso_with_ecma119_descriptors_is_reported_as_xdvdfs() {
    let mut image = xdvdfs_image(0);
    put_ecma119_descriptors(&mut image);
    // The fixture is a valid ISO 9660 volume as well, so the XDVDFS check
    // must run first.
    assert_eq!(
        zrax::formats::iso9660::detect(&image),
        Some(zrax::formats::iso9660::Layout::Iso9660)
    );
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::XboxDvd);
    assert_eq!(slice_labels(&p), ["/default.xbe", "/media/game.xex"]);
}

#[test]
fn full_disc_images_find_the_game_partition_at_documented_offsets() {
    let cases = [
        (XdvdfsImage::Xgd3, 0x0208_0000, "XGD3 disc image"),
        (XdvdfsImage::Xgd2, 0x0FD9_0000, "XGD2 disc image"),
        (XdvdfsImage::Xgd1, 0x1830_0000, "XGD1 disc image"),
    ];
    for (image_kind, partition_offset, label) in cases {
        assert_eq!(image_kind.partition_offset(), partition_offset);
        let image = xdvdfs_image(partition_offset);
        let layout = Layout::Xdvdfs(image_kind);
        assert_eq!(
            zrax::formats::discs::detect(&image),
            Some(layout),
            "{label}"
        );
        let c = parse(&image, layout);
        assert_eq!(c.variant, label);
        assert_eq!(
            child(&c, "/default.xbe").offset,
            partition_offset + XBE_SECTOR * SECTOR
        );
        assert!(has_note(
            &c,
            &format!("The 0x{partition_offset:X} B before the game partition are not parsed")
        ));
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::XboxDvd);
        assert_eq!(p.format.variant_name.as_deref(), Some(label));
        assert_eq!(p.primary.isa, Isa::X86);
    }
}

#[test]
fn xdvdfs_without_files_is_reported_as_empty() {
    let mut image = xdvdfs_image(0);
    put_le32(&mut image, 32 * SECTOR + 0x18, 0);
    let c = parse(&image, Layout::Xdvdfs(XdvdfsImage::Xiso));
    assert!(has_note(&c, "The image contains no files"));
    assert_eq!(c.children.len(), 0);
}

#[test]
fn xdvdfs_empty_root_slot_is_an_empty_directory() {
    let mut image = xdvdfs_image(0);
    image[ROOT_SECTOR * SECTOR..(ROOT_SECTOR + 1) * SECTOR].fill(0xff);
    let c = parse(&image, Layout::Xdvdfs(XdvdfsImage::Xiso));
    assert!(has_note(&c, "0 files; 0 in a recognized format listed"));
}

#[test]
fn xdvdfs_corruptions_are_parse_errors() {
    let image = xdvdfs_image(0);
    let layout = Layout::Xdvdfs(XdvdfsImage::Xiso);
    let descriptor = 32 * SECTOR;
    let root = ROOT_SECTOR * SECTOR;
    let mut trailing = image.clone();
    trailing[descriptor + 0x7EC] = b'm';
    assert!(parse_error(&trailing, layout).contains("missing trailing magic at 0x107EC"));
    let mut far_root = image.clone();
    put_le32(&mut far_root, descriptor + 0x14, 1000);
    assert!(parse_error(&far_root, layout).contains("Truncated XDVDFS directory table at 0x1F4000"));
    let mut far_link = image.clone();
    put_le16(&mut far_link, root, 0x2000);
    assert!(parse_error(&far_link, layout).contains("Truncated XDVDFS directory entry at 0x19000"));
    let mut dot_dot = image.clone();
    dot_dot[root + 13] = 2;
    dot_dot[root + 14..root + 16].copy_from_slice(b"..");
    assert!(parse_error(&dot_dot, layout).contains("Invalid XDVDFS file name at 0x11000"));
    let mut slash = image.clone();
    slash[root + 20 + 14] = b'/';
    assert!(parse_error(&slash, layout).contains("Invalid XDVDFS file name at 0x11014"));
    let mut long_name = image.clone();
    // A name that runs past the end of its table.
    long_name[root + 48 + 13] = 0xff;
    put_le32(&mut long_name, descriptor + 0x18, 300);
    assert!(parse_error(&long_name, layout).contains("Truncated XDVDFS"));
}

#[test]
fn xdvdfs_link_cycles_are_parse_errors() {
    let layout = Layout::Xdvdfs(XdvdfsImage::Xiso);
    // default.xbe's right link (5) names its own slot.
    let mut entries = root_entries();
    entries[1].1.right = 5;
    let image = xdvdfs_partition_with(&entries);
    assert!(parse_error(&image, layout)
        .contains("Invalid XDVDFS directory tree: the entry at 0x11014 is reached twice"));
    // The media directory points at the root table.
    let mut entries = root_entries();
    entries[0].1.sector = ROOT_SECTOR;
    let image = xdvdfs_partition_with(&entries);
    assert!(parse_error(&image, layout)
        .contains("Invalid XDVDFS directory tree: the table at sector 34 is reached twice"));
    // A directory table larger than the image.
    let mut entries = root_entries();
    entries[0].1.size = PARTITION_SECTORS * SECTOR;
    entries[0].1.sector = 0;
    let image = xdvdfs_partition_with(&entries);
    assert!(parse_error(&image, layout)
        .contains("Invalid XDVDFS directory tables: they span more bytes than the image"));
}

#[test]
fn xdvdfs_files_outside_a_truncated_image_are_counted() {
    let image = xdvdfs_image(0);
    let c = parse(
        &image[..XEX_SECTOR * SECTOR],
        Layout::Xdvdfs(XdvdfsImage::Xiso),
    );
    assert_eq!(labels(&c), ["/default.xbe"]);
    assert!(has_note(
        &c,
        "Not listed: 1 file outside the image; first: /media/game.xex at 0x13000 + 64 B"
    ));
}

#[test]
fn xdvdfs_truncations_error_or_leave_out_what_is_missing() {
    let image = xdvdfs_image(0);
    let layout = Layout::Xdvdfs(XdvdfsImage::Xiso);
    let tables_end = (MEDIA_SECTOR + 1) * SECTOR;
    for end in 0..image.len() {
        match container::parse(&image[..end], Kind::Discs(layout)) {
            Ok(c) => {
                assert!(end >= tables_end, "prefix {end} parsed");
                assert!(c
                    .children
                    .iter()
                    .all(|child| child.offset + child.stored_size <= end));
            }
            Err(_) => assert!(end < tables_end, "prefix {end} failed"),
        }
    }
}

#[test]
fn xdvdfs_mutations_never_panic() {
    let image = xdvdfs_image(0);
    let options = ClassifierOptions::new();
    let descriptor = 32 * SECTOR;
    let is_structure = |i: usize| {
        (descriptor..descriptor + 0x24).contains(&i)
            || (descriptor + 0x7EC..descriptor + 0x800).contains(&i)
            || (ROOT_SECTOR * SECTOR..ROOT_SECTOR * SECTOR + 80).contains(&i)
            || (MEDIA_SECTOR * SECTOR..MEDIA_SECTOR * SECTOR + 24).contains(&i)
    };
    for i in (0..image.len()).filter(|&i| is_structure(i) || i % 61 == 0) {
        for value in mutations(image[i]) {
            let mut mutated = image.clone();
            mutated[i] = value;
            let _ = container::parse(&mutated, Kind::Discs(Layout::Xdvdfs(XdvdfsImage::Xiso)));
            if i % 97 == 0 {
                let _ = detect_payload(&mutated, &options);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[test]
fn format_ids_and_names_are_registered() {
    let cases = [
        (
            FileFormat::GameCubeDisc,
            "\"gamecubedisc\"",
            "GameCube disc",
        ),
        (FileFormat::WiiDisc, "\"wiidisc\"", "Wii disc"),
        (FileFormat::XboxDvd, "\"xboxdvd\"", "Xbox DVD (XDVDFS)"),
    ];
    for (format, id, name) in cases {
        assert_eq!(serde_json::to_string(&format).expect("serializes"), id);
        assert_eq!(format.to_string(), name);
    }
    for layout in [
        Layout::GameCube,
        Layout::Wii,
        Layout::Xdvdfs(XdvdfsImage::Xiso),
    ] {
        assert!(!layout.is_weak());
        assert_eq!(Kind::Discs(layout).format(), layout.format());
    }
}
