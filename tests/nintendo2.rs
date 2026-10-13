//! Nintendo 3DS and Switch containers: synthetic NCSD (cart and NAND), CIA,
//! PFS0 and XCI images built from the documented layouts (3dbrew, makerom,
//! ctrtool, switchbrew, hactool), covering NCCH partitions and contents
//! classified by the NCCH parser, NSO members classified by `console.rs`,
//! opaque encrypted members, hash checks, corrupted fields, and truncation
//! and mutation sweeps.

use sha2::{Digest, Sha256};
use zrax::formats::container::{self, Container, Kind};
use zrax::formats::nintendo2::Layout;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    container::parse(data, Kind::Nintendo2(layout)).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    container::parse(data, Kind::Nintendo2(layout))
        .expect_err("is a parse error")
        .to_string()
}

fn detected_format(data: &[u8]) -> Option<FileFormat> {
    detect_payload(data, &ClassifierOptions::new())
        .ok()
        .map(|p| p.format.format)
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|n| n.contains(text))
}

fn payload_has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn slice<'p>(p: &'p DetectionPayload, label: &str) -> &'p zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

fn metadata<'p>(p: &'p DetectionPayload, key: &str) -> &'p zrax::MetadataValue {
    &p.metadata
        .iter()
        .find(|m| m.key == zrax::MetadataKey::Custom(key.into()))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_le_bytes());
}

fn put_le64(data: &mut [u8], at: usize, value: u64) {
    put(data, at, &value.to_le_bytes());
}

fn put_be16(data: &mut [u8], at: usize, value: u16) {
    put(data, at, &value.to_be_bytes());
}

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_be_bytes());
}

fn put_be64(data: &mut [u8], at: usize, value: u64) {
    put(data, at, &value.to_be_bytes());
}

fn u32_of(value: usize) -> u32 {
    u32::try_from(value).expect("fixture value fits in u32")
}

fn u64_of(value: usize) -> u64 {
    u64::try_from(value).expect("fixture value fits in u64")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `value` rounded up to a multiple of `alignment`.
fn align(value: usize, alignment: usize) -> usize {
    match value % alignment {
        0 => value,
        rest => value + alignment - rest,
    }
}

/// Deterministic bytes that look encrypted (xorshift32).
fn noise(size: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.max(1);
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// Every `step`-th prefix and the prefixes within 2 bytes of each boundary
/// must not be reported as `format`.
fn truncation_sweep(data: &[u8], format: FileFormat, step: usize, boundaries: &[usize]) {
    let near = boundaries
        .iter()
        .flat_map(|b| b.saturating_sub(2)..b.saturating_add(3));
    for end in (0..data.len()).step_by(step).chain(near) {
        if end >= data.len() {
            continue;
        }
        let claimed = detected_format(&data[..end]) == Some(format);
        assert!(!claimed, "prefix of {end} B still parses as {format}");
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

// --- Code fixtures ----------------------------------------------------------

/// ARM little-endian code: `push {r4, lr}`, `mov r0, #0`, `pop {r4, pc}`,
/// `bx lr`, repeated.
fn arm_code(size: usize) -> Vec<u8> {
    let words: [u32; 4] = [0xe92d_4010, 0xe3a0_0000, 0xe8bd_8010, 0xe12f_ff1e];
    words
        .iter()
        .cycle()
        .flat_map(|w| w.to_le_bytes())
        .take(size)
        .collect()
}

/// A minimal NSO (switchbrew "NSO"): `NSO0`, version 0, flags 0, the text
/// segment at file offset 0x100 (memory offset 0, 0x40 B), then AArch64
/// code: `nop` (0xD503201F) and `ret` (0xD65F03C0), repeated.
fn nso() -> Vec<u8> {
    let mut data = vec![0u8; 0x100];
    put(&mut data, 0, b"NSO0");
    put_le32(&mut data, 0x10, 0x100);
    put_le32(&mut data, 0x18, 0x40);
    for _ in 0..8 {
        data.extend_from_slice(&0xd503_201fu32.to_le_bytes());
        data.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
    }
    data
}

/// An NCA as stored: its 0xC00-byte header and a section, AES encrypted,
/// so the bytes look random.
fn encrypted_nca(seed: u32) -> Vec<u8> {
    noise(0x1000, seed)
}

/// A decrypted NCA header: zeros with the `NCA3` magic at 0x200.
fn plaintext_nca() -> Vec<u8> {
    let mut data = vec![0u8; 0xc00];
    put(&mut data, 0x200, b"NCA3");
    data
}

// --- 3DS NCCH ---------------------------------------------------------------

/// NCCH fixture options.
#[derive(Clone, Copy)]
struct NcchOptions {
    /// flags\[7\] `NoCrypto` (0x04); clear means the content is encrypted.
    no_crypto: bool,
    /// A CXI (form type 3, with `ExHeader` and `ExeFS`) or a CFA (form
    /// type 1, the header alone).
    executable: bool,
}

const CXI: NcchOptions = NcchOptions {
    no_crypto: true,
    executable: true,
};

const CFA: NcchOptions = NcchOptions {
    no_crypto: true,
    executable: false,
};

/// An NCCH partition (3dbrew "NCCH"): a signature pattern (0x100), `NCCH`
/// at 0x100, the content size in 0x200-byte media units at 0x104, the
/// partition ID at 0x108, maker code `01` at 0x110, version 2 at 0x112, the
/// program ID at 0x118, product code `CTR-P-ZRAX` at 0x150, then flags at
/// 0x188 (\[4\] platform CTR, \[5\] form type, \[7\] `NoCrypto`).
///
/// A CXI is 8 units: a 0x400-byte `ExHeader` (size at 0x180) at 0x200
/// (title `ZraxApp` at 0, `.code` not compressed, text code set 0x00100000
/// with 1 page and 0x100 B at 0x10, stack 0x4000 at 0x1C), and an `ExeFS`
/// at unit 6 (0xC00) of 2 units with a 1-unit hash region (0x1A0, 0x1A4,
/// 0x1A8): its header lists `.code` at 0 with 0x100 B and the file's
/// SHA-256 at 0x1E0, the NCCH header holds the superblock SHA-256 at 0x1C0,
/// and the ARM code follows the `ExeFS` header at 0xE00. A CFA is the
/// 0x200-byte header alone (1 unit).
fn ncch(options: NcchOptions) -> Vec<u8> {
    let size = if options.executable { 0x1000 } else { 0x200 };
    let mut data = vec![0xa5u8; 0x100];
    data.resize(size, 0);
    put(&mut data, 0x100, b"NCCH");
    put_le32(&mut data, 0x104, u32_of(size / 0x200));
    put_le64(&mut data, 0x108, 0x0004_0000_00ab_cd00);
    put(&mut data, 0x110, b"01");
    data[0x112] = 2;
    put_le64(&mut data, 0x118, 0x0004_0000_00ab_cd00);
    put(&mut data, 0x150, b"CTR-P-ZRAX");
    data[0x188 + 4] = 1;
    data[0x188 + 5] = if options.executable { 3 } else { 1 };
    data[0x188 + 7] = if options.no_crypto { 0x04 } else { 0 };
    if !options.executable {
        return data;
    }
    put_le32(&mut data, 0x180, 0x400);
    put(&mut data, 0x200, b"ZraxApp");
    put_le32(&mut data, 0x200 + 0x10, 0x0010_0000);
    put_le32(&mut data, 0x200 + 0x14, 1);
    put_le32(&mut data, 0x200 + 0x18, 0x100);
    put_le32(&mut data, 0x200 + 0x1c, 0x4000);
    let code = arm_code(0x100);
    put(&mut data, 0xc00, b".code");
    put_le32(&mut data, 0xc00 + 8, 0);
    put_le32(&mut data, 0xc00 + 12, 0x100);
    put(&mut data, 0xc00 + 0x1e0, &sha256(&code));
    put(&mut data, 0xe00, &code);
    put_le32(&mut data, 0x1a0, 6);
    put_le32(&mut data, 0x1a4, 2);
    put_le32(&mut data, 0x1a8, 1);
    let superblock = sha256(&data[0xc00..0xe00]);
    put(&mut data, 0x1c0, &superblock);
    data
}

// --- 3DS NCSD ---------------------------------------------------------------

/// Where cart partitions start: the 0x4000-byte cart header area (NCSD
/// header, card info, initial data, development card area).
const CCI_FIRST_PARTITION: usize = 0x4000;

/// A CTR cart image (3dbrew "NCSD"): a signature pattern (0x100), `NCSD`
/// at 0x100, the image size in media units at 0x104, media ID
/// 0x00040000ABCD0000 at 0x108, FS and crypt types 0, the partition table
/// at 0x120 (offset and size in media units), flags at 0x188 (\[3\] card
/// device NOR flash, \[4\] platform CTR, \[5\] media type Card1, \[6\] the
/// media unit exponent) and the partition IDs at 0x190. Partitions follow
/// each other from 0x4000, each zero-padded to whole media units. With
/// `fill`, erased flash (0xFF) follows up to `image_units`; otherwise the
/// image is trimmed after the last partition.
fn cci(partitions: &[(usize, Vec<u8>)], exponent: u8, image_units: u32, fill: bool) -> Vec<u8> {
    let unit = 0x200usize << exponent;
    let mut data = vec![0x5au8; 0x100];
    data.resize(CCI_FIRST_PARTITION, 0);
    put(&mut data, 0x100, b"NCSD");
    put_le32(&mut data, 0x104, image_units);
    put_le64(&mut data, 0x108, 0x0004_0000_abcd_0000);
    data[0x188 + 3] = 1;
    data[0x188 + 4] = 1;
    data[0x188 + 5] = 1;
    data[0x188 + 6] = exponent;
    for (index, bytes) in partitions {
        let offset = align(data.len(), unit);
        data.resize(offset, 0);
        data.extend_from_slice(bytes);
        let size = align(bytes.len(), unit);
        data.resize(offset + size, 0);
        put_le32(&mut data, 0x120 + 8 * index, u32_of(offset / unit));
        put_le32(&mut data, 0x124 + 8 * index, u32_of(size / unit));
        put_le64(
            &mut data,
            0x190 + 8 * index,
            0x0004_0000_abcd_0000 + u64_of(*index),
        );
    }
    if fill {
        data.resize(image_units as usize * unit, 0xff);
    }
    data
}

/// The cart image used by most tests: a NoCrypto CXI as partition 0 and a
/// NoCrypto CFA as partition 1, in a 0x30-unit (24 KiB) image, trimmed.
fn game_card() -> Vec<u8> {
    cci(&[(0, ncch(CXI)), (1, ncch(CFA))], 0, 0x30, false)
}

/// A NAND image (3dbrew "NCSD", "Flash Filesystem"): FS types 1 (TWL
/// NAND), 3 (firm0) and 1 (CTR-NAND) with crypt types 1, 2 and 2 for
/// partitions 0, 2 and 4; partition 0 starts at 0 (it holds the NCSD
/// header sector), partition 2 at unit 4 (2 units) and partition 4 at unit
/// 6 (4 units), in a 10-unit image, all encrypted-looking, followed by
/// 0x200 bytes of NAND space outside the partitions.
fn nand() -> Vec<u8> {
    let mut data = noise(0x1600, 7);
    data[..0x200].fill(0);
    put(&mut data, 0, &[0x5a; 0x100]);
    put(&mut data, 0x100, b"NCSD");
    put_le32(&mut data, 0x104, 10);
    for (index, fs_type, crypt_type, offset, units) in
        [(0, 1, 1, 0, 4), (2, 3, 2, 4, 2), (4, 1, 2, 6, 4)]
    {
        data[0x110 + index] = fs_type;
        data[0x118 + index] = crypt_type;
        put_le32(&mut data, 0x120 + 8 * index, offset);
        put_le32(&mut data, 0x124 + 8 * index, units);
    }
    data
}

#[test]
fn cart_partitions_are_classified_by_the_ncch_parser() {
    let file = game_card();
    let c = parse(&file, Layout::Ncsd);
    assert_eq!(c.format, FileFormat::Ncsd);
    assert_eq!(c.variant, "3DS CCI");
    assert!(c.target.is_none());
    assert_eq!(
        labels(&c),
        ["Partition 0 (executable content)", "Partition 1 (e-manual)"]
    );
    assert_eq!(c.children[0].offset, 0x4000);
    assert_eq!(c.children[0].stored_size, 0x1000);
    assert_eq!(c.children[1].offset, 0x5000);
    assert!(c.children.iter().all(|child| !child.opaque));
    assert!(has_note(
        &c,
        "3DS CTR cart image; media ID 0x00040000ABCD0000; media type Card1; card device NOR flash; media unit 512 B"
    ));
    assert!(has_note(
        &c,
        "Trimmed image: the file holds 0x5200 of 0x6000 B"
    ));
    assert!(has_note(&c, "2 partitions; 2 in a recognized format"));

    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Ncsd);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert!(payload_has_note(
        &p,
        "Partition 0 (executable content): arm (contained 3DS NCCH)"
    ));
    assert!(payload_has_note(
        &p,
        "Partition 1 (e-manual): unknown(0x0000) (contained 3DS NCCH)"
    ));
    let partition = slice(&p, "Partition 0 (executable content)");
    assert_eq!((partition.offset, partition.size), (0x4000, 0x1000));
    assert_eq!(partition.isa, Isa::Arm);
    assert!(matches!(
        metadata(&p, "ncsd_partition_1_id"),
        zrax::MetadataValue::String(s) if s == "0x00040000ABCD0001"
    ));
}

#[test]
fn full_cart_dumps_end_in_erased_flash() {
    let file = cci(&[(0, ncch(CXI)), (1, ncch(CFA))], 0, 0x30, true);
    assert_eq!(file.len(), 0x6000);
    let c = parse(&file, Layout::Ncsd);
    assert!(!has_note(&c, "Trimmed image"));
    assert_eq!(c.consumed, 0x6000);

    let mut junk = file.clone();
    junk[0x5800] = 0x12;
    assert_eq!(
        parse_error(&junk, Layout::Ncsd),
        "Nintendo container parse error: Unexpected data in the 3584 B after the last NCSD partition at 0x5200"
    );
}

#[test]
fn card2_writable_regions_are_kept_but_not_parsed() {
    // A CARD2 cart (media type 2) whose card info header at 0x200 puts the
    // writable region at unit 0x2C (0x5800), holding save data.
    let mut file = cci(&[(0, ncch(CXI))], 0, 0x30, true);
    file[0x188 + 5] = 2;
    put_le32(&mut file, 0x200, 0x2c);
    file[0x5800..].copy_from_slice(&noise(0x800, 11));
    let c = parse(&file, Layout::Ncsd);
    assert!(has_note(&c, "media type Card2"));
    assert!(has_note(
        &c,
        "CARD2 writable region (save data) at 0x5800: 2 KiB not parsed"
    ));
    // The bytes between the last partition and the writable region are
    // still erased flash.
    file[0x5400] = 0x12;
    assert_eq!(
        parse_error(&file, Layout::Ncsd),
        "Nintendo container parse error: Unexpected data in the 2 KiB after the last NCSD partition at 0x5000"
    );
}

#[test]
fn cart_media_units_scale_the_partition_table() {
    let file = cci(&[(0, ncch(CXI)), (1, ncch(CFA))], 1, 0x18, false);
    let c = parse(&file, Layout::Ncsd);
    assert!(has_note(&c, "media unit 1 KiB"));
    assert_eq!(c.children[0].offset, 0x4000);
    assert_eq!(c.children[1].offset, 0x5000);
    assert_eq!(c.children[1].stored_size, 0x400);
    // The CFA is followed by zero padding inside its 1 KiB partition, which
    // the NCCH parser accepts.
    assert_eq!(classify(&file).primary.isa, Isa::Arm);
}

#[test]
fn encrypted_cxi_partitions_keep_the_ncch_parser_decision() {
    let encrypted = NcchOptions {
        no_crypto: false,
        ..CXI
    };
    let p = classify(&cci(&[(0, ncch(encrypted))], 0, 0x30, false));
    assert_eq!(p.format.format, FileFormat::Ncsd);
    // The NCCH header marks an executable, which names the ARM11; its
    // encrypted regions stay opaque inside the NCCH result.
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(payload_has_note(
        &p,
        "Partition 0 (executable content): arm (contained 3DS NCCH)"
    ));
}

#[test]
fn cart_partitions_that_are_not_ncch_are_opaque() {
    let p = classify(&cci(&[(0, noise(0x800, 3))], 0, 0x30, false));
    assert_eq!(p.format.format, FileFormat::Ncsd);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(payload_has_note(
        &p,
        "1 partition not in a recognized format listed as opaque"
    ));
    assert!(payload_has_note(
        &p,
        "Partition 0 (executable content): opaque; payload ISA analysis skipped"
    ));
}

#[test]
fn nand_partitions_are_opaque() {
    let file = nand();
    let c = parse(&file, Layout::Ncsd);
    assert_eq!(c.variant, "3DS NAND image");
    assert_eq!(
        labels(&c),
        [
            "Partition 0 (normal FS; TWL crypt)",
            "Partition 2 (FIRM; CTR crypt)",
            "Partition 4 (normal FS; CTR crypt)"
        ]
    );
    assert_eq!(c.children[0].offset, 0);
    assert_eq!(c.children[2].offset, 0xc00);
    assert!(c.children.iter().all(|child| child.opaque));
    assert!(has_note(
        &c,
        "3DS NAND image; partitions are AES-CTR encrypted"
    ));
    assert!(has_note(
        &c,
        "512 B after the last partition at 0x1400 are not parsed"
    ));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Ncsd);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
}

#[test]
fn corrupt_ncsd_headers_are_parse_errors() {
    let file = game_card();

    let mut overlap = file.clone();
    put_le32(&mut overlap, 0x128, 0x21);
    assert_eq!(
        parse_error(&overlap, Layout::Ncsd),
        "Nintendo container parse error: Invalid NCSD partitions 0 and 1: they overlap"
    );

    let mut beyond = file.clone();
    put_le32(&mut beyond, 0x104, 0x28);
    assert_eq!(
        parse_error(&beyond, Layout::Ncsd),
        "Nintendo container parse error: Invalid NCSD partition 1 0x5000 + 512 B: beyond the 0x5000-byte image"
    );

    let mut card3 = file.clone();
    card3[0x188 + 5] = 3;
    assert!(parse_error(&card3, Layout::Ncsd).contains("Unsupported NCSD media type 3"));

    let mut no_ctr = file.clone();
    no_ctr[0x188 + 4] = 2;
    assert!(parse_error(&no_ctr, Layout::Ncsd).contains("Unsupported NCSD media platform 0x02"));

    let mut huge_unit = file.clone();
    huge_unit[0x188 + 6] = 0x40;
    assert!(
        parse_error(&huge_unit, Layout::Ncsd).contains("Invalid NCSD media unit size exponent 64")
    );

    // Strong detection: a damaged header is a parse error, not raw code.
    assert!(detect_payload(&overlap, &ClassifierOptions::new()).is_err());
    assert_eq!(
        parse_error(&file[..0x5100], Layout::Ncsd),
        "Nintendo container parse error: Truncated NCSD partition 1: ends at 0x5200, file 20736 B"
    );
}

// --- 3DS CIA ----------------------------------------------------------------

/// A CIA content fixture.
struct CiaContent {
    index: u16,
    id: u32,
    /// TMD content type bit 0.
    encrypted: bool,
    bytes: Vec<u8>,
}

/// A certificate (3dbrew "Certificates"): signature type 0x10003 (RSA-4096
/// SHA-256, big-endian), the 0x200-byte signature and 0x3C bytes of
/// padding, issuer `Root`, key type 1 (RSA-2048), name `CA00000003`, an
/// expiration of 0, the 0x100-byte modulus, exponent 0x10001 and 0x34
/// bytes of padding: 0x400 bytes.
fn certificate() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    put_be32(&mut data, 0, 0x0001_0003);
    data[4..0x204].fill(0x11);
    put(&mut data, 0x240, b"Root");
    put_be32(&mut data, 0x280, 1);
    put(&mut data, 0x284, b"CA00000003");
    data[0x2c8..0x3c8].fill(0x22);
    put_be32(&mut data, 0x3c8, 0x0001_0001);
    data
}

/// A ticket (3dbrew "Ticket"): signature type 0x10004 (RSA-2048 SHA-256),
/// the 0x100-byte signature and 0x3C bytes of padding, then 0x210 bytes of
/// ticket data: issuer `Root-CA00000003-XS0000000c`, version 1 at 0x7C, a
/// title key at 0x7F and the title ID at 0x9C: 0x350 bytes.
fn ticket() -> Vec<u8> {
    let mut data = vec![0u8; 0x350];
    put_be32(&mut data, 0, 0x0001_0004);
    data[4..0x104].fill(0x33);
    put(&mut data, 0x140, b"Root-CA00000003-XS0000000c");
    data[0x140 + 0x7c] = 1;
    data[0x140 + 0x7f..0x140 + 0x8f].fill(0x44);
    put_be64(&mut data, 0x140 + 0x9c, 0x0004_0000_00ab_cd00);
    data
}

/// A version 1 TMD (3dbrew "Title metadata"), big-endian: signature type
/// 0x10004 with a 0x100-byte signature and 0x3C bytes of padding; the
/// header at 0x140 (issuer `Root-CA00000003-CP0000000b`, version 1 at 0x40,
/// title ID at 0x4C, title type 0x40 at 0x54, title version 0x0410 at
/// 0x9C, the content count at 0x9E, and the SHA-256 of the content info
/// records at 0xA4); 64 content info records of which the first hashes all
/// content chunk records; and one chunk record per content (ID, index,
/// type, size, SHA-256 of the bytes).
fn tmd(contents: &[CiaContent]) -> Vec<u8> {
    let mut chunks = Vec::new();
    for content in contents {
        let mut record = vec![0u8; 0x30];
        put_be32(&mut record, 0, content.id);
        put_be16(&mut record, 4, content.index);
        put_be16(&mut record, 6, u16::from(content.encrypted));
        put_be64(&mut record, 8, u64_of(content.bytes.len()));
        put(&mut record, 0x10, &sha256(&content.bytes));
        chunks.extend_from_slice(&record);
    }
    let mut info = vec![0u8; 64 * 0x24];
    put_be16(&mut info, 2, u16::try_from(contents.len()).unwrap());
    put(&mut info, 4, &sha256(&chunks));
    let mut data = vec![0u8; 0x140 + 0xc4];
    put_be32(&mut data, 0, 0x0001_0004);
    data[4..0x104].fill(0x55);
    put(&mut data, 0x140, b"Root-CA00000003-CP0000000b");
    data[0x140 + 0x40] = 1;
    put_be64(&mut data, 0x140 + 0x4c, 0x0004_0000_00ab_cd00);
    put_be32(&mut data, 0x140 + 0x54, 0x40);
    put_be16(&mut data, 0x140 + 0x9c, 0x0410);
    put_be16(
        &mut data,
        0x140 + 0x9e,
        u16::try_from(contents.len()).unwrap(),
    );
    put(&mut data, 0x140 + 0xa4, &sha256(&info));
    data.extend_from_slice(&info);
    data.extend_from_slice(&chunks);
    data
}

/// The meta section (3dbrew "CIA"): one dependency title ID, core version
/// 2 at 0x300, then a zeroed 0x36C0-byte icon.
fn meta() -> Vec<u8> {
    let mut data = vec![0u8; 0x400 + 0x36c0];
    put_le64(&mut data, 0, 0x0004_0130_0000_2c02);
    put_le32(&mut data, 0x300, 2);
    data
}

/// A CIA (3dbrew "CIA"; makerom `cia.c`): the 0x2020-byte little-endian
/// header (header size, type 0, version 0, the certificate chain, ticket,
/// TMD and meta sizes, the content size, and the content index bitmap with
/// bit `0x80 >> (i % 8)` of byte `i / 8` per content), then the
/// certificate chain, ticket, TMD, contents and optional meta, each section
/// at the previous end aligned to 64 bytes and each content at a
/// 16-byte-aligned position of the content section.
fn cia(contents: &[CiaContent], with_meta: bool) -> Vec<u8> {
    let certificates = certificate();
    let ticket = ticket();
    let tmd = tmd(contents);
    let mut content = Vec::new();
    for c in contents {
        content.resize(align(content.len(), 16), 0);
        content.extend_from_slice(&c.bytes);
    }
    content.resize(align(content.len(), 16), 0);
    let meta = if with_meta { meta() } else { Vec::new() };

    let mut data = vec![0u8; 0x2020];
    put_le32(&mut data, 0, 0x2020);
    put_le32(&mut data, 8, u32_of(certificates.len()));
    put_le32(&mut data, 0xc, u32_of(ticket.len()));
    put_le32(&mut data, 0x10, u32_of(tmd.len()));
    put_le32(&mut data, 0x14, u32_of(meta.len()));
    put_le64(&mut data, 0x18, u64_of(content.len()));
    for c in contents {
        let index = usize::from(c.index);
        data[0x20 + index / 8] |= 0x80 >> (index % 8);
    }
    for section in [&certificates, &ticket, &tmd, &content] {
        data.resize(align(data.len(), 64), 0);
        data.extend_from_slice(section);
    }
    if with_meta {
        data.resize(align(data.len(), 64), 0);
        data.extend_from_slice(&meta);
    }
    data
}

/// A CIA of a NoCrypto CXI (content 0) and CFA (content 1), with meta.
fn plain_cia() -> Vec<u8> {
    cia(
        &[
            CiaContent {
                index: 0,
                id: 0,
                encrypted: false,
                bytes: ncch(CXI),
            },
            CiaContent {
                index: 1,
                id: 1,
                encrypted: false,
                bytes: ncch(CFA),
            },
        ],
        true,
    )
}

/// Offsets in [`plain_cia`]: the certificate chain at 0x2040, the ticket at
/// 0x2440, the TMD (0xB64 B) at 0x27C0, the contents at 0x3340 and 0x4340,
/// the meta at 0x4540.
const CIA_TMD: usize = 0x27c0;
const CIA_CONTENT: usize = 0x3340;
const CIA_META: usize = 0x4540;

#[test]
fn cia_contents_are_classified_and_their_hashes_verified() {
    let file = plain_cia();
    assert_eq!(file.len(), CIA_META + 0x3ac0);
    assert_eq!(detected_format(&file), Some(FileFormat::Cia));
    let c = parse(&file, Layout::Cia);
    assert_eq!(
        labels(&c),
        [
            "Certificate chain",
            "Ticket",
            "TMD",
            "Content 0 (ID 0x00000000)",
            "Content 1 (ID 0x00000001)",
            "Meta"
        ]
    );
    let offsets: Vec<usize> = c.children.iter().map(|child| child.offset).collect();
    assert_eq!(
        offsets,
        [
            0x2040,
            0x2440,
            CIA_TMD,
            CIA_CONTENT,
            CIA_CONTENT + 0x1000,
            CIA_META
        ]
    );
    assert!(has_note(
        &c,
        "3DS CIA; title ID 0x0004000000ABCD00; title version 1040; title type 0x00000040; 2 contents in the TMD, 2 in the archive"
    ));
    assert!(has_note(
        &c,
        "signatures (certificate chain RSA-4096 SHA-256, ticket RSA-2048 SHA-256, TMD RSA-2048 SHA-256) are not verified"
    ));
    assert!(has_note(
        &c,
        "Content SHA-256 verified for 2 of 2 unencrypted contents"
    ));
    assert!(has_note(
        &c,
        "Meta: core version 0x00000002; 1 dependency; icon data 14016 B"
    ));

    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Cia);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(payload_has_note(
        &p,
        "Content 0 (ID 0x00000000): arm (contained 3DS NCCH)"
    ));
    assert!(payload_has_note(&p, "TMD: opaque"));
    assert!(matches!(
        metadata(&p, "cia_title_id"),
        zrax::MetadataValue::String(s) if s == "0x0004000000ABCD00"
    ));
}

#[test]
fn encrypted_cia_contents_are_opaque() {
    let file = cia(
        &[CiaContent {
            index: 0,
            id: 0x0000_0004,
            encrypted: true,
            bytes: noise(0x1000, 9),
        }],
        false,
    );
    let c = parse(&file, Layout::Cia);
    assert!(c.children[3].opaque);
    assert_eq!(c.children[3].label, "Content 0 (ID 0x00000004), encrypted");
    assert!(has_note(
        &c,
        "1 of 1 contents are AES-128-CBC encrypted with the ticket's title key"
    ));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Cia);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
}

#[test]
fn cia_content_positions_are_aligned_to_16_bytes() {
    let odd = CiaContent {
        index: 0,
        id: 0,
        encrypted: false,
        bytes: noise(0x101, 4),
    };
    let skipped = CiaContent {
        index: 5,
        id: 5,
        encrypted: true,
        bytes: noise(0x20, 5),
    };
    let file = cia(&[odd, skipped], false);
    let c = parse(&file, Layout::Cia);
    let content = c
        .children
        .iter()
        .find(|child| child.label.starts_with("Content 5"))
        .expect("content 5");
    // Content 0 (0x101 B) starts the content section at 0x3340; content 5
    // follows at the next 16-byte boundary.
    assert_eq!(content.offset, 0x3340 + 0x110);
    assert_eq!(content.stored_size, 0x20);
    // Without meta, the file ends at the content end.
    assert_eq!(file.len(), content.offset + 0x20);
}

#[test]
fn cia_files_end_at_the_last_section_or_its_64_byte_boundary() {
    let contents = [CiaContent {
        index: 0,
        id: 0,
        encrypted: false,
        bytes: ncch(CFA)[..0x1f0].to_vec(),
    }];
    let exact = cia(&contents, false);
    assert_eq!(exact.len() % 64, 0x30);
    assert_eq!(detected_format(&exact), Some(FileFormat::Cia));
    let mut padded = exact.clone();
    padded.resize(align(exact.len(), 64), 0);
    assert_eq!(detected_format(&padded), Some(FileFormat::Cia));
    let mut longer = exact.clone();
    longer.resize(exact.len() + 64, 0);
    assert_ne!(detected_format(&longer), Some(FileFormat::Cia));
    assert!(parse_error(&longer, Layout::Cia).contains("Invalid CIA size: the sections end at"));
    let mut dirty = padded;
    let last = dirty.len() - 1;
    dirty[last] = 1;
    assert_ne!(detected_format(&dirty), Some(FileFormat::Cia));
}

#[test]
fn cia_recognition_requires_a_consistent_header_and_tmd() {
    let file = plain_cia();

    let mut header_size = file.clone();
    put_le32(&mut header_size, 0, 0x2000);
    assert!(parse_error(&header_size, Layout::Cia).contains("Invalid CIA header size 0x2000"));

    let mut simple = file.clone();
    simple[6] = 0xff;
    assert!(parse_error(&simple, Layout::Cia)
        .contains("Unsupported CIA format version 0x00FF (simple CIA without a TMD)"));

    let mut signature = file.clone();
    put_be32(&mut signature, CIA_TMD, 0x0001_0006);
    assert!(
        parse_error(&signature, Layout::Cia).contains("Unsupported TMD signature type 0x00010006")
    );

    let mut info = file.clone();
    info[CIA_TMD + 0x140 + 0xc4 + 2] ^= 1;
    assert!(parse_error(&info, Layout::Cia)
        .contains("Invalid TMD content info records: SHA-256 mismatch"));

    let mut chunk = file.clone();
    chunk[CIA_TMD + 0x140 + 0xc4 + 0x900 + 8] ^= 1;
    assert!(parse_error(&chunk, Layout::Cia)
        .contains("Invalid TMD content chunk records 0 to 1: SHA-256 mismatch"));

    let mut bitmap = file.clone();
    bitmap[0x20] = 0x80;
    assert!(parse_error(&bitmap, Layout::Cia)
        .contains("Invalid CIA content section size 0x1200: the present contents end at 0x1000"));

    for broken in [header_size, simple, signature, info, chunk, bitmap] {
        assert_ne!(detected_format(&broken), Some(FileFormat::Cia));
    }
}

#[test]
fn cia_content_hash_mismatch_is_reported() {
    let mut file = plain_cia();
    // A byte of the CFA's signature area: the NCCH still parses.
    file[CIA_CONTENT + 0x1000 + 4] ^= 0xff;
    let c = parse(&file, Layout::Cia);
    assert!(has_note(
        &c,
        "Content SHA-256 verified for 1 of 2 unencrypted contents; mismatch for content 1"
    ));
}

// --- Switch PFS0 ------------------------------------------------------------

/// A PFS0 (switchbrew "NCA", section PFS0; hactool `pfs0.h`): `PFS0`, the
/// entry count, the string table size and a reserved word; 0x18-byte
/// entries (data offset after the string table, size, name offset,
/// reserved); NUL-terminated names padded with zeros so the data starts at
/// a multiple of 0x20; then the files in order.
fn pfs0(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut names = Vec::new();
    let mut entries = Vec::new();
    let mut contents = Vec::new();
    for (name, bytes) in files {
        let mut entry = vec![0u8; 0x18];
        put_le64(&mut entry, 0, u64_of(contents.len()));
        put_le64(&mut entry, 8, u64_of(bytes.len()));
        put_le32(&mut entry, 0x10, u32_of(names.len()));
        entries.extend_from_slice(&entry);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        contents.extend_from_slice(bytes);
    }
    let header_end = 0x10 + entries.len() + names.len();
    names.resize(names.len() + align(header_end, 0x20) - header_end, 0);
    let mut data = b"PFS0".to_vec();
    data.extend_from_slice(&u32_of(files.len()).to_le_bytes());
    data.extend_from_slice(&u32_of(names.len()).to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&entries);
    data.extend_from_slice(&names);
    data.extend_from_slice(&contents);
    data
}

/// An NSP-like PFS0: an encrypted NCA, a ticket, a certificate chain and
/// an NSO.
fn nsp() -> Vec<u8> {
    pfs0(&[
        ("0123456789abcdef0123456789abcdef.nca", encrypted_nca(1)),
        ("0100000000010000.tik", ticket()),
        ("0100000000010000.cert", certificate()),
        ("main", nso()),
    ])
}

#[test]
fn pfs0_files_are_children_labeled_by_name() {
    let file = nsp();
    let c = parse(&file, Layout::Pfs0);
    assert_eq!(
        labels(&c),
        [
            "0123456789abcdef0123456789abcdef.nca",
            "0100000000010000.tik",
            "0100000000010000.cert",
            "main"
        ]
    );
    // 0x10 + 4 entries of 0x18 + 85 name bytes, padded to 0xE0.
    let header_size = 0xe0;
    assert_eq!(c.children[0].offset, header_size);
    assert_eq!(c.children[1].offset, header_size + 0x1000);
    assert!(c.children[0].opaque && c.children[1].opaque && c.children[2].opaque);
    assert!(!c.children[3].opaque);
    assert!(has_note(&c, "PFS0: 4 files; header and string table 224 B"));
    assert!(has_note(&c, "NCA content archives are AES-XTS encrypted"));
    assert!(has_note(
        &c,
        "4 files; 1 in a recognized format, classified on their own"
    ));

    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Pfs0);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(payload_has_note(&p, "main: aarch64 (contained NSO)"));
    let main = slice(&p, "main");
    assert_eq!(main.offset, u64_of(header_size + 0x1000 + 0x350 + 0x400));
    assert!(matches!(
        slice(&p, "0123456789abcdef0123456789abcdef.nca").isa,
        Isa::Unknown(_)
    ));
}

#[test]
fn pfs0_exefs_and_plaintext_ncas_are_noted() {
    let mut npdm = b"META".to_vec();
    npdm.resize(0x80, 0);
    let exefs = pfs0(&[("main", nso()), ("main.npdm", npdm)]);
    let c = parse(&exefs, Layout::Pfs0);
    assert!(has_note(
        &c,
        "main.npdm carries the META magic, which hactool takes as the mark of an ExeFS"
    ));
    assert!(!has_note(&c, "NCA content archives"));

    let decrypted = pfs0(&[("program.nca", plaintext_nca())]);
    let c = parse(&decrypted, Layout::Pfs0);
    assert!(has_note(
        &c,
        "1 file with a plaintext NCA magic at 0x200 (a decrypted NCA header); NCA sections are not parsed"
    ));
    assert!(c.children[0].opaque);
}

#[test]
fn corrupt_pfs0_tables_are_parse_errors() {
    let file = nsp();
    let mut beyond = file.clone();
    put_le64(&mut beyond, 0x10 + 3 * 0x18 + 8, 0x1_0000);
    assert_eq!(
        parse_error(&beyond, Layout::Pfs0),
        "Nintendo container parse error: Invalid PFS0 entry main in the PFS0 at 0x0: data 0x1750 + 65536 B beyond the 6512 B PFS0"
    );
    assert!(detect_payload(&beyond, &ClassifierOptions::new()).is_err());

    let mut name = file.clone();
    put_le32(&mut name, 0x10 + 0x10, 0x70);
    assert!(parse_error(&name, Layout::Pfs0).contains("Invalid PFS0 entry 0: name offset 0x70"));

    let mut trailing = file.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing, Layout::Pfs0).contains("Unexpected 4 B after the PFS0 data"));

    let mut count = file;
    put_le32(&mut count, 4, 0x1000);
    assert_ne!(detected_format(&count), Some(FileFormat::Pfs0));
}

/// A PFS0 of `count` entries that all name the same NSO (offset 0, name
/// offset 0): the format does not forbid overlapping entries.
fn overlapping_pfs0(count: usize) -> Vec<u8> {
    let nso = nso();
    let header_end = 0x10 + count * 0x18 + 5;
    let names_size = align(header_end, 0x20) - 0x10 - count * 0x18;
    let mut data = b"PFS0".to_vec();
    data.extend_from_slice(&u32_of(count).to_le_bytes());
    data.extend_from_slice(&u32_of(names_size).to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    for _ in 0..count {
        let mut entry = vec![0u8; 0x18];
        put_le64(&mut entry, 8, u64_of(nso.len()));
        data.extend_from_slice(&entry);
    }
    let mut names = b"main\0".to_vec();
    names.resize(names_size, 0);
    data.extend_from_slice(&names);
    data.extend_from_slice(&nso);
    data
}

#[test]
fn overlapping_members_are_checked_within_the_container_size() {
    // 64 entries of the 0x140-byte NSO in a 0x760-byte (1888 B) file: five
    // fit the examination budget, the rest stay opaque.
    let file = overlapping_pfs0(64);
    assert_eq!(file.len(), 0x760);
    let c = parse(&file, Layout::Pfs0);
    assert_eq!(c.children.len(), 64);
    assert_eq!(c.children.iter().filter(|child| !child.opaque).count(), 5);
    assert!(has_note(
        &c,
        "64 files; 5 in a recognized format, classified on their own"
    ));
    assert!(has_note(
        &c,
        "Not examined: 59 files past the examination budget of 1888 B (the container size), listed as opaque"
    ));
    assert_eq!(classify(&file).primary.isa, Isa::AArch64);
}

// --- Switch XCI -------------------------------------------------------------

/// The root HFS0 offset in the card header: the HFS0 that switchbrew places
/// at card offset 0x10000, after the 0x1000-byte key area that XCI files
/// leave out.
const XCI_ROOT_OFFSET: usize = 0xf000;

/// An HFS0 and the size of its header (magic, counts, entries and string
/// table).
struct Hfs0 {
    bytes: Vec<u8>,
    header_size: usize,
}

/// An HFS0 (switchbrew "XCI"; hactool `hfs0.h`): like a PFS0 with `HFS0`
/// and 0x40-byte entries that add the hashed region size (at 0x14) and the
/// SHA-256 of the file's first hashed-region bytes (at 0x20). `hashed`
/// gives each file's hashed region size.
fn hfs0(files: &[(&str, Vec<u8>, usize)]) -> Hfs0 {
    let mut names = Vec::new();
    let mut entries = Vec::new();
    let mut contents = Vec::new();
    for (name, bytes, hashed) in files {
        let mut entry = vec![0u8; 0x40];
        put_le64(&mut entry, 0, u64_of(contents.len()));
        put_le64(&mut entry, 8, u64_of(bytes.len()));
        put_le32(&mut entry, 0x10, u32_of(names.len()));
        put_le32(&mut entry, 0x14, u32_of(*hashed));
        put(&mut entry, 0x20, &sha256(&bytes[..*hashed]));
        entries.extend_from_slice(&entry);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        contents.extend_from_slice(bytes);
    }
    let header_end = 0x10 + entries.len() + names.len();
    names.resize(names.len() + align(header_end, 0x200) - header_end, 0);
    let mut bytes = b"HFS0".to_vec();
    bytes.extend_from_slice(&u32_of(files.len()).to_le_bytes());
    bytes.extend_from_slice(&u32_of(names.len()).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&entries);
    bytes.extend_from_slice(&names);
    let header_size = bytes.len();
    bytes.extend_from_slice(&contents);
    Hfs0 { bytes, header_size }
}

/// A partition HFS0 whose files hash their first 0x200 bytes (or all of a
/// shorter file), as NCAs do.
fn partition(files: &[(&str, Vec<u8>)]) -> Hfs0 {
    let hashed: Vec<(&str, Vec<u8>, usize)> = files
        .iter()
        .map(|(name, bytes)| (*name, bytes.clone(), bytes.len().min(0x200)))
        .collect();
    hfs0(&hashed)
}

/// An XCI (switchbrew "XCI" `CardHeader`; hactool `xci_header_t`): a
/// signature pattern (0x100), `HEAD` at 0x100, ROM area start page 0 at
/// 0x104, backup area 0xFFFFFFFF at 0x108, ROM size 0xFA (1 GB) at 0x10D,
/// package ID at 0x110, the valid data end page at 0x118, the root HFS0
/// offset (0xF000) at 0x130, its header size at 0x138 and its SHA-256 at
/// 0x140 (with `salt` appended when given), `SelSec` 1 at 0x180; the root
/// HFS0 lists the partitions (their hashed regions are their headers), and
/// the file is padded with 0xFF to a whole page, where the valid data ends.
fn xci(partitions: &[(&str, Hfs0)], salt: Option<u8>) -> Vec<u8> {
    let root_files: Vec<(&str, Vec<u8>, usize)> = partitions
        .iter()
        .map(|(name, fs)| (*name, fs.bytes.clone(), fs.header_size))
        .collect();
    let root = hfs0(&root_files);
    let mut data = vec![0x5au8; 0x100];
    data.resize(XCI_ROOT_OFFSET, 0);
    put(&mut data, 0x100, b"HEAD");
    put_le32(&mut data, 0x108, u32::MAX);
    data[0x10d] = 0xfa;
    put_le64(&mut data, 0x110, 0x1122_3344_5566_7788);
    put_le64(&mut data, 0x130, u64_of(XCI_ROOT_OFFSET));
    put_le64(&mut data, 0x138, u64_of(root.header_size));
    let mut hasher = Sha256::new();
    hasher.update(&root.bytes[..root.header_size]);
    if let Some(salt) = salt {
        hasher.update([salt]);
    }
    put(&mut data, 0x140, &hasher.finalize());
    put_le32(&mut data, 0x180, 1);
    data.extend_from_slice(&root.bytes);
    data.resize(align(data.len(), 0x200), 0xff);
    let last_page = u32_of(data.len() / 0x200 - 1);
    put_le32(&mut data, 0x118, last_page);
    data
}

/// A game card: an update partition with one NCA, an empty normal
/// partition, a secure partition with an NCA and an NSO, and a logo
/// partition with an NCA.
fn game_xci() -> Vec<u8> {
    xci(
        &[
            ("update", partition(&[("aaaa.nca", encrypted_nca(2))])),
            ("normal", partition(&[])),
            (
                "secure",
                partition(&[("bbbb.nca", encrypted_nca(3)), ("main", nso())]),
            ),
            ("logo", partition(&[("cccc.nca", encrypted_nca(4))])),
        ],
        None,
    )
}

#[test]
fn xci_partition_files_are_children_with_the_game_first() {
    let file = game_xci();
    assert_eq!(detected_format(&file), Some(FileFormat::Xci));
    let c = parse(&file, Layout::Xci);
    assert_eq!(
        labels(&c),
        [
            "secure/bbbb.nca",
            "secure/main",
            "logo/cccc.nca",
            "update/aaaa.nca"
        ]
    );
    assert!(c.children[0].opaque);
    assert!(!c.children[1].opaque);
    assert!(has_note(
        &c,
        "Switch gamecard image; ROM size 1 GB; header version 0; flags 0x00; package ID 0x1122334455667788"
    ));
    assert!(has_note(&c, "Root HFS0 at 0xF000; header SHA-256 verified"));
    assert!(has_note(
        &c,
        "header SHA-256 verified; hashed regions verified for 2 of 2"
    ));
    assert!(has_note(&c, "Partition normal at 0x"));
    assert!(has_note(&c, "0 files; header SHA-256 verified"));
    assert!(has_note(
        &c,
        "4 partition files; 1 in a recognized format, classified on their own"
    ));

    // The update partition is first in the root HFS0, right after the root
    // header; its NCA follows the partition's own 0x200-byte header.
    let root_header = 0x200;
    let update = c
        .children
        .iter()
        .find(|child| child.label == "update/aaaa.nca")
        .unwrap();
    assert_eq!(update.offset, XCI_ROOT_OFFSET + root_header + 0x200);

    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Xci);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(payload_has_note(&p, "secure/main: aarch64 (contained NSO)"));
    assert!(matches!(
        metadata(&p, "xci_rom_size"),
        zrax::MetadataValue::String(s) if s == "1 GB"
    ));
}

#[test]
fn xci_root_hash_may_carry_the_china_salt() {
    let file = xci(&[("secure", partition(&[("main", nso())]))], Some(1));
    let c = parse(&file, Layout::Xci);
    assert!(has_note(
        &c,
        "header SHA-256 verified with the China compatibility salt"
    ));
    let other = xci(&[("secure", partition(&[("main", nso())]))], Some(2));
    assert!(has_note(
        &parse(&other, Layout::Xci),
        "header SHA-256 does not match"
    ));
}

#[test]
fn xci_hash_mismatches_are_reported() {
    let mut file = game_xci();
    let c = parse(&file, Layout::Xci);
    let main = c
        .children
        .iter()
        .find(|child| child.label == "secure/main")
        .unwrap()
        .offset;
    file[main + 0x104] ^= 1;
    let c = parse(&file, Layout::Xci);
    assert!(has_note(
        &c,
        "hashed regions verified for 1 of 2; mismatch for main"
    ));
}

#[test]
fn corrupt_xci_images_are_parse_errors() {
    let unknown = xci(&[("extra", partition(&[]))], None);
    assert_eq!(
        parse_error(&unknown, Layout::Xci),
        "Nintendo container parse error: Unknown XCI partition extra"
    );
    let duplicate = xci(&[("logo", partition(&[])), ("logo", partition(&[]))], None);
    assert!(parse_error(&duplicate, Layout::Xci).contains("Duplicate XCI partition logo"));
    let five: Vec<(&str, Hfs0)> = ["update", "normal", "secure", "logo", "logo"]
        .iter()
        .map(|name| (*name, partition(&[])))
        .collect();
    assert!(parse_error(&xci(&five, None), Layout::Xci)
        .contains("Invalid XCI root partition count 5 (at most 4)"));

    let file = game_xci();
    let mut not_hfs0 = file.clone();
    let secure_offset = XCI_ROOT_OFFSET + 0x200 + 0x200 + 0x1000 + 0x200;
    put(&mut not_hfs0, secure_offset, b"PFS0");
    assert!(parse_error(&not_hfs0, Layout::Xci).contains("Missing HFS0 magic"));

    let mut trailing = file.clone();
    trailing.extend_from_slice(&[0x12; 0x200]);
    assert!(parse_error(&trailing, Layout::Xci).contains("after the XCI valid data end"));
    let mut full = file.clone();
    full.extend_from_slice(&[0xff; 0x400]);
    assert_eq!(detected_format(&full), Some(FileFormat::Xci));

    assert!(parse_error(&file[..file.len() - 0x200], Layout::Xci)
        .contains("Truncated XCI: valid data ends at"));

    // Without an HFS0 where the card header points, `HEAD` alone is not
    // recognized.
    let mut moved = file;
    put_le64(&mut moved, 0x130, 0x4000);
    assert_ne!(detected_format(&moved), Some(FileFormat::Xci));
}

// --- Detection and sweeps ---------------------------------------------------

#[test]
fn layouts_report_their_formats_and_strength() {
    assert_eq!(Kind::Nintendo2(Layout::Ncsd).format(), FileFormat::Ncsd);
    assert_eq!(Kind::Nintendo2(Layout::Cia).format(), FileFormat::Cia);
    assert_eq!(Kind::Nintendo2(Layout::Pfs0).format(), FileFormat::Pfs0);
    assert_eq!(Kind::Nintendo2(Layout::Xci).format(), FileFormat::Xci);
    assert!(Kind::Nintendo2(Layout::Cia).is_weak());
    assert!(!Kind::Nintendo2(Layout::Ncsd).is_weak());
    assert_eq!(Kind::Nintendo2(Layout::Xci).label(), "Switch XCI");
    for (format, id) in [
        (FileFormat::Ncsd, "\"ncsd\""),
        (FileFormat::Cia, "\"cia\""),
        (FileFormat::Pfs0, "\"pfs0\""),
        (FileFormat::Xci, "\"xci\""),
    ] {
        assert_eq!(serde_json::to_string(&format).unwrap(), id);
    }
}

#[test]
fn the_ncch_inside_a_cart_does_not_take_the_cart() {
    // A cart image holds NCCH headers at 0x4100 and 0x5100, but its own
    // magic at 0x100 decides.
    assert_eq!(detected_format(&game_card()), Some(FileFormat::Ncsd));
    assert_eq!(detected_format(&ncch(CXI)), Some(FileFormat::N3dsNcch));
    assert_eq!(detected_format(&nso()), Some(FileFormat::Nso));
}

#[test]
fn nintendo_containers_survive_truncation() {
    let card = game_card();
    truncation_sweep(
        &card,
        FileFormat::Ncsd,
        37,
        &[0x200, 0x4000, 0x5000, 0x5200],
    );
    // The NAND partitions end at 0x1400; a longer prefix is a valid image
    // with NAND space after the partitions.
    let nand = nand();
    truncation_sweep(
        &nand[..0x1400],
        FileFormat::Ncsd,
        37,
        &[0x200, 0x800, 0xc00],
    );
    let cia = plain_cia();
    truncation_sweep(
        &cia,
        FileFormat::Cia,
        97,
        &[0x2020, CIA_TMD, CIA_CONTENT, CIA_META],
    );
    let nsp = nsp();
    truncation_sweep(&nsp, FileFormat::Pfs0, 7, &[0x10, 0x70, 0xe0]);
    let game = game_xci();
    truncation_sweep(
        &game,
        FileFormat::Xci,
        211,
        &[0x200, XCI_ROOT_OFFSET, XCI_ROOT_OFFSET + 0x200],
    );
}

#[test]
fn nintendo_containers_survive_byte_mutations() {
    mutation_sweep(&game_card(), 0x100..0x200, 97);
    mutation_sweep(&nand(), 0x100..0x160, 61);
    let cia = plain_cia();
    mutation_sweep(&cia, 0..0x40, 211);
    mutation_sweep(&cia, CIA_TMD..CIA_TMD + 4, 4099);
    mutation_sweep(&cia, CIA_TMD + 0x140..CIA_TMD + 0x210, 4099);
    mutation_sweep(&nsp(), 0..0xe0, 31);
    mutation_sweep(&game_xci(), 0x100..0x1a0, 251);
    mutation_sweep(&game_xci(), XCI_ROOT_OFFSET..XCI_ROOT_OFFSET + 0x140, 4099);
}
