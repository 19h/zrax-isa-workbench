//! Apple II disk images: DOS 3.3 and ProDOS volumes in DOS and ProDOS
//! sector order and 2IMG images, built in the tests from the documented
//! layouts (Beneath Apple DOS chapter 4, ProDOS 8 Technical Reference
//! Manual Appendix B, the 2IMG description): files and boot code as
//! children with 6502 targets, sector order detection and ambiguity,
//! corrupted fields, damage below the catalog or directory, limits, and
//! truncation and mutation sweeps.

use std::borrow::Cow;
use zrax::formats::apple2::{self, Layout, Order};
use zrax::formats::container::{Child, Classify, Container, MAX_COMPONENTS};
use zrax::types::MetadataKey;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const SECTOR: usize = 256;
const SECTORS_PER_TRACK: usize = 16;
const TRACK: usize = SECTOR * SECTORS_PER_TRACK;
const BLOCK: usize = 512;
const DOS_TRACKS: usize = 35;

/// ProDOS 8 Technical Reference Manual Figure B-15: the sector offset and
/// half of block of DOS sectors 0-F (block = 8 * track + offset).
const BLOCK_OFFSET: [usize; 16] = [0, 7, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0, 7];
const BLOCK_HALF: [usize; 16] = [1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 2];

/// A hand-assembled 6502 routine of 20 bytes:
/// `LDA #$01` (A9 01), `STA $0200` (8D 00 02), `LDX #$00` (A2 00),
/// `LDA $0300,X` (BD 00 03), `STA $0400,X` (9D 00 04), `INX` (E8),
/// `BNE` back to the `LDA $0300,X` (D0 F7), `JSR $FDED` (20 ED FD), `RTS`
/// (60).
const CODE_6502: [u8; 20] = [
    0xa9, 0x01, 0x8d, 0x00, 0x02, 0xa2, 0x00, 0xbd, 0x00, 0x03, 0x9d, 0x00, 0x04, 0xe8, 0xd0, 0xf7,
    0x20, 0xed, 0xfd, 0x60,
];

/// `size` bytes of the 6502 routine, repeated.
fn code(size: usize) -> Vec<u8> {
    CODE_6502.iter().cycle().take(size).copied().collect()
}

/// The 256-byte position within a ProDOS-order track of DOS sector `s`.
fn prodos_position(sector: usize) -> usize {
    2 * BLOCK_OFFSET[sector] + BLOCK_HALF[sector] - 1
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
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

fn metadata(c: &Container<'_>, key: &str) -> Option<String> {
    c.metadata
        .iter()
        .find(|entry| entry.key == MetadataKey::Custom(key.to_string()))
        .map(|entry| entry.value.to_string())
}

fn is_6502_code(child: &Child<'_>) -> bool {
    child.classify == Classify::Code
        && !child.opaque
        && child
            .target
            .is_some_and(|target| target.isa == Isa::Mcs6502 && target.bits == 8)
}

fn error_text(data: &[u8], layout: Layout) -> String {
    apple2::parse_container(data, layout)
        .expect_err("does not parse")
        .to_string()
}

// ---------------------------------------------------------------------
// DOS 3.3 fixtures (Beneath Apple DOS pp. 4-2 to 4-12).

/// A DOS 3.3 disk as logical sectors in DOS order: sector `s` of track `t`
/// at `(16 * t + s) * 256`.
struct DosDisk {
    data: Vec<u8>,
}

impl DosDisk {
    fn blank(tracks: usize) -> Self {
        Self {
            data: vec![0; tracks * TRACK],
        }
    }

    fn sector(&mut self, track: usize, sector: usize) -> &mut [u8] {
        let start = (track * SECTORS_PER_TRACK + sector) * SECTOR;
        &mut self.data[start..start + SECTOR]
    }

    fn offset(order: Order, track: usize, sector: usize) -> usize {
        let position = match order {
            Order::Dos => sector,
            Order::ProDos => prodos_position(sector),
        };
        (track * SECTORS_PER_TRACK + position) * SECTOR
    }

    /// The image file in `order`.
    fn image(&self, order: Order) -> Vec<u8> {
        let mut image = vec![0; self.data.len()];
        for track in 0..self.data.len() / TRACK {
            for sector in 0..SECTORS_PER_TRACK {
                let from = (track * SECTORS_PER_TRACK + sector) * SECTOR;
                let to = Self::offset(order, track, sector);
                image[to..to + SECTOR].copy_from_slice(&self.data[from..from + SECTOR]);
            }
        }
        image
    }
}

/// The VTOC at track 17 sector 0 (Beneath Apple DOS p. 4-3): first catalog
/// sector `catalog`, release 3, volume 254, 122 pairs per list, last track
/// allocated 19 going up, `tracks` tracks of 16 sectors of 256 B, and a
/// bitmap with tracks 0 and 17-19 in use.
fn put_vtoc(disk: &mut DosDisk, tracks: usize, catalog: (u8, u8)) {
    let vtoc = disk.sector(17, 0);
    vtoc[0x00] = 0x04;
    vtoc[0x01] = catalog.0;
    vtoc[0x02] = catalog.1;
    vtoc[0x03] = 3;
    vtoc[0x06] = 254;
    vtoc[0x27] = 122;
    vtoc[0x30] = 19;
    vtoc[0x31] = 0x01;
    vtoc[0x34] = u8::try_from(tracks).unwrap();
    vtoc[0x35] = 16;
    vtoc[0x36] = 0x00;
    vtoc[0x37] = 0x01;
    for track in 0..tracks {
        let free = !(track == 0 || (17..=19).contains(&track));
        let bitmap = 0x38 + 4 * track;
        let value = if free { [0xff, 0xff, 0, 0] } else { [0; 4] };
        vtoc[bitmap..bitmap + 4].copy_from_slice(&value);
    }
}

/// The catalog chain INIT writes: track 17 sector 15 down to sector 1,
/// each linking to the next lower sector, sector 1 ending the chain.
fn put_catalog_chain(disk: &mut DosDisk) {
    for sector in 1..16u8 {
        let next = if sector == 1 {
            (0, 0)
        } else {
            (17, sector - 1)
        };
        let catalog = disk.sector(17, usize::from(sector));
        catalog[0x01] = next.0;
        catalog[0x02] = next.1;
    }
}

/// Catalog entry `n` (0-6) of the catalog sector at track 17 `sector`
/// (Beneath Apple DOS p. 4-6): track/sector list at `list`, file type,
/// name in high-bit ASCII padded with 0xA0, length in sectors.
fn put_entry(
    disk: &mut DosDisk,
    sector: usize,
    n: usize,
    list: (u8, u8),
    file_type: u8,
    name: &str,
    sectors: u16,
) {
    let catalog = disk.sector(17, sector);
    let entry = 0x0b + 35 * n;
    catalog[entry] = list.0;
    catalog[entry + 1] = list.1;
    catalog[entry + 2] = file_type;
    catalog[entry + 3..entry + 33].fill(0xa0);
    for (i, b) in name.bytes().enumerate() {
        catalog[entry + 3 + i] = b | 0x80;
    }
    catalog[entry + 0x21..entry + 0x23].copy_from_slice(&sectors.to_le_bytes());
}

/// A track/sector list at `list` (Beneath Apple DOS p. 4-8): next list
/// `next`, sector offset of its first pair `offset`, then the data pairs.
fn put_list(disk: &mut DosDisk, list: (u8, u8), next: (u8, u8), offset: u16, pairs: &[(u8, u8)]) {
    let sector = disk.sector(usize::from(list.0), usize::from(list.1));
    sector[0x01] = next.0;
    sector[0x02] = next.1;
    sector[0x05..0x07].copy_from_slice(&offset.to_le_bytes());
    for (i, pair) in pairs.iter().enumerate() {
        sector[0x0c + 2 * i] = pair.0;
        sector[0x0d + 2 * i] = pair.1;
    }
}

/// Write `bytes` across the data sectors `sectors`, 256 B each.
fn put_data(disk: &mut DosDisk, sectors: &[(u8, u8)], bytes: &[u8]) {
    for (chunk, sector) in bytes.chunks(SECTOR).zip(sectors) {
        disk.sector(usize::from(sector.0), usize::from(sector.1))[..chunk.len()]
            .copy_from_slice(chunk);
    }
}

/// The B file of the sample disk: load address 0x6000, 300 B of 6502 code.
const PROG_LOAD: u16 = 0x6000;
const PROG_SIZE: usize = 300;

/// A formatted 35-track DOS 3.3 disk with boot code at track 0 sector 0
/// (sector count 1, then 255 B of 6502 code) and, in catalog sector 15:
/// 0 `HELLO` (Applesoft, list T18 S15, data T18 S14);
/// 1 `PROG` (binary, locked; list T18 S13, data T18 S12 and S11: load
///   address, length 300, the code);
/// 2 a deleted entry (list track 0xFF);
/// 3 `NOTES` (text; list T19 S15, data T19 S14);
/// 4 never used, which ends the entries.
fn sample_dos_disk() -> DosDisk {
    let mut disk = DosDisk::blank(DOS_TRACKS);
    let boot = disk.sector(0, 0);
    boot[0] = 0x01;
    boot[1..].copy_from_slice(&code(255));
    put_vtoc(&mut disk, DOS_TRACKS, (17, 15));
    put_catalog_chain(&mut disk);
    put_entry(&mut disk, 15, 0, (18, 15), 0x02, "HELLO", 2);
    put_list(&mut disk, (18, 15), (0, 0), 0, &[(18, 14)]);
    // Applesoft: length 6, then `10 PRINT` tokenized.
    put_data(
        &mut disk,
        &[(18, 14)],
        &[0x06, 0x00, 0x07, 0x08, 0x0a, 0x00, 0xba, 0x00],
    );
    put_entry(&mut disk, 15, 1, (18, 13), 0x84, "PROG", 3);
    put_list(&mut disk, (18, 13), (0, 0), 0, &[(18, 12), (18, 11)]);
    let mut binary = PROG_LOAD.to_le_bytes().to_vec();
    binary.extend(u16::try_from(PROG_SIZE).unwrap().to_le_bytes());
    binary.extend(code(PROG_SIZE));
    put_data(&mut disk, &[(18, 12), (18, 11)], &binary);
    put_entry(&mut disk, 15, 2, (0xff, 10), 0x00, "OLD", 2);
    put_entry(&mut disk, 15, 3, (19, 15), 0x00, "NOTES", 2);
    put_list(&mut disk, (19, 15), (0, 0), 0, &[(19, 14)]);
    let text: Vec<u8> = b"HELLO WORLD\r".iter().map(|b| b | 0x80).collect();
    put_data(&mut disk, &[(19, 14)], &text);
    disk
}

fn parse_dos(image: &[u8], order: Order) -> Container<'_> {
    assert_eq!(apple2::detect_weak(image), Some(Layout::Dos33(order)));
    apple2::parse_container(image, Layout::Dos33(order)).expect("parses")
}

#[test]
fn dos_order_images_list_files_by_catalog_order_and_boot_code_last() {
    let image = sample_dos_disk().image(Order::Dos);
    let c = parse_dos(&image, Order::Dos);
    assert_eq!(c.format, FileFormat::Apple2Dos);
    assert_eq!(c.variant, "DOS 3.3, DOS order");
    assert_eq!(c.target, None);
    assert_eq!(c.consumed, image.len());
    assert_eq!(
        labels(&c),
        ["HELLO", "PROG", "NOTES", "Boot code (track 0 sector 0)"]
    );
    let prog = child(&c, "PROG");
    assert!(is_6502_code(prog));
    assert_eq!(prog.data.as_ref(), code(PROG_SIZE));
    // Stored from the first data sector after the 4-byte header, then
    // reassembled with the second sector.
    assert_eq!(prog.offset, (18 * 16 + 12) * SECTOR + 4);
    assert_eq!(prog.stored_size, SECTOR - 4);
    assert_eq!(prog.transform, Some("DOS 3.3 track/sector list"));
    let hello = child(&c, "HELLO");
    assert!(hello.opaque);
    assert_eq!(hello.offset, (18 * 16 + 14) * SECTOR);
    assert_eq!(hello.data.len(), SECTOR);
    assert!(child(&c, "NOTES").opaque);
    let boot = child(&c, "Boot code (track 0 sector 0)");
    assert!(is_6502_code(boot));
    assert_eq!((boot.offset, boot.data.len()), (0, SECTOR));
    assert!(matches!(boot.data, Cow::Borrowed(_)));
    assert!(has_note(
        &c,
        "DOS 3.3 volume 254; 35 tracks of 16 sectors; DOS order"
    ));
    assert!(has_note(
        &c,
        "Catalog: 15 sectors, 3 files; 1 deleted entry ignored"
    ));
    assert!(has_note(&c, "File types: T 1, A 1, B 1; 1 locked"));
    assert!(has_note(
        &c,
        "Sector order from the catalog chain: 15 sectors in DOS order, 2 sectors in ProDOS order"
    ));
    assert!(has_note(&c, "3 files listed: 1 as 6502 code"));
    assert!(has_note(&c, "Boot code: track 0 sector 0 at 0x0 (256 B)"));
    assert_eq!(
        metadata(&c, "apple2_load_address_1").as_deref(),
        Some("0x6000 (B file, 300 B)")
    );
    assert_eq!(metadata(&c, "apple2_dos_volume").as_deref(), Some("254"));
    assert_eq!(
        metadata(&c, "apple2_catalog_sectors").as_deref(),
        Some("15")
    );
    assert_eq!(metadata(&c, "apple2_file_count").as_deref(), Some("3"));
}

#[test]
fn prodos_order_dos_images_are_found_from_the_longer_catalog_chain() {
    let disk = sample_dos_disk();
    let image = disk.image(Order::ProDos);
    let c = parse_dos(&image, Order::ProDos);
    assert_eq!(c.variant, "DOS 3.3, ProDOS order");
    assert!(has_note(
        &c,
        "Sector order from the catalog chain: 2 sectors in DOS order, 15 sectors in ProDOS order"
    ));
    let prog = child(&c, "PROG");
    assert_eq!(prog.data.as_ref(), code(PROG_SIZE));
    assert_eq!(
        prog.offset,
        DosDisk::offset(Order::ProDos, 18, 12) + 4,
        "stored coordinates follow the file's sector order"
    );
    // The same files as in DOS order, with the same bytes.
    let dos = disk.image(Order::Dos);
    let in_dos_order = parse_dos(&dos, Order::Dos);
    for (a, b) in c.children.iter().zip(&in_dos_order.children) {
        assert_eq!(a.label, b.label);
        assert_eq!(a.data, b.data);
    }
}

#[test]
fn dos_images_classify_as_6502_from_the_first_code_file() {
    let image = sample_dos_disk().image(Order::Dos);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Apple2Dos);
    assert_eq!(p.format.variant_name.as_deref(), Some("DOS 3.3, DOS order"));
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert_eq!(p.primary.bitwidth, 8);
    let labels: Vec<_> = p.slices.iter().filter_map(|s| s.label.clone()).collect();
    assert_eq!(
        labels,
        ["HELLO", "PROG", "NOTES", "Boot code (track 0 sector 0)"]
    );
    let prog = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("PROG"))
        .unwrap();
    assert_eq!(prog.isa, Isa::Mcs6502);
    let decoded = prog.decoded.as_ref().expect("reassembled");
    assert_eq!(decoded.size, PROG_SIZE as u64);
    let hello = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("HELLO"))
        .unwrap();
    assert!(matches!(hello.isa, Isa::Unknown(_)));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message
            == "Primary ISA selected from PROG; other components are listed separately"));
    assert_eq!(
        serde_json::to_value(p.format.format).unwrap(),
        serde_json::json!("apple2dos")
    );
}

#[test]
fn disks_without_code_files_or_boot_code_have_no_isa() {
    let mut disk = DosDisk::blank(DOS_TRACKS);
    put_vtoc(&mut disk, DOS_TRACKS, (17, 15));
    put_catalog_chain(&mut disk);
    put_entry(&mut disk, 15, 0, (18, 15), 0x00, "TEXT", 2);
    put_list(&mut disk, (18, 15), (0, 0), 0, &[(18, 14)]);
    let image = disk.image(Order::Dos);
    let c = parse_dos(&image, Order::Dos);
    assert_eq!(labels(&c), ["TEXT"]);
    assert!(has_note(
        &c,
        "No boot code: track 0 sector 0 is filled with 0x00"
    ));
    let p = classify(&image);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
}

#[test]
fn forty_track_disks_are_dos_images() {
    let mut disk = DosDisk::blank(40);
    put_vtoc(&mut disk, 40, (17, 15));
    put_catalog_chain(&mut disk);
    put_entry(&mut disk, 15, 0, (39, 15), 0x04, "HIGH", 2);
    put_list(&mut disk, (39, 15), (0, 0), 0, &[(39, 14)]);
    let mut binary = vec![0x00, 0x08, 0x14, 0x00];
    binary.extend(code(20));
    put_data(&mut disk, &[(39, 14)], &binary);
    let image = disk.image(Order::Dos);
    assert_eq!(image.len(), 163_840);
    let c = parse_dos(&image, Order::Dos);
    let high = child(&c, "HIGH");
    assert!(is_6502_code(high));
    assert_eq!(high.data.as_ref(), code(20));
    assert!(matches!(high.data, Cow::Borrowed(_)));
    assert_eq!(metadata(&c, "apple2_tracks").as_deref(), Some("40"));
}

/// A disk whose one catalog sector (track 17 sector 15) and only file
/// (list T18 S15, data T18 S0) sit where both orders store them.
fn ambiguous_dos_disk() -> DosDisk {
    let mut disk = DosDisk::blank(DOS_TRACKS);
    put_vtoc(&mut disk, DOS_TRACKS, (17, 15));
    put_entry(&mut disk, 15, 0, (18, 15), 0x04, "SAME", 2);
    put_list(&mut disk, (18, 15), (0, 0), 0, &[(18, 0)]);
    let mut binary = vec![0x00, 0x03, 0x14, 0x00];
    binary.extend(code(20));
    put_data(&mut disk, &[(18, 0)], &binary);
    disk
}

#[test]
fn catalogs_that_validate_equally_in_both_orders_are_ambiguous() {
    let image = ambiguous_dos_disk().image(Order::Dos);
    assert_eq!(apple2::detect_weak(&image), Some(Layout::Dos33Ambiguous));
    let c = apple2::parse_container(&image, Layout::Dos33Ambiguous).unwrap();
    assert_eq!(c.variant, "DOS 3.3, ambiguous sector order");
    assert!(c.children.is_empty());
    assert!(has_note(
        &c,
        "1 sector in DOS order, 1 sector in ProDOS order"
    ));
    assert!(has_note(&c, "no files or boot code are extracted"));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Apple2Dos);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.slices.is_empty());
    // An unambiguous image is not ambiguous.
    let sample = sample_dos_disk().image(Order::Dos);
    assert!(error_text(&sample, Layout::Dos33Ambiguous)
        .contains("the catalog does not validate equally in both sector orders"));
}

#[test]
fn vtoc_fields_must_be_those_dos_33_writes() {
    let cases: [(usize, u8, &str); 6] = [
        (
            0x27,
            121,
            "Invalid VTOC at 0x11000: 121 track/sector pairs per list, 122 expected",
        ),
        (
            0x37,
            0x02,
            "Invalid VTOC at 0x11000: 512 B per sector, 256 B expected",
        ),
        (
            0x35,
            13,
            "Invalid VTOC at 0x11000: 13 sectors per track, 16 expected",
        ),
        (
            0x34,
            40,
            "Invalid VTOC at 0x11000: 40 tracks, the image holds 35",
        ),
        (
            0x03,
            2,
            "Unsupported DOS release 2 in the VTOC at 0x11000: DOS 3.3 writes 3",
        ),
        (
            0x01,
            35,
            "Invalid VTOC at 0x11000: first catalog sector at track 35 sector 15",
        ),
    ];
    for (field, value, message) in cases {
        let mut disk = sample_dos_disk();
        disk.sector(17, 0)[field] = value;
        let image = disk.image(Order::Dos);
        assert_eq!(apple2::detect_weak(&image), None, "{message}");
        assert_eq!(
            error_text(&image, Layout::Dos33(Order::Dos)),
            format!("Apple II disk image parse error: {message}")
        );
    }
    let mut disk = sample_dos_disk();
    disk.sector(17, 0)[0x02] = 0;
    disk.sector(17, 0)[0x01] = 17;
    assert!(
        error_text(&disk.image(Order::Dos), Layout::Dos33(Order::Dos))
            .contains("first catalog sector at track 17 sector 0")
    );
}

#[test]
fn catalog_chains_must_end_without_loops_or_links_off_the_disk() {
    let mut looped = sample_dos_disk();
    looped.sector(17, 2)[0x02] = 15;
    assert!(
        error_text(&looped.image(Order::Dos), Layout::Dos33(Order::Dos))
            .contains("Invalid catalog chain: track 17 sector 15 is reached twice")
    );
    let mut outside = sample_dos_disk();
    outside.sector(17, 5)[0x01] = 99;
    assert!(
        error_text(&outside.image(Order::Dos), Layout::Dos33(Order::Dos))
            .contains("Invalid catalog link to track 99 sector 4 after 11 catalog sectors")
    );
    let mut to_vtoc = sample_dos_disk();
    to_vtoc.sector(17, 3)[0x02] = 0;
    assert!(
        error_text(&to_vtoc.image(Order::Dos), Layout::Dos33(Order::Dos))
            .contains("Invalid catalog link to track 17 sector 0")
    );
    let mut entry = sample_dos_disk();
    put_entry(&mut entry, 15, 3, (35, 15), 0x00, "NOTES", 2);
    assert!(
        error_text(&entry.image(Order::Dos), Layout::Dos33(Order::Dos)).contains(
            "Invalid catalog entry 4 in track 17 sector 15: its track/sector list is at track 35 \
         sector 15"
        )
    );
    // The chain is longer in DOS order, so the short chain the same
    // bytes give in ProDOS order does not make them a ProDOS-order image.
    for damaged in [looped, outside, to_vtoc, entry] {
        let image = damaged.image(Order::Dos);
        assert_eq!(apple2::detect_weak(&image), None);
    }
}

#[test]
fn a_catalog_broken_after_two_sectors_is_read_in_the_order_where_it_validates() {
    // The link of sector 14 leaves the disk, so the DOS-order chain stops
    // after two sectors, as long as the chain the same bytes give in
    // ProDOS order (assumption A4 in docs/apple2.md).
    let mut disk = sample_dos_disk();
    disk.sector(17, 14)[0x01] = 99;
    let image = disk.image(Order::Dos);
    assert_eq!(
        apple2::detect_weak(&image),
        Some(Layout::Dos33(Order::ProDos))
    );
    let c = apple2::parse_container(&image, Layout::Dos33(Order::ProDos)).unwrap();
    assert!(has_note(
        &c,
        "2 sectors in DOS order, 2 sectors in ProDOS order; it validates only in ProDOS order"
    ));
}

#[test]
fn track_sector_list_damage_is_noted_and_keeps_the_sectors_before_it() {
    let mut disk = sample_dos_disk();
    // HELLO: a second data pair off the disk. NOTES: its list links to
    // PROG's list, a cross-link.
    disk.sector(18, 15)[0x0e] = 36;
    disk.sector(19, 15)[0x01] = 18;
    disk.sector(19, 15)[0x02] = 13;
    let image = disk.image(Order::Dos);
    let c = parse_dos(&image, Order::Dos);
    assert!(has_note(
        &c,
        "HELLO: pair 2 of the track/sector list at track 18 sector 15 names track 36 sector 0; \
         the sectors before it are listed"
    ));
    assert!(has_note(
        &c,
        "NOTES: the track/sector list at track 18 sector 13 was already read (a loop or a \
         cross-link)"
    ));
    assert_eq!(child(&c, "HELLO").data.len(), SECTOR);
    assert_eq!(child(&c, "NOTES").data.len(), SECTOR);
}

#[test]
fn binary_headers_bound_the_code_and_empty_ones_are_opaque() {
    let mut long = sample_dos_disk();
    long.sector(18, 12)[2..4].copy_from_slice(&1000u16.to_le_bytes());
    let image = long.image(Order::Dos);
    let c = parse_dos(&image, Order::Dos);
    assert!(has_note(
        &c,
        "B file PROG: the header length 1000 B exceeds the 508 B stored after the header"
    ));
    assert_eq!(child(&c, "PROG").data.len(), 508);
    let mut empty = sample_dos_disk();
    empty.sector(18, 12)[2..4].copy_from_slice(&0u16.to_le_bytes());
    let image = empty.image(Order::Dos);
    let c = parse_dos(&image, Order::Dos);
    assert!(child(&c, "PROG").opaque);
    assert!(has_note(
        &c,
        "B file PROG: the header length is 0 B; listed as opaque"
    ));
    let mut sparse = sample_dos_disk();
    put_list(&mut sparse, (18, 13), (0, 0), 0, &[(0, 0), (18, 11)]);
    let image = sparse.image(Order::Dos);
    let c = parse_dos(&image, Order::Dos);
    assert!(child(&c, "PROG").opaque);
    assert!(has_note(
        &c,
        "B file PROG: the first data sector is missing"
    ));
}

#[test]
fn dos_disks_with_a_prodos_volume_directory_are_noted_as_hybrid() {
    let mut disk = sample_dos_disk();
    // ProDOS block 2 is DOS sectors 11 (first half) and 10 of track 0.
    let volume = sample_prodos_volume(280);
    disk.sector(0, 11)
        .copy_from_slice(&volume.blocks[2][..SECTOR]);
    disk.sector(0, 10)
        .copy_from_slice(&volume.blocks[2][SECTOR..]);
    // Block 3, the second volume directory block: DOS sectors 9 and 8.
    disk.sector(0, 9)
        .copy_from_slice(&volume.blocks[3][..SECTOR]);
    disk.sector(0, 8)
        .copy_from_slice(&volume.blocks[3][SECTOR..]);
    let image = disk.image(Order::Dos);
    let c = parse_dos(&image, Order::Dos);
    assert!(has_note(
        &c,
        "The disk also holds a ProDOS volume directory that validates (a hybrid disk)"
    ));
}

// ---------------------------------------------------------------------
// ProDOS fixtures (ProDOS 8 Technical Reference Manual Appendix B).

/// A ProDOS volume as 512-byte blocks.
struct ProDosVolume {
    blocks: Vec<[u8; BLOCK]>,
}

/// A directory entry (TRM B.2.4).
struct ProEntry<'n> {
    storage: u8,
    name: &'n str,
    file_type: u8,
    key: u16,
    blocks_used: u16,
    eof: u32,
    aux: u16,
    header: u16,
}

impl ProDosVolume {
    fn new(blocks: usize) -> Self {
        Self {
            blocks: vec![[0; BLOCK]; blocks],
        }
    }

    /// The image file in `order`; DOS order needs whole 16-sector tracks
    /// (TRM Figure B-15).
    fn image(&self, order: Order) -> Vec<u8> {
        match order {
            Order::ProDos => self.blocks.concat(),
            Order::Dos => {
                let mut image = vec![0; self.blocks.len() * BLOCK];
                for track in 0..self.blocks.len() / 8 {
                    for sector in 0..SECTORS_PER_TRACK {
                        let block = &self.blocks[8 * track + BLOCK_OFFSET[sector]];
                        let half = (BLOCK_HALF[sector] - 1) * SECTOR;
                        let at = (track * SECTORS_PER_TRACK + sector) * SECTOR;
                        image[at..at + SECTOR].copy_from_slice(&block[half..half + SECTOR]);
                    }
                }
                image
            }
        }
    }

    /// Previous and next block pointers of a directory block (TRM B.2.1).
    fn put_links(&mut self, block: usize, previous: u16, next: u16) {
        self.blocks[block][0..2].copy_from_slice(&previous.to_le_bytes());
        self.blocks[block][2..4].copy_from_slice(&next.to_le_bytes());
    }

    /// The volume directory header in block 2 (TRM B.2.2): storage type
    /// 0xF and name, entry length 0x27, 13 entries per block, the file
    /// count, bitmap pointer and total blocks.
    fn put_volume_header(&mut self, name: &str, file_count: u16, bitmap: u16, total: u16) {
        let header = &mut self.blocks[2][4..4 + 0x27];
        header[0] = 0xf0 | u8::try_from(name.len()).unwrap();
        header[1..1 + name.len()].copy_from_slice(name.as_bytes());
        header[0x1f] = 0x27;
        header[0x20] = 0x0d;
        header[0x21..0x23].copy_from_slice(&file_count.to_le_bytes());
        header[0x23..0x25].copy_from_slice(&bitmap.to_le_bytes());
        header[0x25..0x27].copy_from_slice(&total.to_le_bytes());
    }

    /// A subdirectory header at the start of `block` (TRM B.2.3): storage
    /// type 0xE and name, the reserved byte 0x75, entry length 0x27, 13 per
    /// block, the file count, and the parent's block, entry number and
    /// entry length 0x27.
    fn put_subdirectory_header(
        &mut self,
        block: usize,
        name: &str,
        file_count: u16,
        parent: u16,
        number: u8,
    ) {
        let header = &mut self.blocks[block][4..4 + 0x27];
        header[0] = 0xe0 | u8::try_from(name.len()).unwrap();
        header[1..1 + name.len()].copy_from_slice(name.as_bytes());
        header[0x10] = 0x75;
        header[0x1f] = 0x27;
        header[0x20] = 0x0d;
        header[0x21..0x23].copy_from_slice(&file_count.to_le_bytes());
        header[0x23..0x25].copy_from_slice(&parent.to_le_bytes());
        header[0x25] = number;
        header[0x26] = 0x27;
    }

    /// The entry in slot `slot` (from 1; slot 1 of a key block is the
    /// header) of directory `block`.
    fn put_entry(&mut self, block: usize, slot: usize, entry: &ProEntry<'_>) {
        let start = 4 + (slot - 1) * 0x27;
        let fields = &mut self.blocks[block][start..start + 0x27];
        fields[0] = entry.storage << 4 | u8::try_from(entry.name.len()).unwrap();
        fields[1..1 + entry.name.len()].copy_from_slice(entry.name.as_bytes());
        fields[0x10] = entry.file_type;
        fields[0x11..0x13].copy_from_slice(&entry.key.to_le_bytes());
        fields[0x13..0x15].copy_from_slice(&entry.blocks_used.to_le_bytes());
        fields[0x15..0x18].copy_from_slice(&entry.eof.to_le_bytes()[..3]);
        fields[0x1e] = 0xe3;
        fields[0x1f..0x21].copy_from_slice(&entry.aux.to_le_bytes());
        fields[0x25..0x27].copy_from_slice(&entry.header.to_le_bytes());
    }

    /// Pointer `i` of an index block: low byte at `i`, high byte at
    /// `256 + i`.
    fn put_pointer(&mut self, block: usize, i: usize, value: u16) {
        let [low, high] = value.to_le_bytes();
        self.blocks[block][i] = low;
        self.blocks[block][256 + i] = high;
    }

    fn put_bytes(&mut self, block: usize, bytes: &[u8]) {
        self.blocks[block][..bytes.len()].copy_from_slice(bytes);
    }
}

/// Load address of `GAME` (aux type) and of the data fork of `FORKED`.
const GAME_LOAD: u16 = 0x0800;
const GAME_SIZE: usize = 700;
const FORKED_LOAD: u16 = 0x4000;
/// `BIG` is a tree file of 128 KiB + 1 B.
const BIG_SIZE: usize = 0x2_0001;

/// A ProDOS volume `ZRAX` of `total` blocks:
/// - blocks 0-1: loader (512 B of 6502 code, then zeros);
/// - blocks 2-3: volume directory; block 6: bitmap;
/// - `PRODOS`: SYS seedling, block 7, 100 B of code;
/// - `GAME`: BIN sapling, index block 8, data blocks 9 and 11, aux 0x0800;
/// - a deleted entry that keeps its name length (`OLD`);
/// - `DOCS`: subdirectory, key block 12, holding `README` (TXT seedling,
///   block 15) and `BIG` (typeless tree, master index 16, index 17, data
///   block 18, then sparse);
/// - `FORKED`: extended BIN file, key block 13: data fork seedling block 19
///   (50 B of code), resource fork seedling block 20 (30 B);
/// - `EMPTY`: a typeless seedling of 0 B in block 14.
fn sample_prodos_volume(total: u16) -> ProDosVolume {
    sample_prodos_volume_with(total, BIG_SIZE)
}

/// The sample volume with `BIG` cut to `big_size` bytes, which keeps the
/// mutation sweeps fast.
fn sample_prodos_volume_with(total: u16, big_size: usize) -> ProDosVolume {
    let mut v = ProDosVolume::new(usize::from(total));
    v.put_bytes(0, &code(BLOCK));
    v.put_links(2, 0, 3);
    v.put_links(3, 2, 0);
    v.put_volume_header("ZRAX", 5, 6, total);
    let prodos = ProEntry {
        storage: 1,
        name: "PRODOS",
        file_type: 0xff,
        key: 7,
        blocks_used: 1,
        eof: 100,
        aux: 0,
        header: 2,
    };
    v.put_entry(2, 2, &prodos);
    v.put_bytes(7, &code(100));
    v.put_entry(
        2,
        3,
        &ProEntry {
            storage: 2,
            name: "GAME",
            file_type: 0x06,
            key: 8,
            blocks_used: 3,
            eof: u32::try_from(GAME_SIZE).unwrap(),
            aux: GAME_LOAD,
            header: 2,
        },
    );
    v.put_pointer(8, 0, 9);
    v.put_pointer(8, 1, 11);
    let game = code(GAME_SIZE);
    v.put_bytes(9, &game[..BLOCK]);
    v.put_bytes(11, &game[BLOCK..]);
    // A deleted entry: storage type 0, name length left at 3.
    v.put_entry(
        2,
        4,
        &ProEntry {
            storage: 0,
            name: "OLD",
            file_type: 0x04,
            key: 21,
            blocks_used: 1,
            eof: 10,
            aux: 0,
            header: 2,
        },
    );
    v.put_entry(
        2,
        5,
        &ProEntry {
            storage: 0xd,
            name: "DOCS",
            file_type: 0x0f,
            key: 12,
            blocks_used: 1,
            eof: 512,
            aux: 0,
            header: 2,
        },
    );
    v.put_links(12, 0, 0);
    v.put_subdirectory_header(12, "DOCS", 2, 2, 5);
    v.put_entry(
        12,
        2,
        &ProEntry {
            storage: 1,
            name: "README",
            file_type: 0x04,
            key: 15,
            blocks_used: 1,
            eof: 20,
            aux: 0,
            header: 12,
        },
    );
    v.put_bytes(15, b"ZRAX PRODOS FIXTURE\r");
    v.put_entry(
        12,
        3,
        &ProEntry {
            storage: 3,
            name: "BIG",
            file_type: 0x00,
            key: 16,
            blocks_used: 3,
            eof: u32::try_from(big_size).unwrap(),
            aux: 0,
            header: 12,
        },
    );
    v.put_pointer(16, 0, 17);
    v.put_pointer(17, 0, 18);
    v.put_bytes(18, &[0xab; BLOCK]);
    v.put_entry(
        3,
        1,
        &ProEntry {
            storage: 5,
            name: "FORKED",
            file_type: 0x06,
            key: 13,
            blocks_used: 3,
            eof: 512,
            aux: FORKED_LOAD,
            header: 2,
        },
    );
    // Extended key block: data fork entry at 0x000, resource fork at
    // 0x100: storage type, key block, blocks used, EOF.
    v.put_bytes(13, &[1, 19, 0, 1, 0, 50, 0, 0]);
    v.blocks[13][0x100..0x108].copy_from_slice(&[1, 20, 0, 1, 0, 30, 0, 0]);
    v.put_bytes(19, &code(50));
    v.put_bytes(20, &[0x5a; 30]);
    v.put_entry(
        3,
        2,
        &ProEntry {
            storage: 1,
            name: "EMPTY",
            file_type: 0x00,
            key: 14,
            blocks_used: 1,
            eof: 0,
            aux: 0,
            header: 2,
        },
    );
    v
}

const PRODOS_LABELS: [&str; 8] = [
    "/ZRAX/PRODOS",
    "/ZRAX/GAME",
    "/ZRAX/DOCS/README",
    "/ZRAX/DOCS/BIG",
    "/ZRAX/FORKED",
    "/ZRAX/FORKED (resource fork)",
    "/ZRAX/EMPTY",
    "Boot code (blocks 0 and 1)",
];

fn parse_prodos(image: &[u8], order: Order) -> Container<'_> {
    assert_eq!(apple2::detect_weak(image), Some(Layout::ProDos(order)));
    apple2::parse_container(image, Layout::ProDos(order)).expect("parses")
}

/// The expected bytes of `BIG`: block 18, then zeros to the EOF.
fn big_contents() -> Vec<u8> {
    let mut bytes = vec![0xab; BLOCK];
    bytes.resize(BIG_SIZE, 0);
    bytes
}

#[test]
fn prodos_volumes_list_files_by_path_with_code_targets() {
    let image = sample_prodos_volume(32).image(Order::ProDos);
    let c = parse_prodos(&image, Order::ProDos);
    assert_eq!(c.format, FileFormat::ProDos);
    assert_eq!(c.variant, "ProDOS, ProDOS order");
    assert_eq!(labels(&c), PRODOS_LABELS);
    let system = child(&c, "/ZRAX/PRODOS");
    assert!(is_6502_code(system));
    assert_eq!(
        (system.offset, system.data.as_ref()),
        (7 * BLOCK, &code(100)[..])
    );
    assert!(matches!(system.data, Cow::Borrowed(_)));
    let game = child(&c, "/ZRAX/GAME");
    assert!(is_6502_code(game));
    assert_eq!(game.data.as_ref(), code(GAME_SIZE));
    assert_eq!((game.offset, game.stored_size), (9 * BLOCK, BLOCK));
    assert_eq!(game.transform, Some("ProDOS index blocks"));
    let readme = child(&c, "/ZRAX/DOCS/README");
    assert!(readme.opaque);
    assert_eq!(readme.data.as_ref(), b"ZRAX PRODOS FIXTURE\r");
    let big = child(&c, "/ZRAX/DOCS/BIG");
    assert!(big.opaque);
    assert_eq!(big.data.as_ref(), big_contents());
    assert_eq!((big.offset, big.stored_size), (18 * BLOCK, BLOCK));
    let forked = child(&c, "/ZRAX/FORKED");
    assert!(is_6502_code(forked));
    assert_eq!(forked.data.as_ref(), code(50));
    let resource = child(&c, "/ZRAX/FORKED (resource fork)");
    assert!(resource.opaque);
    assert_eq!(resource.data.as_ref(), [0x5a; 30]);
    let empty = child(&c, "/ZRAX/EMPTY");
    assert!(empty.opaque);
    assert_eq!(empty.data.as_ref(), b"");
    assert_eq!((empty.offset, empty.transform), (14 * BLOCK, None));
    let boot = child(&c, "Boot code (blocks 0 and 1)");
    assert!(is_6502_code(boot));
    assert_eq!((boot.offset, boot.data.len()), (0, 2 * BLOCK));
    assert!(has_note(
        &c,
        "ProDOS volume /ZRAX; 32 blocks of 512 B; ProDOS order"
    ));
    assert!(has_note(
        &c,
        "Directory walk: 2 directories, volume directory included"
    ));
    assert!(has_note(&c, "7 files listed: 3 as 6502 code"));
    assert_eq!(
        metadata(&c, "apple2_load_address_0").as_deref(),
        Some("0x2000 (SYS file, 100 B)")
    );
    assert_eq!(
        metadata(&c, "apple2_load_address_1").as_deref(),
        Some("0x0800 (BIN file, 700 B)")
    );
    assert_eq!(
        metadata(&c, "apple2_load_address_4").as_deref(),
        Some("0x4000 (BIN file, 50 B)")
    );
    assert_eq!(metadata(&c, "apple2_volume_name").as_deref(), Some("ZRAX"));
    assert_eq!(metadata(&c, "apple2_total_blocks").as_deref(), Some("32"));
}

#[test]
fn prodos_volumes_in_dos_order_read_blocks_from_two_sectors() {
    let volume = sample_prodos_volume(280);
    let image = volume.image(Order::Dos);
    let c = parse_prodos(&image, Order::Dos);
    assert_eq!(c.variant, "ProDOS, DOS order");
    assert_eq!(labels(&c), PRODOS_LABELS);
    // Block 7 is DOS sectors 1 (first half) and 15 of track 0; the 100 B
    // file lies in the first.
    let system = child(&c, "/ZRAX/PRODOS");
    assert_eq!(system.data.as_ref(), code(100));
    assert_eq!((system.offset, system.stored_size), (SECTOR, 100));
    assert!(matches!(system.data, Cow::Borrowed(_)));
    // The forked file's data fork is block 19, DOS sectors 5 and 4 of
    // track 2: reassembled from 256 B at the first.
    let readme = child(&c, "/ZRAX/DOCS/README");
    assert_eq!(readme.data.as_ref(), b"ZRAX PRODOS FIXTURE\r");
    let game = child(&c, "/ZRAX/GAME");
    assert_eq!(game.data.as_ref(), code(GAME_SIZE));
    assert_eq!(game.transform, Some("ProDOS index blocks"));
    // Block 9 is DOS sectors 13 and 12 of track 1.
    assert_eq!(
        (game.offset, game.stored_size),
        (TRACK + 13 * SECTOR, SECTOR)
    );
    assert_eq!(child(&c, "/ZRAX/DOCS/BIG").data.as_ref(), big_contents());
    let boot = child(&c, "Boot code (blocks 0 and 1)");
    assert_eq!(&boot.data[..BLOCK], code(BLOCK));
    let in_prodos_order = volume.image(Order::ProDos);
    let other = parse_prodos(&in_prodos_order, Order::ProDos);
    for (a, b) in c.children.iter().zip(&other.children) {
        assert_eq!((&a.label, &a.data), (&b.label, &b.data));
    }
}

#[test]
fn prodos_volumes_classify_as_6502_from_the_system_file() {
    let image = sample_prodos_volume(32).image(Order::ProDos);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::ProDos);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    let labels: Vec<_> = p.slices.iter().filter_map(|s| s.label.clone()).collect();
    assert_eq!(labels, PRODOS_LABELS);
    let big = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("/ZRAX/DOCS/BIG"))
        .unwrap();
    assert_eq!((big.offset, big.size), (18 * BLOCK as u64, BLOCK as u64));
    assert_eq!(big.decoded.as_ref().map(|d| d.size), Some(BIG_SIZE as u64));
    assert_eq!(
        serde_json::to_value(p.format.format).unwrap(),
        serde_json::json!("prodos")
    );
}

#[test]
fn volume_directory_headers_must_validate() {
    type Damage = fn(&mut ProDosVolume);
    let cases: [(Damage, &str); 7] = [
        (
            |v| v.put_links(2, 1, 3),
            "Invalid volume directory header in block 2 at 0x400: previous block pointer 1, 0 \
             expected",
        ),
        (
            |v| v.blocks[2][4] = 0xe4,
            "Invalid volume directory header in block 2 at 0x400: storage type 0xE, 0xF expected",
        ),
        (
            |v| v.blocks[2][5] = b'1',
            "Invalid volume directory header in block 2 at 0x400: volume name '1RAX'",
        ),
        (
            |v| v.blocks[2][4 + 0x20] = 14,
            "Invalid volume directory header in block 2 at 0x400: entry length 0x27 and 14 \
             entries per block do not fit a block",
        ),
        (
            |v| v.put_volume_header("ZRAX", 5, 6, 33),
            "Invalid volume directory header in block 2 at 0x400: 33 total blocks; the image \
             holds 32",
        ),
        (
            |v| v.put_volume_header("ZRAX", 5, 2, 32),
            "Invalid volume directory header in block 2 at 0x400: bitmap pointer 2 outside \
             blocks 3-31",
        ),
        (
            |v| v.put_volume_header("ZRAX", 4, 6, 32),
            "Invalid volume directory: file count 4, 5 active entries",
        ),
    ];
    for (damage, message) in cases {
        let mut volume = sample_prodos_volume(32);
        damage(&mut volume);
        let image = volume.image(Order::ProDos);
        assert_eq!(apple2::detect_weak(&image), None, "{message}");
        assert_eq!(
            error_text(&image, Layout::ProDos(Order::ProDos)),
            format!("Apple II disk image parse error: {message}")
        );
    }
}

#[test]
fn volume_directory_chains_and_entries_must_validate() {
    let mut looped = sample_prodos_volume(32);
    looped.put_links(3, 2, 2);
    assert!(
        error_text(&looped.image(Order::ProDos), Layout::ProDos(Order::ProDos)).contains(
            "Invalid volume directory: block 2 is already part of a directory (a loop or a \
         cross-link)"
        )
    );
    let mut previous = sample_prodos_volume(32);
    previous.put_links(3, 5, 0);
    assert!(error_text(
        &previous.image(Order::ProDos),
        Layout::ProDos(Order::ProDos)
    )
    .contains("block 3 names block 5 as its predecessor, not 2"));
    let mut storage = sample_prodos_volume(32);
    storage.blocks[2][4 + 0x27] = 0xe6;
    assert!(
        error_text(&storage.image(Order::ProDos), Layout::ProDos(Order::ProDos))
            .contains("entry 2 of block 2 has storage type 0xE")
    );
    let mut key = sample_prodos_volume(32);
    key.blocks[2][4 + 0x27 + 0x11] = 40;
    assert!(
        error_text(&key.image(Order::ProDos), Layout::ProDos(Order::ProDos))
            .contains("entry 2 of block 2 has name length 6 and key block 40")
    );
    let mut outside = sample_prodos_volume(32);
    outside.put_links(3, 2, 99);
    assert!(
        error_text(&outside.image(Order::ProDos), Layout::ProDos(Order::ProDos))
            .contains("the chain leads to block 99, outside the volume")
    );
}

#[test]
fn damage_below_the_volume_directory_is_noted() {
    let mut v = sample_prodos_volume(32);
    // GAME's second data pointer leaves the volume; DOCS's header names
    // another parent; BIG's master index is GAME's index block.
    v.put_pointer(8, 1, 77);
    v.blocks[12][4 + 0x25] = 9;
    v.put_entry(
        12,
        3,
        &ProEntry {
            storage: 3,
            name: "BIG",
            file_type: 0x00,
            key: 8,
            blocks_used: 3,
            eof: u32::try_from(BIG_SIZE).unwrap(),
            aux: 0,
            header: 12,
        },
    );
    let image = v.image(Order::ProDos);
    let c = parse_prodos(&image, Order::ProDos);
    assert!(has_note(
        &c,
        "/ZRAX/GAME: block pointer 77 is outside the volume; not listed"
    ));
    assert!(has_note(
        &c,
        "/ZRAX/DOCS: the directory header names entry 9 of block 2 as its parent, not entry 5 of \
         block 2"
    ));
    assert!(has_note(
        &c,
        "/ZRAX/DOCS/BIG: block 8 is already in use as a directory or index block"
    ));
    assert!(!labels(&c).contains(&"/ZRAX/GAME".to_string()));
    let mut looped = sample_prodos_volume(32);
    looped.blocks[2][4 + 4 * 0x27 + 0x11] = 2;
    let image = looped.image(Order::ProDos);
    let c = parse_prodos(&image, Order::ProDos);
    assert!(has_note(
        &c,
        "/ZRAX/DOCS: the directory header has storage type 0xF, 0xE expected; not walked"
    ));
}

#[test]
fn volumes_with_more_files_than_components_are_cut_with_a_note() {
    // 4100 seedling entries sharing one key block, 13 per directory block
    // after the header.
    let files = MAX_COMPONENTS + 4;
    let directory_blocks = div_round_up(files + 1, 13);
    let total = 2 + directory_blocks + 2;
    let mut v = ProDosVolume::new(total);
    let data_block = total - 1;
    v.put_bytes(data_block, &code(64));
    for i in 0..directory_blocks {
        let block = 2 + i;
        let previous = if i == 0 { 0 } else { block - 1 };
        let next = if i + 1 == directory_blocks {
            0
        } else {
            block + 1
        };
        v.put_links(
            block,
            u16::try_from(previous).unwrap(),
            u16::try_from(next).unwrap(),
        );
    }
    v.put_volume_header(
        "MANY",
        u16::try_from(files).unwrap(),
        u16::try_from(total - 2).unwrap(),
        u16::try_from(total).unwrap(),
    );
    for n in 0..files {
        let slot = n + 1;
        let entry = ProEntry {
            storage: 1,
            name: "F",
            file_type: 0x06,
            key: u16::try_from(data_block).unwrap(),
            blocks_used: 1,
            eof: 64,
            aux: 0x0300,
            header: 2,
        };
        v.put_entry(2 + slot / 13, slot % 13 + 1, &entry);
    }
    let image = v.image(Order::ProDos);
    let c = parse_prodos(&image, Order::ProDos);
    assert_eq!(c.children.len(), MAX_COMPONENTS);
    assert!(has_note(
        &c,
        "4 files were not listed: at most 4096 components are listed"
    ));
}

/// `value` divided by `divisor`, rounded up.
fn div_round_up(value: usize, divisor: usize) -> usize {
    value / divisor + usize::from(value % divisor != 0)
}

// ---------------------------------------------------------------------
// 2IMG fixtures (magnet.ch "Disk Images", CiderPress II TwoIMG-notes.md).

/// A 2IMG file: magic, creator `CPII`, header length 64, version 1, image
/// format, flags, block count, data at 64, then a comment and 4 B of
/// creator data when given.
fn two_img(format: u32, flags: u32, blocks: u32, data: &[u8], comment: &[u8]) -> Vec<u8> {
    let mut file = vec![0u8; 64];
    file[0..4].copy_from_slice(b"2IMG");
    file[4..8].copy_from_slice(b"CPII");
    file[8..10].copy_from_slice(&64u16.to_le_bytes());
    file[10..12].copy_from_slice(&1u16.to_le_bytes());
    file[12..16].copy_from_slice(&format.to_le_bytes());
    file[16..20].copy_from_slice(&flags.to_le_bytes());
    file[20..24].copy_from_slice(&blocks.to_le_bytes());
    file[24..28].copy_from_slice(&64u32.to_le_bytes());
    file[28..32].copy_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    file.extend_from_slice(data);
    if !comment.is_empty() {
        let at = u32::try_from(file.len()).unwrap();
        file[32..36].copy_from_slice(&at.to_le_bytes());
        file[36..40].copy_from_slice(&u32::try_from(comment.len()).unwrap().to_le_bytes());
        file.extend_from_slice(comment);
        let creator_at = u32::try_from(file.len()).unwrap();
        file[40..44].copy_from_slice(&creator_at.to_le_bytes());
        file[44..48].copy_from_slice(&4u32.to_le_bytes());
        file.extend_from_slice(b"zrax");
    }
    file
}

fn sample_two_img() -> Vec<u8> {
    let volume = sample_prodos_volume(32).image(Order::ProDos);
    two_img(1, 0, 32, &volume, b"ZRAX TEST DISK\r")
}

fn parse_two_img(file: &[u8]) -> Container<'_> {
    assert_eq!(apple2::detect(file), Some(Layout::TwoImg));
    apple2::parse_container(file, Layout::TwoImg).expect("parses")
}

#[test]
fn two_img_prodos_images_list_the_volume_at_the_data_offset() {
    let file = sample_two_img();
    let c = parse_two_img(&file);
    assert_eq!(c.format, FileFormat::TwoImg);
    assert_eq!(c.variant, "2IMG, ProDOS, ProDOS order");
    assert_eq!(c.consumed, file.len());
    assert_eq!(labels(&c), PRODOS_LABELS);
    assert_eq!(child(&c, "/ZRAX/PRODOS").offset, 64 + 7 * BLOCK);
    assert_eq!(child(&c, "Boot code (blocks 0 and 1)").offset, 64);
    assert!(has_note(
        &c,
        "2IMG image by creator 'CPII'; ProDOS order; 16384 B of data at 0x40"
    ));
    assert!(has_note(&c, "2IMG comment: ZRAX TEST DISK"));
    assert!(has_note(
        &c,
        "2IMG creator data: 4 B at 0x404F; not interpreted"
    ));
    assert!(has_note(
        &c,
        "2IMG flags 0x00000000: not locked; sector volume number 254"
    ));
    assert_eq!(
        metadata(&c, "apple2_twoimg_comment").as_deref(),
        Some("ZRAX TEST DISK")
    );
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::TwoImg);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert_eq!(
        serde_json::to_value(p.format.format).unwrap(),
        serde_json::json!("twoimg")
    );
}

#[test]
fn two_img_dos_order_images_hold_dos_33_disks() {
    let disk = sample_dos_disk().image(Order::Dos);
    let file = two_img(0, 0x8000_01fe, 280, &disk, b"");
    let c = parse_two_img(&file);
    assert_eq!(c.variant, "2IMG, DOS 3.3, DOS order");
    assert_eq!(
        labels(&c),
        ["HELLO", "PROG", "NOTES", "Boot code (track 0 sector 0)"]
    );
    assert_eq!(child(&c, "PROG").data.as_ref(), code(PROG_SIZE));
    assert_eq!(child(&c, "PROG").offset, 64 + (18 * 16 + 12) * SECTOR + 4);
    assert!(has_note(
        &c,
        "2IMG flags 0x800001FE: locked; sector volume number 254"
    ));
    // A DOS 3.3 disk stored in ProDOS order.
    let file = two_img(1, 0, 280, &sample_dos_disk().image(Order::ProDos), b"");
    let c = parse_two_img(&file);
    assert_eq!(c.variant, "2IMG, DOS 3.3, ProDOS order");
    assert_eq!(child(&c, "PROG").data.as_ref(), code(PROG_SIZE));
}

#[test]
fn two_img_floppy_data_is_also_tried_in_the_other_order() {
    // A DOS-order disk under a ProDOS-order header: the catalog chain is
    // longer in DOS order.
    let file = two_img(1, 0, 280, &sample_dos_disk().image(Order::Dos), b"");
    let c = parse_two_img(&file);
    assert_eq!(c.variant, "2IMG, DOS 3.3, DOS order");
    assert!(has_note(
        &c,
        "The header names ProDOS order, but the catalog is read in DOS order; its chain is 15 \
         sectors in DOS order, 2 sectors in ProDOS order; it validates in both"
    ));
    assert_eq!(child(&c, "PROG").data.as_ref(), code(PROG_SIZE));
    // A ProDOS-order volume under a DOS-order header.
    let volume = sample_prodos_volume(280).image(Order::ProDos);
    let file = two_img(0, 0, 280, &volume, b"");
    let c = parse_two_img(&file);
    assert_eq!(c.variant, "2IMG, ProDOS, ProDOS order");
    assert!(has_note(
        &c,
        "The header names DOS order, but the volume directory validates only in ProDOS order"
    ));
    assert_eq!(labels(&c), PRODOS_LABELS);
    // A catalog that validates equally in both orders follows the header.
    let ambiguous = ambiguous_dos_disk().image(Order::Dos);
    for (format, variant) in [
        (0, "2IMG, DOS 3.3, DOS order"),
        (1, "2IMG, DOS 3.3, ProDOS order"),
    ] {
        let file = two_img(format, 0, 280, &ambiguous, b"");
        let c = parse_two_img(&file);
        assert_eq!(c.variant, variant);
        assert_eq!(labels(&c), ["SAME"]);
    }
}

#[test]
fn two_img_headers_must_validate() {
    let good = sample_two_img();
    let mutate = |at: usize, bytes: &[u8]| {
        let mut file = good.clone();
        file[at..at + bytes.len()].copy_from_slice(bytes);
        file
    };
    let cases = [
        (
            mutate(24, &0u32.to_le_bytes()),
            "Missing 2IMG data: offset 0x0, length 16384 B",
        ),
        (
            mutate(24, &32u32.to_le_bytes()),
            "Invalid 2IMG data offset 0x20: inside the 64 B header",
        ),
        (
            mutate(28, &20000u32.to_le_bytes()),
            "Truncated 2IMG data: 0x40 + 20000 B exceed the 16467 B file",
        ),
        (
            mutate(20, &31u32.to_le_bytes()),
            "Invalid 2IMG data length 16384 B for ProDOS order with 31 blocks",
        ),
        (
            two_img(0, 0, 0, &[0; 1000], b""),
            "Invalid 2IMG data length 1000 B for DOS order with 0 blocks",
        ),
        (
            mutate(12, &2u32.to_le_bytes()),
            "Invalid 2IMG data length 16384 B for nibbles with 32 blocks",
        ),
    ];
    for (file, message) in cases {
        assert_eq!(
            error_text(&file, Layout::TwoImg),
            format!("Apple II disk image parse error: {message}")
        );
    }
    // Fields that detection checks: a damaged one leaves the file raw.
    for (at, bytes) in [
        (8, &48u16.to_le_bytes()[..]),
        (10, &2u16.to_le_bytes()),
        (12, &3u32.to_le_bytes()),
    ] {
        let file = mutate(at, bytes);
        assert_eq!(apple2::detect(&file), None);
    }
    assert_eq!(
        error_text(&mutate(10, &2u16.to_le_bytes()), Layout::TwoImg),
        "Apple II disk image parse error: Unsupported 2IMG version 2"
    );
    assert_eq!(
        error_text(&good[..40], Layout::TwoImg),
        "Apple II disk image parse error: Truncated 2IMG header: 40 B, 64 B expected"
    );
    // A header length of 52, from the original description, is accepted.
    let old = mutate(8, &52u16.to_le_bytes());
    assert_eq!(parse_two_img(&old).children.len(), PRODOS_LABELS.len());
}

#[test]
fn two_img_chunks_that_overlap_or_leave_the_file_are_noted() {
    let good = sample_two_img();
    let mut file = good.clone();
    file[32..36].copy_from_slice(&100u32.to_le_bytes());
    let c = parse_two_img(&file);
    assert!(has_note(
        &c,
        "The 2IMG comment chunk 0x64 + 15 B overlaps the data or leaves the file; ignored"
    ));
    let mut file = good.clone();
    file.extend_from_slice(&[0; 7]);
    let c = parse_two_img(&file);
    assert!(has_note(&c, "7 B after the last chunk at 0x4053"));
    assert_eq!(c.consumed, good.len());
    // WOOF images may give the size only as a block count.
    let mut woof = good;
    woof[4..8].copy_from_slice(b"WOOF");
    woof[28..32].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(parse_two_img(&woof).children.len(), PRODOS_LABELS.len());
}

#[test]
fn two_img_data_without_a_filesystem_and_nibble_data_are_not_code() {
    let file = two_img(1, 0, 32, &vec![0u8; 32 * BLOCK], b"");
    let c = parse_two_img(&file);
    assert_eq!(c.variant, "2IMG");
    assert!(has_note(
        &c,
        "No DOS 3.3 catalog or ProDOS volume directory validates in ProDOS order"
    ));
    assert_eq!(labels(&c), ["Disk data"]);
    assert_eq!(c.children[0].classify, Classify::IfRecognized);
    let p = classify(&file);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.slices.is_empty());
    let nibbles = two_img(2, 0, 0, &vec![0xffu8; 35 * 6656], b"");
    let c = parse_two_img(&nibbles);
    assert_eq!(labels(&c), ["Nibble data"]);
    assert!(c.children[0].opaque);
    assert!(has_note(&c, "nibble decoding is not implemented"));
    let p = classify(&nibbles);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

// ---------------------------------------------------------------------
// Sweeps.

#[test]
fn prefixes_of_raw_images_are_not_detected_and_of_two_img_do_not_parse() {
    let dos = sample_dos_disk().image(Order::Dos);
    for end in (0..dos.len()).step_by(SECTOR / 2) {
        assert_eq!(apple2::detect_weak(&dos[..end]), None, "{end}");
    }
    let prodos = sample_prodos_volume(32).image(Order::ProDos);
    for end in 0..prodos.len() {
        assert_eq!(apple2::detect_weak(&prodos[..end]), None, "{end}");
    }
    let file = sample_two_img();
    let data_end = 64 + 32 * BLOCK;
    for end in 0..file.len() {
        let result = apple2::parse_container(&file[..end], Layout::TwoImg);
        if end < data_end {
            assert!(result.is_err(), "{end}");
        } else {
            let c = result.expect("the data is complete");
            assert!(c.consumed <= end);
        }
    }
    // A sample of prefixes through the whole classifier.
    for end in (0..dos.len()).step_by(4099) {
        let _ = detect_payload(&dos[..end], &ClassifierOptions::new());
    }
}

/// Parse `image` after each single-byte mutation (0x00, 0xFF, low bit
/// flipped) at each position in `positions`; nothing may panic.
fn mutation_sweep(image: &[u8], positions: impl Iterator<Item = usize>) {
    let mut mutated = image.to_vec();
    for at in positions {
        let original = image[at];
        for value in [0x00, 0xff, original ^ 0x01] {
            mutated[at] = value;
            let layout = apple2::detect(&mutated).or_else(|| apple2::detect_weak(&mutated));
            if let Some(layout) = layout {
                let _ = apple2::parse_container(&mutated, layout);
            }
            for other in [
                Layout::Dos33(Order::Dos),
                Layout::Dos33(Order::ProDos),
                Layout::ProDos(Order::ProDos),
                Layout::TwoImg,
            ] {
                let _ = apple2::parse_container(&mutated, other);
            }
        }
        mutated[at] = original;
    }
}

#[test]
fn byte_mutations_of_dos_structures_do_not_panic() {
    let image = sample_dos_disk().image(Order::Dos);
    let sectors = [
        (0, 0),
        (17, 0),
        (17, 15),
        (17, 14),
        (18, 15),
        (18, 13),
        (18, 12),
        (19, 15),
    ];
    let positions = sectors.iter().flat_map(|&(track, sector)| {
        let start = DosDisk::offset(Order::Dos, track, sector);
        start..start + SECTOR
    });
    mutation_sweep(&image, positions);
    // The whole image at a stride, and a sample through the classifier.
    mutation_sweep(&image, (0..image.len()).step_by(97));
    let mut mutated = image.clone();
    for at in (0x11000..0x11100).step_by(5) {
        mutated[at] ^= 0xff;
        let _ = detect_payload(&mutated, &ClassifierOptions::new());
        mutated[at] ^= 0xff;
    }
}

#[test]
fn byte_mutations_of_prodos_and_two_img_images_do_not_panic() {
    let image = sample_prodos_volume_with(32, 1000).image(Order::ProDos);
    mutation_sweep(&image, 0..image.len());
    let file = two_img(1, 0, 32, &image, b"ZRAX TEST DISK\r");
    mutation_sweep(&file, (0..64).chain(64 + 2 * BLOCK..64 + 4 * BLOCK));
    let dos_order = sample_prodos_volume_with(280, 1000).image(Order::Dos);
    // Track 0 holds blocks 0-7: the loader, the volume directory, the
    // bitmap and the first files.
    mutation_sweep(&dos_order, 0..TRACK);
    let mut mutated = image.clone();
    for at in (0..mutated.len()).step_by(61) {
        mutated[at] ^= 0xff;
        let _ = detect_payload(&mutated, &ClassifierOptions::new());
        mutated[at] ^= 0xff;
    }
}

#[test]
fn deterministic_noise_of_disk_sizes_is_not_detected() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    for size in [143_360usize, 163_840, 16 * BLOCK, 280 * BLOCK] {
        let noise: Vec<u8> = (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        assert_eq!(apple2::detect_weak(&noise), None);
        assert_eq!(apple2::detect(&noise), None);
    }
}
