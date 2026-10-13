//! Atari 8-bit ATR disk images (DOS 2.x files and the boot record) and DOS
//! binary load files: layouts, 6502 targets, slices in stored coordinates,
//! corrupted fields and chains, and truncation and mutation sweeps. ATR
//! images are built here from the documented layout; the binary load file
//! `tests/fixtures/atari8/program.xex` was linked by cc65 (see its README).

use zrax::formats::atari8::{self, Layout};
use zrax::formats::container::{self, Container};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassifierOptions, ContainedArch, DetectionPayload, Endianness, FileFormat,
    Isa, MetadataKey, MetadataValue,
};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// The binary load marker and the DOS vectors ("Mapping the Atari" 736-739).
const MARKER: [u8; 2] = [0xff, 0xff];
const RUNAD: u16 = 0x02e0;
const INITAD: u16 = 0x02e2;

/// ATR header magic and size.
const ATR_MAGIC: [u8; 2] = [0x96, 0x02];
const ATR_HEADER: usize = 16;

/// DOS 2.x structures ("Inside Atari DOS" chapter 2).
const VTOC: usize = 360;
const DIRECTORY: usize = 361;
const DOS2_FILE: u8 = 0x42;
const DOS25_EXTENDED_FILE: u8 = 0x03;
const DELETED: u8 = 0x80;

/// DOS 2.5 enhanced density: the second VTOC at sector 1024 maps sectors
/// 48-1023 in bytes 0-121 and counts the free sectors 720-1023 in bytes
/// 122-123 (Altirra `diskfsdos2.cpp`; `AtariSIO` `Dos2xUtils.cpp`).
const DOS25_SECTORS: usize = 1040;
const VTOC2: usize = 1024;
const VTOC2_FIRST: usize = 48;
const VTOC2_FREE: usize = 122;

const CHAIN: &str = "DOS 2 sector chain";

/// A 6502 routine at 0x2000 that copies a zero-terminated text to screen
/// memory, hand-assembled from NMOS 6502 opcodes:
/// `LDX #$00` (A2 00), `LDA $2010,X` (BD 10 20), `BEQ $200D` (F0 06),
/// `STA $BC40,X` (9D 40 BC), `INX` (E8), `BNE $2002` (D0 F5),
/// `JMP $200D` (4C 0D 20).
const CODE: [u8; 16] = [
    0xa2, 0x00, 0xbd, 0x10, 0x20, 0xf0, 0x06, 0x9d, 0x40, 0xbc, 0xe8, 0xd0, 0xf5, 0x4c, 0x0d, 0x20,
];
const CODE_ADDRESS: u16 = 0x2000;
const TEXT_ADDRESS: u16 = 0x2010;
const TABLE_ADDRESS: u16 = 0x3000;

/// A boot record (sector 1): flags 0x00, 3 boot sectors, load address
/// 0x0700, initialization address 0x0708; at 0x0706 the loader `CLC` (18)
/// and `RTS` (60) reports success; at 0x0708 the init routine is `RTS`
/// (60).
const BOOT_RECORD: [u8; 9] = [0x00, 0x03, 0x00, 0x07, 0x08, 0x07, 0x18, 0x60, 0x60];

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    atari8::parse_container(data, layout).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    match atari8::parse_container(data, layout) {
        Ok(c) => panic!("expected an error, got {:?}", c.notes),
        Err(e) => e.to_string(),
    }
}

fn layout(data: &[u8]) -> Option<Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: container::Kind::Atari8(layout),
        } => Some(layout),
        _ => None,
    }
}

fn has_note(p: &DetectionPayload, needle: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(needle))
}

fn container_note(c: &Container<'_>, needle: &str) -> bool {
    c.notes.iter().any(|n| n.contains(needle))
}

fn custom(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| m.key == MetadataKey::Custom(key.to_string()))
        .map(|m| m.value.to_string())
}

fn entry_point(p: &DetectionPayload) -> Option<u64> {
    p.metadata.iter().find_map(|m| match (&m.key, &m.value) {
        (MetadataKey::EntryPoint, MetadataValue::Address(address)) => Some(*address),
        _ => None,
    })
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{ROOT}/tests/fixtures/atari8/{name}")).expect("fixture")
}

// Binary load files

/// A binary load file under construction: the `FF FF` marker, then
/// segments of start address and inclusive end address (2 + 2,
/// little-endian) followed by the loaded bytes.
struct Xex {
    bytes: Vec<u8>,
}

impl Xex {
    fn new() -> Self {
        Self {
            bytes: MARKER.to_vec(),
        }
    }

    /// A segment loading `data` at `start`, without a marker.
    fn segment(mut self, start: u16, data: &[u8]) -> Self {
        let end = start + u16::try_from(data.len()).unwrap() - 1;
        self.bytes.extend_from_slice(&start.to_le_bytes());
        self.bytes.extend_from_slice(&end.to_le_bytes());
        self.bytes.extend_from_slice(data);
        self
    }

    /// The optional `FF FF` marker before the next segment.
    fn marker(mut self) -> Self {
        self.bytes.extend_from_slice(&MARKER);
        self
    }

    /// A segment that loads RUNAD.
    fn run(self, address: u16) -> Self {
        self.segment(RUNAD, &address.to_le_bytes())
    }

    /// A segment that loads INITAD.
    fn init(self, address: u16) -> Self {
        self.segment(INITAD, &address.to_le_bytes())
    }

    fn build(self) -> Vec<u8> {
        self.bytes
    }
}

/// The program: [`CODE`] at 0x2000, a text at 0x2010, a 256-byte table at
/// 0x3000 (after a marker), and RUNAD 0x2000: 307 bytes, three data
/// sectors (125 + 125 + 57) on a single-density disk.
fn program() -> Vec<u8> {
    let table: Vec<u8> = (0..=255).collect();
    Xex::new()
        .segment(CODE_ADDRESS, &CODE)
        .segment(TEXT_ADDRESS, b"HELLO, ATARI\0")
        .marker()
        .segment(TABLE_ADDRESS, &table)
        .run(CODE_ADDRESS)
        .build()
}

#[test]
fn cc65_binary_load_file_reports_segments_vectors_and_6502() {
    let data = fixture("program.xex");
    assert_eq!(layout(&data), Some(Layout::BinaryLoad));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::AtariXex);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Atari DOS binary load file")
    );
    assert!(p.format.confidence < 0.9, "weak detection");
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Mcs6502, 8, Endianness::Little)
    );
    assert!(p.primary.confidence > 0.99);
    assert_eq!(entry_point(&p), Some(0x2e00));
    assert!(has_note(
        &p,
        "Atari DOS binary load file: 4 segments, 18 B loaded"
    ));
    assert!(has_note(&p, "Run address (RUNAD) 0x2E00"));
    assert!(has_note(&p, "Init calls (INITAD): 0x0600"));
    assert_eq!(custom(&p, "atarixex_runad").as_deref(), Some("0x2E00"));
    assert_eq!(custom(&p, "atarixex_initad").as_deref(), Some("0x0600"));
    assert_eq!(custom(&p, "atarixex_segments").as_deref(), Some("4"));

    let c = parse(&data, Layout::BinaryLoad);
    let sections: Vec<(&str, u64, usize, usize)> = c
        .sections
        .iter()
        .map(|s| (s.label.as_str(), s.address, s.offset, s.stored_size))
        .collect();
    assert_eq!(
        sections,
        [
            ("Segment 1: 0x0600-0x0605", 0x0600, 6, 6),
            ("Segment 2: 0x02E2-0x02E3 (INITAD)", 0x02e2, 0x10, 2),
            ("Segment 3: 0x2E00-0x2E07", 0x2e00, 0x16, 8),
            ("Segment 4: 0x02E0-0x02E1 (RUNAD)", 0x02e0, 0x22, 2),
        ]
    );
    assert_eq!(&*c.sections[0].data, [0xa9, 0x94, 0x8d, 0xc6, 0x02, 0x60]);
    assert!(c.code_sections);
}

#[test]
fn binary_load_markers_are_optional_after_the_first_segment() {
    let data = program();
    let c = parse(&data, Layout::BinaryLoad);
    assert_eq!(c.sections.len(), 4);
    // Marker (2), header (4) and code (16), header and text (4 + 13), then
    // the second marker before the table's header.
    assert_eq!(c.sections[2].offset, 2 + 4 + 16 + 4 + 13 + 2 + 4);
    assert_eq!(c.sections[2].address, u64::from(TABLE_ADDRESS));
    assert_eq!(c.entry, Some(u64::from(CODE_ADDRESS)));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::AtariXex);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
}

#[test]
fn without_a_run_address_the_first_init_call_is_the_entry() {
    let data = Xex::new()
        .segment(0x0600, &[0x60])
        .init(0x0600)
        .segment(0x0700, &[0x60])
        .init(0x0700)
        .build();
    let c = parse(&data, Layout::BinaryLoad);
    assert_eq!(c.entry, Some(0x0600));
    assert!(container_note(
        &c,
        "No run address (RUNAD): DOS returns to its menu after loading"
    ));
    assert!(container_note(
        &c,
        "Init calls (INITAD): 0x0600, 0x0700; the first is reported as the entry point"
    ));

    let data = Xex::new().segment(0x02c5, &[0x0f, 0x00]).build();
    let c = parse(&data, Layout::BinaryLoad);
    assert_eq!(c.entry, None);

    // One byte of INITAD per segment is no init call.
    let data = Xex::new()
        .segment(0x0600, &[0x60])
        .segment(INITAD, &[0x00])
        .build();
    let c = parse(&data, Layout::BinaryLoad);
    assert_eq!(c.entry, None);
    assert!(container_note(
        &c,
        "Segments that load only one byte of INITAD: 1"
    ));
}

#[test]
fn binary_load_segments_must_be_valid_and_tile_the_file() {
    let data = program();
    // Trailing bytes, a trailing marker, and a missing first marker.
    for suffix in [&[0x00][..], &[0x00, 0x00, 0x00], &MARKER] {
        let mut longer = data.clone();
        longer.extend_from_slice(suffix);
        assert_ne!(layout(&longer), Some(Layout::BinaryLoad), "{suffix:?}");
    }
    assert_eq!(layout(&data[2..]), None);
    assert_eq!(
        parse_error(&data[2..], Layout::BinaryLoad),
        "Atari 8-bit image parse error: Missing binary load marker FF FF at 0x0"
    );

    // An end address below the start.
    let mut reversed = data.clone();
    reversed[4..6].copy_from_slice(&0x1fffu16.to_le_bytes());
    assert_eq!(layout(&reversed), None);
    assert_eq!(
        parse_error(&reversed, Layout::BinaryLoad),
        "Atari 8-bit image parse error: Invalid segment at 0x2: end address 0x1FFF is below \
         start address 0x2000"
    );

    let mut trailing = data.clone();
    trailing.push(0);
    assert_eq!(
        parse_error(&trailing, Layout::BinaryLoad),
        format!(
            "Atari 8-bit image parse error: Truncated segment header at 0x{:X}: 1 B of 4",
            data.len()
        )
    );
    let truncated = &data[..data.len() - 1];
    assert!(parse_error(truncated, Layout::BinaryLoad).contains("Truncated segment at 0x"));
    let mut marked = data.clone();
    marked.extend_from_slice(&MARKER);
    assert!(parse_error(&marked, Layout::BinaryLoad).contains("is not followed by a segment"));

    // Erased flash is not a binary load file.
    assert_eq!(layout(&[0xff; 4096]), None);
}

#[test]
fn standalone_binary_load_files_must_load_a_run_or_init_address() {
    // Erased flash with a few programmed bytes: `FF FF` markers, then
    // 0xFFF8-0xFFFF and 0xFFFF-0xFFFF segments that tile the file.
    let flash = [
        0xff, 0xff, 0xff, 0xff, 0xf8, 0xff, 0xff, 0xff, 0x50, 0x64, 0xff, 0xff, 0xff, 0xac, 0xff,
        0x98,
    ];
    assert!(atari8::parse_container(&flash, Layout::BinaryLoad).is_ok());
    assert_eq!(layout(&flash), None);
    // The same segments followed by RUNAD are a program.
    let code_only = Xex::new().segment(CODE_ADDRESS, &CODE).build();
    assert_eq!(layout(&code_only), None);
    let runnable = Xex::new()
        .segment(CODE_ADDRESS, &CODE)
        .run(CODE_ADDRESS)
        .build();
    assert_eq!(layout(&runnable), Some(Layout::BinaryLoad));
}

#[test]
fn binary_load_truncations_and_mutations_never_claim_or_panic() {
    // A prefix that ends after a segment is a shorter, valid file, which is
    // recognized once a segment has loaded a run or init address
    // (`program.xex` loads INITAD in its second segment; `program()` loads
    // RUNAD last); every other prefix must not be recognized.
    let cases = [(fixture("program.xex"), vec![18, 30]), (program(), vec![])];
    for (data, segment_ends) in cases {
        for end in 0..data.len() {
            let prefix = &data[..end];
            let expected = segment_ends.contains(&end).then_some(Layout::BinaryLoad);
            assert_eq!(layout(prefix), expected, "prefix of {end} B");
            let _ = detect_payload(prefix, &ClassifierOptions::new());
        }
        for i in 0..data.len() {
            for value in [0x00, 0xff, data[i] ^ 0x01] {
                let mut mutated = data.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
                let _ = atari8::parse_container(&mutated, Layout::BinaryLoad);
            }
        }
    }
}

// ATR disk images

/// How a 256-byte-sector image stores sectors 1-3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slots {
    /// 128 bytes each (and every sector of a single-density image).
    Short,
    /// First half of 256-byte slots.
    Physical,
    /// The first 384 bytes, then 384 unused bytes.
    Sio2pc,
}

/// A disk under construction: logical sectors 1 to n; on 256-byte disks
/// sectors 1-3 hold 128 bytes ("Altirra Hardware Reference Manual" §10.1).
struct Disk {
    sector_size: usize,
    sectors: Vec<Vec<u8>>,
}

impl Disk {
    fn new(sector_size: usize, count: usize) -> Self {
        let sectors = (1..=count)
            .map(|number| vec![0; Self::length(sector_size, number)])
            .collect();
        Self {
            sector_size,
            sectors,
        }
    }

    fn length(sector_size: usize, number: usize) -> usize {
        if number <= 3 && sector_size <= 256 {
            128
        } else {
            sector_size
        }
    }

    fn sector(&mut self, number: usize) -> &mut [u8] {
        &mut self.sectors[number - 1]
    }

    /// Image offset (after the header) of sector `number` in `slots`.
    fn image_offset(&self, number: usize, slots: Slots) -> usize {
        let index = number - 1;
        let size = self.sector_size;
        if size != 256 {
            return index * size;
        }
        match slots {
            Slots::Short if index < 3 => index * 128,
            Slots::Short => 384 + (index - 3) * 256,
            Slots::Physical if index < 3 => index * 256,
            Slots::Sio2pc if index < 3 => index * 128,
            Slots::Physical | Slots::Sio2pc => 768 + (index - 3) * 256,
        }
    }

    /// File offset of sector `number` in `slots`.
    fn offset(&self, number: usize, slots: Slots) -> usize {
        ATR_HEADER + self.image_offset(number, slots)
    }

    /// The ATR file: magic `96 02`, the image size in paragraphs (bits 0-15
    /// at 2, bits 16-23 at 6), the sector size at 4, then the sectors.
    fn atr(&self, slots: Slots) -> Vec<u8> {
        let count = self.sectors.len();
        let size = self.image_offset(count, slots) + self.sectors[count - 1].len();
        let paragraphs = size / 16;
        let mut data = vec![0; ATR_HEADER + size];
        data[..2].copy_from_slice(&ATR_MAGIC);
        data[2..4].copy_from_slice(&u16::try_from(paragraphs & 0xffff).unwrap().to_le_bytes());
        data[4..6].copy_from_slice(&u16::try_from(self.sector_size).unwrap().to_le_bytes());
        data[6] = u8::try_from(paragraphs >> 16).unwrap();
        for (i, sector) in self.sectors.iter().enumerate() {
            let at = self.offset(i + 1, slots);
            data[at..at + sector.len()].copy_from_slice(sector);
        }
        data
    }

    fn write_boot_record(&mut self, record: &[u8]) {
        self.sector(1)[..record.len()].copy_from_slice(record);
    }

    /// Format as DOS 2.x: VTOC code 2, 707 usable sectors, a bitmap of
    /// sectors 0-719 (bit 0x80 of byte 10 is sector 0; a set bit is free)
    /// with sectors 0-3 and 360-368 in use, and an empty directory.
    /// On a DOS 2.5 disk (1040 sectors of 128 bytes) the VTOC counts 1010
    /// usable sectors and VTOC2 maps 48-1023, with 303 free above 720.
    fn format_dos2(&mut self) {
        let dos25 = self.is_dos25();
        let vtoc = self.sector(VTOC);
        vtoc[0] = 2;
        let total: u16 = if dos25 { 1010 } else { 707 };
        vtoc[1..3].copy_from_slice(&total.to_le_bytes());
        vtoc[3..5].copy_from_slice(&707u16.to_le_bytes());
        for sector in (4..360).chain(369..720) {
            vtoc[10 + sector / 8] |= 0x80 >> (sector % 8);
        }
        if dos25 {
            let vtoc2 = self.sector(VTOC2);
            for sector in (VTOC2_FIRST..360).chain(369..720).chain(721..1024) {
                vtoc2[sector / 8 - VTOC2_FIRST / 8] |= 0x80 >> (sector % 8);
            }
            vtoc2[VTOC2_FREE..VTOC2_FREE + 2].copy_from_slice(&303u16.to_le_bytes());
        }
    }

    fn is_dos25(&self) -> bool {
        self.sector_size == 128 && self.sectors.len() == DOS25_SECTORS
    }

    /// Mark `sector` in use in the VTOC (and VTOC2) and decrement the free
    /// count that covers it.
    fn allocate(&mut self, sector: usize) {
        let dos25 = self.is_dos25();
        if sector < 720 {
            let vtoc = self.sector(VTOC);
            vtoc[10 + sector / 8] &= !(0x80 >> (sector % 8));
            let free = u16::from_le_bytes([vtoc[3], vtoc[4]]) - 1;
            vtoc[3..5].copy_from_slice(&free.to_le_bytes());
        }
        if dos25 && sector >= VTOC2_FIRST {
            let vtoc2 = self.sector(VTOC2);
            vtoc2[sector / 8 - VTOC2_FIRST / 8] &= !(0x80 >> (sector % 8));
            if sector > 720 {
                let free = u16::from_le_bytes([vtoc2[VTOC2_FREE], vtoc2[VTOC2_FREE + 1]]) - 1;
                vtoc2[VTOC2_FREE..VTOC2_FREE + 2].copy_from_slice(&free.to_le_bytes());
            }
        }
    }

    /// Write directory entry `number`: flags, sector count (2), first
    /// sector (2), name (8) and extension (3).
    fn write_entry(
        &mut self,
        number: usize,
        flags: u8,
        name: &[u8; 11],
        count: usize,
        first: usize,
    ) {
        let entry = &mut self.sector(DIRECTORY + number / 8)[(number % 8) * 16..][..16];
        entry[0] = flags;
        entry[1..3].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
        entry[3..5].copy_from_slice(&u16::try_from(first).unwrap().to_le_bytes());
        entry[5..16].copy_from_slice(name);
    }

    /// Write `contents` as file `number` through `sectors`: size - 3 data
    /// bytes per sector, then the file number (bits 7-2) with the next
    /// sector's bits 9-8, the next sector's low byte (0 at the end) and the
    /// bytes used.
    fn write_file(
        &mut self,
        number: usize,
        flags: u8,
        name: &[u8; 11],
        contents: &[u8],
        sectors: &[usize],
    ) {
        let capacity = self.sector_size - 3;
        let chunks: Vec<&[u8]> = contents.chunks(capacity).collect();
        assert_eq!(chunks.len().max(1), sectors.len(), "sectors for {name:?}");
        for (i, &sector) in sectors.iter().enumerate() {
            let next = sectors.get(i + 1).copied().unwrap_or(0);
            let chunk = chunks.get(i).copied().unwrap_or_default();
            let size = self.sector_size;
            let bytes = self.sector(sector);
            bytes[..chunk.len()].copy_from_slice(chunk);
            bytes[size - 3] = u8::try_from(number << 2 | next >> 8).unwrap();
            bytes[size - 2] = u8::try_from(next & 0xff).unwrap();
            bytes[size - 1] = u8::try_from(chunk.len()).unwrap();
            self.allocate(sector);
        }
        self.write_entry(number, flags, name, sectors.len(), sectors[0]);
    }
}

/// A plain-text file of 200 bytes (two single-density sectors).
fn readme() -> Vec<u8> {
    b"THIS DISK HOLDS A SYNTHETIC PROGRAM.\x9b"
        .iter()
        .copied()
        .cycle()
        .take(200)
        .collect()
}

/// A single-density DOS 2.x disk: HELLO.XEX ([`program`]) in sectors 4-6,
/// README.TXT in sectors 7 and 9, and the boot record.
fn sd_disk() -> Disk {
    let mut disk = Disk::new(128, 720);
    disk.format_dos2();
    disk.write_boot_record(&BOOT_RECORD);
    disk.write_file(0, DOS2_FILE, b"HELLO   XEX", &program(), &[4, 5, 6]);
    disk.write_file(1, DOS2_FILE, b"README  TXT", &readme(), &[7, 9]);
    disk
}

#[test]
fn single_density_disks_list_dos_files_and_classify_binary_load_files() {
    let disk = sd_disk();
    let data = disk.atr(Slots::Short);
    assert_eq!(data.len(), 16 + 720 * 128);
    assert_eq!(layout(&data), Some(Layout::Atr));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Atr);
    assert!(p.format.confidence > 0.99);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert!(has_note(&p, "Primary ISA selected from HELLO.XEX"));
    assert!(has_note(&p, "ATR image: 720 sectors of 128 B, 90 KiB"));
    assert!(has_note(
        &p,
        "Atari DOS 2.x file system: 2 files; the VTOC records 702 of 707 sectors free"
    ));
    assert!(has_note(
        &p,
        "Boot record: 3 sectors loaded at 0x0700, loader at 0x0706, initialization address \
         0x0708, flags 0x00"
    ));
    let order: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(order, ["HELLO.XEX", "README.TXT", "Boot sectors 1-3"]);

    let hello = slice(&p, "HELLO.XEX");
    assert_eq!(hello.isa, Isa::Mcs6502);
    assert_eq!(
        (hello.offset, hello.size),
        (disk.offset(4, Slots::Short) as u64, 125)
    );
    let decoded = hello.decoded.as_ref().expect("decoded range");
    assert_eq!(
        (decoded.transform.as_str(), decoded.size),
        (CHAIN, program().len() as u64)
    );
    let readme_slice = slice(&p, "README.TXT");
    assert_eq!(readme_slice.isa, Isa::Unknown(0));
    assert!(has_note(
        &p,
        "README.TXT: opaque; payload ISA analysis skipped"
    ));
    let boot = slice(&p, "Boot sectors 1-3");
    assert_eq!((boot.isa, boot.offset, boot.size), (Isa::Mcs6502, 16, 384));
    assert_eq!(custom(&p, "atr_dos_files").as_deref(), Some("2"));
    assert_eq!(
        custom(&p, "atr_boot_load_address").as_deref(),
        Some("0x0700")
    );

    let c = parse(&data, Layout::Atr);
    assert_eq!(&*c.children[0].data, program().as_slice());
    assert_eq!(&*c.children[1].data, readme().as_slice());
    assert!(c.children[1].opaque);
    assert_eq!(c.target, None, "the disk names no ISA itself");
}

#[test]
fn a_file_in_one_sector_is_stored_without_a_transform() {
    let mut disk = Disk::new(128, 720);
    disk.format_dos2();
    let xex = fixture("program.xex");
    disk.write_file(0, DOS2_FILE | 0x20, b"PROGRAM COM", &xex, &[4]);
    let p = classify(&disk.atr(Slots::Short));
    let program = slice(&p, "PROGRAM.COM");
    assert_eq!(program.isa, Isa::Mcs6502);
    assert_eq!(
        (program.offset, program.size),
        (16 + 3 * 128, xex.len() as u64)
    );
    assert!(program.decoded.is_none());
    assert!(has_note(&p, "Primary ISA selected from PROGRAM.COM"));
    assert!(has_note(
        &p,
        "Sector 1 holds only 0x00 or 0xFF bytes: no boot record"
    ));
    assert_eq!(p.slices.len(), 1);
}

#[test]
fn double_density_layouts_place_short_boot_sectors() {
    for slots in [Slots::Short, Slots::Physical, Slots::Sio2pc] {
        let mut disk = Disk::new(256, 720);
        disk.format_dos2();
        let mut record = BOOT_RECORD.to_vec();
        // A sector 3 that is not empty, so the physical layout's probe sees
        // data and the SIO2PC layout's unused bytes stay zero.
        disk.sector(3)[0] = 0x60;
        record.resize(128, 0xea);
        disk.write_boot_record(&record);
        disk.write_file(0, DOS2_FILE, b"HELLO   XEX", &program(), &[4, 5]);
        let data = disk.atr(slots);
        let expected_size = match slots {
            Slots::Short => 16 + 384 + 717 * 256,
            Slots::Physical | Slots::Sio2pc => 16 + 720 * 256,
        };
        assert_eq!(data.len(), expected_size, "{slots:?}");
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::Atr, "{slots:?}");
        let hello = slice(&p, "HELLO.XEX");
        assert_eq!(
            (hello.isa, hello.offset, hello.size),
            (Isa::Mcs6502, disk.offset(4, slots) as u64, 253),
            "{slots:?}"
        );
        let boot = slice(&p, "Boot sectors 1-3");
        assert_eq!(boot.isa, Isa::Mcs6502);
        let c = parse(&data, Layout::Atr);
        let boot_child = c.children.last().unwrap();
        assert_eq!(boot_child.data.len(), 384);
        assert_eq!(&boot_child.data[..9], BOOT_RECORD);
        assert_eq!(boot_child.data[256], 0x60, "{slots:?}");
        match slots {
            Slots::Physical => {
                assert_eq!(boot_child.transform, Some("ATR boot sector slots"));
                assert_eq!(boot_child.stored_size, 512 + 128);
                assert!(container_note(&c, "first half of 256-byte slots"));
            }
            Slots::Sio2pc => {
                assert_eq!(boot_child.transform, None);
                assert!(container_note(&c, "packed into the first 384 B"));
            }
            Slots::Short => {
                assert_eq!(boot_child.transform, None);
                assert!(container_note(&c, "sectors 1-3 stored as 128 B"));
            }
        }
    }
}

#[test]
fn dos25_enhanced_density_lists_files_flagged_0x03() {
    let mut disk = Disk::new(128, 1040);
    disk.format_dos2();
    disk.write_file(
        0,
        DOS25_EXTENDED_FILE,
        b"HIGH    XEX",
        &program(),
        &[800, 900, 1000],
    );
    let data = disk.atr(Slots::Short);
    let c = parse(&data, Layout::Atr);
    assert_eq!(labels(&c), ["HIGH.XEX"]);
    assert!(container_note(
        &c,
        "Atari DOS 2.x file system (DOS 2.5 enhanced density): 1 file"
    ));
    assert!(container_note(
        &c,
        "ATR image: 1040 sectors of 128 B, 130 KiB"
    ));

    // On a 720-sector disk the same flags mean "open for output".
    let mut disk = Disk::new(128, 720);
    disk.format_dos2();
    disk.write_file(
        0,
        DOS25_EXTENDED_FILE,
        b"HIGH    XEX",
        &program(),
        &[400, 500, 600],
    );
    let image = disk.atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert!(container_note(&c, "HIGH.XEX: open for output; not listed"));
    assert!(c.children.is_empty());
}

#[test]
fn hidden_and_foreign_directory_entries_are_noted() {
    let mut disk = sd_disk();
    disk.write_entry(2, DELETED | DOS2_FILE, b"OLD     DAT", 1, 10);
    disk.write_entry(3, 0x40, b"DOS1    DAT", 1, 11);
    disk.write_entry(4, 0x10, b"SUBDIR     ", 8, 20);
    disk.write_entry(5, 0x46, b"BIG     DAT", 1, 12);
    let image = disk.atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert_eq!(labels(&c), ["HELLO.XEX", "README.TXT", "Boot sectors 1-3"]);
    assert!(container_note(
        &c,
        "Deleted or unused directory entries, not listed: 1"
    ));
    assert!(container_note(
        &c,
        "DOS1.DAT: DOS 1.x file; its sectors are not interpreted"
    ));
    assert!(container_note(
        &c,
        "SUBDIR: MyDOS subdirectory; not interpreted"
    ));
    assert!(container_note(
        &c,
        "BIG.DAT: MyDOS 16-bit sector links; not extracted"
    ));

    // The first entry with flags 0 ends the directory.
    let mut disk = sd_disk();
    disk.write_entry(1, 0, b"README  TXT", 2, 7);
    let image = disk.atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert_eq!(labels(&c), ["HELLO.XEX", "Boot sectors 1-3"]);
}

/// A change to HELLO.XEX's chain on [`sd_disk`] and the problem it causes.
struct Damage {
    problem: &'static str,
    apply: fn(&mut Disk),
}

#[test]
fn broken_sector_chains_are_noted_and_skipped() {
    let base = sd_disk();
    // Trailer bytes of a 128-byte sector: 125 file number and link bits
    // 9-8, 126 link bits 7-0, 127 bytes used.
    let cases = [
        Damage {
            problem: "sector 4 appears twice in the chain",
            apply: |disk| disk.sector(6)[126] = 4,
        },
        Damage {
            problem: "sector 5 carries file number 1",
            apply: |disk| disk.sector(5)[125] = 1 << 2,
        },
        Damage {
            problem: "sector 1000 is beyond the 720-sector disk",
            apply: |disk| {
                disk.sector(4)[125] = 3;
                disk.sector(4)[126] = 0xe8;
            },
        },
        Damage {
            problem: "sector 6 declares 126 B of data, more than 125",
            apply: |disk| disk.sector(6)[127] = 126,
        },
        Damage {
            problem: "the directory names sector 0 as its first sector",
            apply: |disk| disk.sector(DIRECTORY)[3..5].copy_from_slice(&[0, 0]),
        },
    ];
    for Damage { problem, apply } in cases {
        let mut disk = Disk {
            sector_size: base.sector_size,
            sectors: base.sectors.clone(),
        };
        apply(&mut disk);
        let image = disk.atr(Slots::Short);
        let c = parse(&image, Layout::Atr);
        assert!(
            container_note(&c, &format!("HELLO.XEX: {problem}; not extracted")),
            "{problem}: {:?}",
            c.notes
        );
        assert_eq!(labels(&c), ["README.TXT", "Boot sectors 1-3"], "{problem}");
    }

    // A wrong sector count in the directory is only noted.
    let mut disk = sd_disk();
    disk.write_entry(0, DOS2_FILE, b"HELLO   XEX", 9, 4);
    let image = disk.atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert!(container_note(
        &c,
        "HELLO.XEX: the directory lists 9 sectors, the chain has 3"
    ));
    assert_eq!(c.children.len(), 3);

    // A double-density chain must not run through a 128-byte boot sector.
    let mut disk = Disk::new(256, 720);
    disk.format_dos2();
    disk.write_file(0, DOS2_FILE, b"HELLO   XEX", &program(), &[4, 5]);
    disk.sector(4)[254] = 2;
    let image = disk.atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert!(container_note(
        &c,
        "HELLO.XEX: sector 2 is a 128-byte boot sector; not extracted"
    ));
}

#[test]
fn disks_without_a_dos2_file_system_classify_their_boot_record() {
    // A boot disk: three boot sectors of code, no VTOC.
    let mut disk = Disk::new(128, 720);
    disk.write_boot_record(&BOOT_RECORD);
    let data = disk.atr(Slots::Short);
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Atr);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert!(has_note(
        &p,
        "No Atari DOS 2.x file system: VTOC code 0x00 at sector 360 (DOS 2.x writes 0x02)"
    ));
    assert!(has_note(&p, "Primary ISA selected from Boot sectors 1-3"));
    let boot = slice(&p, "Boot sectors 1-3");
    assert_eq!(boot.variant.as_ref().map(|v| v.name.as_str()), Some("6502"));

    // A VTOC whose bitmap frees the directory is not DOS 2.x.
    let mut disk = sd_disk();
    disk.sector(VTOC)[10 + 361 / 8] |= 0x80 >> (361 % 8);
    let image = disk.atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert!(container_note(
        &c,
        "marks sector 361 free, which DOS 2.x keeps in use"
    ));
    assert_eq!(labels(&c), ["Boot sectors 1-3"]);

    // DOS 1.x, small disks and large sectors.
    let mut disk = sd_disk();
    disk.sector(VTOC)[0] = 1;
    let image = disk.atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert!(container_note(
        &c,
        "VTOC code 0x01 at sector 360 is the DOS 1.x code"
    ));
    let image = Disk::new(128, 400).atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert!(container_note(
        &c,
        "400 sectors, fewer than the 720 its VTOC maps"
    ));
    let image = Disk::new(512, 16).atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert!(container_note(&c, "not 512 B"));
    assert!(container_note(
        &c,
        "Boot sectors of 512-byte-sector images are not interpreted"
    ));
    assert!(c.children.is_empty());
}

#[test]
fn implausible_or_empty_boot_records_are_opaque() {
    // 0x40 sectors at 0xF000 would end beyond 64 KiB.
    let mut disk = Disk::new(128, 720);
    disk.write_boot_record(&[0x00, 0x40, 0x00, 0xf0, 0x00, 0x00, 0x60]);
    let data = disk.atr(Slots::Short);
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    assert!(has_note(
        &p,
        "The boot record loads 64 sectors at 0xF000, beyond the 64 KiB address space"
    ));
    assert!(has_note(&p, "Boot sectors 1-64: opaque"));

    // An empty sector 1 holds no boot record.
    let p = classify(&Disk::new(128, 720).atr(Slots::Short));
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    assert!(has_note(
        &p,
        "Sector 1 holds only 0x00 or 0xFF bytes: no boot record"
    ));
    assert!(p.slices.is_empty());

    // DBSECT 0 loads 256 sectors.
    let mut disk = Disk::new(128, 720);
    disk.write_boot_record(&[0x00, 0x00, 0x00, 0x30, 0x00, 0x30, 0x18, 0x60]);
    let p = classify(&disk.atr(Slots::Short));
    assert!(has_note(
        &p,
        "Boot record: 256 sectors loaded at 0x3000, loader at 0x3006"
    ));
    assert_eq!(slice(&p, "Boot sectors 1-256").isa, Isa::Mcs6502);

    // A double-density boot record that declares more than three sectors.
    let mut disk = Disk::new(256, 720);
    disk.write_boot_record(&[0x00, 0x05, 0x00, 0x07, 0x00, 0x07, 0x60]);
    let image = disk.atr(Slots::Short);
    let c = parse(&image, Layout::Atr);
    assert!(container_note(
        &c,
        "The boot record declares 5 sectors; 3 are listed: a double-density image has three \
         128-byte boot sectors"
    ));
}

#[test]
fn atr_header_and_size_damage() {
    let data = sd_disk().atr(Slots::Short);
    // 12 paragraphs, 192 B: not a whole number of sectors, so not an ATR
    // header.
    let mut partial = data[..16 + 192].to_vec();
    partial[2..4].copy_from_slice(&12u16.to_le_bytes());
    assert_eq!(layout(&partial), None);
    assert_eq!(
        parse_error(&partial, Layout::Atr),
        "Atari 8-bit image parse error: Invalid ATR image size 192 B: not a whole number of \
         128-byte sectors"
    );

    // Trailing bytes after the declared image: padding is noted, data is an
    // error.
    let mut padded = data.clone();
    padded.extend_from_slice(&[0; 64]);
    let c = parse(&padded, Layout::Atr);
    assert!(container_note(
        &c,
        "64 B of padding after the declared image"
    ));
    let mut trailing = data.clone();
    trailing.extend_from_slice(b"JUNK");
    assert_eq!(
        parse_error(&trailing, Layout::Atr),
        format!(
            "Atari 8-bit image parse error: Invalid trailing data: 4 B at 0x{:X} after the \
             declared ATR image",
            data.len()
        )
    );

    // An undocumented sector size, a zero size or a declared size beyond
    // the file is not an ATR.
    let mut odd = data.clone();
    odd[4..6].copy_from_slice(&100u16.to_le_bytes());
    assert_eq!(layout(&odd), None);
    assert_eq!(
        parse_error(&odd, Layout::Atr),
        "Atari 8-bit image parse error: Unsupported ATR sector size 100 B at 0x4"
    );
    let mut zero = data.clone();
    zero[2..4].fill(0);
    assert_eq!(layout(&zero), None);
    assert_eq!(
        parse_error(&zero, Layout::Atr),
        "Atari 8-bit image parse error: Invalid ATR image size 0 B at 0x2"
    );
    // A truncated image is recognized and reported as truncated, so an
    // archive member is recognized from its first bytes.
    assert!(container::is_recognized(&data[..4096]));
    assert_eq!(layout(&data[..data.len() - 1]), Some(Layout::Atr));
    assert!(detect_payload(&data[..data.len() - 1], &ClassifierOptions::new()).is_err());
    assert_eq!(
        parse_error(&data[..data.len() - 1], Layout::Atr),
        format!(
            "Atari 8-bit image parse error: Truncated ATR image: the header declares {} B, {} B \
             follow it",
            720 * 128,
            720 * 128 - 1
        )
    );
    assert_eq!(
        parse_error(&data[..10], Layout::Atr),
        "Atari 8-bit image parse error: Truncated ATR header: 10 B of 16"
    );

    // More than 65535 sectors.
    let mut huge = vec![0; 16 + 65_536 * 128];
    huge[..2].copy_from_slice(&ATR_MAGIC);
    let paragraphs = 65_536 * 128 / 16;
    huge[2..4].copy_from_slice(&u16::try_from(paragraphs & 0xffff).unwrap().to_le_bytes());
    huge[4] = 0x80;
    huge[6] = u8::try_from(paragraphs >> 16).unwrap();
    assert_eq!(
        parse_error(&huge, Layout::Atr),
        "Atari 8-bit image parse error: Unsupported ATR sector count 65536: sector numbers are \
         16-bit"
    );
}

#[test]
fn atr_truncations_are_errors_once_the_header_is_present() {
    for data in [sd_disk().atr(Slots::Short), {
        let mut disk = Disk::new(256, 720);
        disk.format_dos2();
        disk.write_file(0, DOS2_FILE, b"HELLO   XEX", &program(), &[4, 5]);
        disk.atr(Slots::Physical)
    }] {
        for end in (0..data.len())
            .step_by(61)
            .chain(data.len() - 17..data.len())
        {
            let prefix = &data[..end];
            let recognized = end >= 16;
            assert_eq!(
                layout(prefix) == Some(Layout::Atr),
                recognized,
                "prefix of {end} B"
            );
            let result = detect_payload(prefix, &ClassifierOptions::new());
            assert!(
                !result.is_ok_and(|p| p.format.format == FileFormat::Atr),
                "prefix of {end} B classifies as ATR"
            );
        }
    }
}

#[test]
fn atr_mutations_never_panic() {
    let disk = sd_disk();
    let data = disk.atr(Slots::Short);
    let vtoc = disk.offset(VTOC, Slots::Short);
    let directory = disk.offset(DIRECTORY, Slots::Short);
    let positions = (0..16)
        .chain(16..16 + 16)
        .chain(vtoc..vtoc + 16)
        .chain(directory..directory + 48)
        .chain((disk.offset(4, Slots::Short)..disk.offset(10, Slots::Short)).step_by(7))
        .chain((0..data.len()).step_by(4099));
    for i in positions {
        for value in [0x00, 0xff, data[i] ^ 0x01] {
            let mut mutated = data.clone();
            mutated[i] = value;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
            let _ = atari8::parse_container(&mutated, Layout::Atr);
        }
    }
    // Every trailer byte of every file sector, on both densities.
    for sector_size in [128usize, 256] {
        let mut disk = Disk::new(sector_size, 720);
        disk.format_dos2();
        disk.write_file(
            0,
            DOS2_FILE,
            b"HELLO   XEX",
            &program(),
            if sector_size == 128 {
                &[4, 5, 6]
            } else {
                &[4, 5]
            },
        );
        let data = disk.atr(Slots::Short);
        for sector in 4..=6 {
            let at = disk.offset(sector, Slots::Short) + sector_size - 3;
            for i in at..at + 3 {
                for value in [0x00, 0xff, data[i] ^ 0x01, data[i] ^ 0x80] {
                    let mut mutated = data.clone();
                    mutated[i] = value;
                    let _ = detect_payload(&mutated, &ClassifierOptions::new());
                }
            }
        }
    }
}
