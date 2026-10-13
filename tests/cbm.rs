//! Commodore disk and tape images: D64 (35 and 40 tracks, with and without
//! error bytes), D71, D81 and T64 images built from the VICE manual's
//! layouts; PRG files become 6502-family code after their load address,
//! other files stay opaque, and damaged chains, BAMs and directories are
//! notes or rejections, never panics.

use zrax::formats::cbm::{self, DiskImage, Layout};
use zrax::{
    detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa, MetadataKey,
};

const SECTOR: usize = 256;

/// A 6502 routine at 0xC000, hand-assembled:
/// `A9 01` LDA #$01; `8D 20 D0` STA $D020 (border colour); `A2 00` LDX #$00;
/// `BD 00 C1` LDA $C100,X; `9D 00 04` STA $0400,X (screen); `E8` INX;
/// `D0 F7` BNE back to the LDA (0xC010 - 9 = 0xC007); `60` RTS.
const ROUTINE: [u8; 17] = [
    0xa9, 0x01, 0x8d, 0x20, 0xd0, 0xa2, 0x00, 0xbd, 0x00, 0xc1, 0x9d, 0x00, 0x04, 0xe8, 0xd0, 0xf7,
    0x60,
];

/// A BASIC line `10 SYS 2061` at 0x0801 (next-line pointer 0x080B, line
/// number 10, token 0x9E, "2061", end of line, end of program), then code
/// at 0x080D.
const BASIC_STUB: [u8; 12] = [
    0x0b, 0x08, 0x0a, 0x00, 0x9e, 0x32, 0x30, 0x36, 0x31, 0x00, 0x00, 0x00,
];

/// `size` bytes of the routine, repeated.
fn code(size: usize) -> Vec<u8> {
    ROUTINE.iter().copied().cycle().take(size).collect()
}

/// A PRG file: little-endian load address, then the program.
fn prg(load_address: u16, program: &[u8]) -> Vec<u8> {
    let mut file = load_address.to_le_bytes().to_vec();
    file.extend_from_slice(program);
    file
}

/// The disk geometries of the VICE manual's offset tables.
#[derive(Clone, Copy)]
enum Drive {
    /// 1541 zones (21/19/18/17 sectors) for `tracks` tracks.
    C1541 { tracks: u8 },
    /// 1541 zones on both sides: tracks 36-70 repeat tracks 1-35.
    C1571,
    /// 80 tracks of 40 sectors.
    C1581,
}

impl Drive {
    fn tracks(self) -> u8 {
        match self {
            Self::C1541 { tracks } => tracks,
            Self::C1571 => 70,
            Self::C1581 => 80,
        }
    }

    fn sectors_per_track(self, track: u8) -> usize {
        let zone = |track: u8| match track {
            1..=17 => 21,
            18..=24 => 19,
            25..=30 => 18,
            _ => 17,
        };
        match self {
            Self::C1541 { .. } => zone(track),
            Self::C1571 if track > 35 => zone(track - 35),
            Self::C1571 => zone(track),
            Self::C1581 => 40,
        }
    }

    fn sectors(self) -> usize {
        (1..=self.tracks()).map(|t| self.sectors_per_track(t)).sum()
    }

    /// Image offset of `track`/`sector`: the sectors of all earlier tracks,
    /// then the sector.
    fn offset(self, track: u8, sector: u8) -> usize {
        let before: usize = (1..track).map(|t| self.sectors_per_track(t)).sum();
        (before + usize::from(sector)) * SECTOR
    }
}

/// A file to put on a disk: its directory type byte, name, sectors in
/// chain order and contents.
struct File {
    type_byte: u8,
    name: &'static str,
    sectors: Vec<(u8, u8)>,
    contents: Vec<u8>,
}

impl File {
    fn new(type_byte: u8, name: &'static str, sectors: &[(u8, u8)], contents: Vec<u8>) -> Self {
        Self {
            type_byte,
            name,
            sectors: sectors.to_vec(),
            contents,
        }
    }
}

/// A 32-byte directory entry: next-sector link (written by the caller in
/// the first slot), type, first track and sector, name padded with 0xA0,
/// REL fields and GEOS bytes zero, size in sectors (little-endian).
fn entry(type_byte: u8, first: (u8, u8), name: &str, blocks: u16) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[2] = type_byte;
    e[3] = first.0;
    e[4] = first.1;
    e[5..21].fill(0xa0);
    e[5..5 + name.len()].copy_from_slice(name.as_bytes());
    e[30..32].copy_from_slice(&blocks.to_le_bytes());
    e
}

/// Write `contents` along a sector chain: each sector links to the next
/// (track, sector) and holds 254 data bytes; the last sector has track 0
/// and the index of its last used byte.
fn write_chain(image: &mut [u8], drive: Drive, sectors: &[(u8, u8)], contents: &[u8]) {
    let pieces: Vec<&[u8]> = contents.chunks(254).collect();
    assert_eq!(pieces.len(), sectors.len(), "chain length");
    for (i, (&(track, sector), piece)) in sectors.iter().zip(&pieces).enumerate() {
        let at = drive.offset(track, sector);
        match sectors.get(i + 1) {
            Some(&(next_track, next_sector)) => {
                image[at] = next_track;
                image[at + 1] = next_sector;
            }
            None => {
                image[at] = 0;
                image[at + 1] = u8::try_from(piece.len() + 1).expect("piece of 254 B at most");
            }
        }
        image[at + 2..at + 2 + piece.len()].copy_from_slice(piece);
    }
}

/// Mark `sector` of `track` used in a BAM bitmap (bit set = free, LSB first).
fn allocate(bitmap: &mut [u8], sector: u8) {
    bitmap[usize::from(sector / 8)] &= !(1 << (sector % 8));
}

/// A 1541 or 1571 image: BAM at 18/0 (directory link 18/1, DOS version
/// `A`, double-sided flag 0x80 on the 1571; per-track free counts and
/// bitmaps; disk name `ZRAX TEST` and the 0xA0 fill; ID `ZX`; DOS type
/// `2A`), one directory sector at 18/1 (link 00/FF) with `files` and any
/// `extra` entries, and the files' chains.
fn disk_1541(drive: Drive, files: &[File], extra: &[[u8; 32]]) -> Vec<u8> {
    let mut image = vec![0u8; drive.sectors() * SECTOR];
    let bam_at = drive.offset(18, 0);
    let dir_at = drive.offset(18, 1);
    for file in files {
        write_chain(&mut image, drive, &file.sectors, &file.contents);
    }
    let mut used: Vec<(u8, u8)> = files.iter().flat_map(|f| f.sectors.clone()).collect();
    used.extend([(18, 0), (18, 1)]);
    let bam = &mut image[bam_at..bam_at + SECTOR];
    bam[..4].copy_from_slice(&[18, 1, 0x41, 0]);
    if matches!(drive, Drive::C1571) {
        bam[3] = 0x80;
    }
    for track in 1..=35u8 {
        let spt = drive.sectors_per_track(track);
        let mut bitmap = [0u8; 3];
        for sector in 0..spt {
            bitmap[sector / 8] |= 1 << (sector % 8);
        }
        for &(t, s) in used.iter().filter(|(t, _)| *t == track) {
            assert_eq!(t, track);
            allocate(&mut bitmap, s);
        }
        let free = bitmap.iter().map(|b| b.count_ones()).sum::<u32>();
        let at = 4 + 4 * usize::from(track - 1);
        bam[at] = u8::try_from(free).expect("at most 21 sectors");
        bam[at + 1..at + 4].copy_from_slice(&bitmap);
    }
    if matches!(drive, Drive::C1571) {
        for track in 36..=70u8 {
            let used_here = used.iter().filter(|(t, _)| *t == track).count();
            let free = drive.sectors_per_track(track) - used_here;
            bam[0xdd + usize::from(track - 36)] = u8::try_from(free).expect("at most 21");
        }
    }
    bam[0x90..0xab].fill(0xa0);
    bam[0x90..0x99].copy_from_slice(b"ZRAX TEST");
    bam[0xa2..0xa4].copy_from_slice(b"ZX");
    bam[0xa5..0xa7].copy_from_slice(b"2A");
    let dir = &mut image[dir_at..dir_at + SECTOR];
    let entries = files
        .iter()
        .map(|f| entry(f.type_byte, f.sectors[0], f.name, f.sectors.len() as u16))
        .chain(extra.iter().copied());
    for (slot, e) in entries.enumerate() {
        dir[slot * 32..slot * 32 + 32].copy_from_slice(&e);
    }
    dir[0] = 0;
    dir[1] = 0xff;
    image
}

/// A 1581 image: header at 40/0 (`28 03 44 00`, name `ZRAX D81`, 0xA0 fill,
/// ID `ZX`, `3D`), BAM sectors 40/1 (link 40/2) and 40/2 (link 00/FF), both
/// with version `D`, complement 0xBB, the ID and the I/O byte 0xC0, and
/// full free counts; one directory sector at 40/3 with `files` and `extra`.
fn disk_1581(files: &[File], extra: &[[u8; 32]]) -> Vec<u8> {
    let drive = Drive::C1581;
    let mut image = vec![0u8; drive.sectors() * SECTOR];
    for file in files {
        write_chain(&mut image, drive, &file.sectors, &file.contents);
    }
    let header_at = drive.offset(40, 0);
    let header = &mut image[header_at..header_at + SECTOR];
    header[..4].copy_from_slice(&[0x28, 0x03, 0x44, 0x00]);
    header[0x04..0x1d].fill(0xa0);
    header[0x04..0x0c].copy_from_slice(b"ZRAX D81");
    header[0x16..0x18].copy_from_slice(b"ZX");
    header[0x19..0x1b].copy_from_slice(b"3D");
    for (sector, link) in [(1u8, [0x28, 0x02]), (2, [0x00, 0xff])] {
        let at = drive.offset(40, sector);
        let bam = &mut image[at..at + SECTOR];
        bam[..2].copy_from_slice(&link);
        bam[2..7].copy_from_slice(&[0x44, 0xbb, b'Z', b'X', 0xc0]);
        for track in 0..40 {
            let entry = 0x10 + 6 * track;
            bam[entry] = 40;
            bam[entry + 1..entry + 6].fill(0xff);
        }
    }
    let dir_at = drive.offset(40, 3);
    let dir = &mut image[dir_at..dir_at + SECTOR];
    let entries = files
        .iter()
        .map(|f| entry(f.type_byte, f.sectors[0], f.name, f.sectors.len() as u16))
        .chain(extra.iter().copied());
    for (slot, e) in entries.enumerate() {
        dir[slot * 32..slot * 32 + 32].copy_from_slice(&e);
    }
    dir[0] = 0;
    dir[1] = 0xff;
    image
}

/// The standard test disk: a 600-byte program at 0xC000 on 17/0, 17/10,
/// 17/20 (interleave 10), a one-sector SEQ file on 19/0, a USR file on
/// 16/0, and a closed DEL entry used as a separator.
fn d64_files() -> Vec<File> {
    vec![
        File::new(
            0x82,
            "ZRAX DEMO",
            &[(17, 0), (17, 10), (17, 20)],
            prg(0xc000, &code(600)),
        ),
        File::new(0x81, "NOTES", &[(19, 0)], b"HELLO FROM ZRAX\r".to_vec()),
        File::new(0xc3, "DRIVE CODE", &[(16, 0)], code(40)),
    ]
}

fn separator() -> [u8; 32] {
    entry(0x80, (0, 0), "----------", 0)
}

fn d64() -> Vec<u8> {
    disk_1541(Drive::C1541 { tracks: 35 }, &d64_files(), &[separator()])
}

/// A T64 tape: signature `C64S tape image file` padded with NULs to 32 B,
/// version 0x0101, `entries` directory entries of which `records` are
/// used, description padded with spaces, the records, then the data.
fn t64(entries: u16, records: &[[u8; 32]], data: &[u8]) -> Vec<u8> {
    let mut tape = vec![0u8; 64];
    tape[..20].copy_from_slice(b"C64S tape image file");
    tape[0x20..0x22].copy_from_slice(&0x0101u16.to_le_bytes());
    tape[0x22..0x24].copy_from_slice(&entries.to_le_bytes());
    tape[0x24..0x26].copy_from_slice(&(records.len() as u16).to_le_bytes());
    tape[0x28..0x40].fill(b' ');
    tape[0x28..0x31].copy_from_slice(b"ZRAX TAPE");
    for i in 0..usize::from(entries) {
        tape.extend_from_slice(records.get(i).unwrap_or(&[0u8; 32]));
    }
    tape.extend_from_slice(data);
    tape
}

/// A T64 record: entry type, CBM file type, start and end address, data
/// offset (little-endian), name padded with spaces.
fn t64_record(
    entry_type: u8,
    cbm_type: u8,
    start: u16,
    end: u16,
    offset: u32,
    name: &str,
) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = entry_type;
    r[1] = cbm_type;
    r[2..4].copy_from_slice(&start.to_le_bytes());
    r[4..6].copy_from_slice(&end.to_le_bytes());
    r[8..12].copy_from_slice(&offset.to_le_bytes());
    r[16..32].fill(b' ');
    r[16..16 + name.len()].copy_from_slice(name.as_bytes());
    r
}

/// The BASIC stub and the routine, loaded at 0x0801.
fn basic_program() -> Vec<u8> {
    let mut program = BASIC_STUB.to_vec();
    program.extend(code(300));
    program
}

/// A tape with one BASIC program at 0x0801 and a SEQ file, in 30
/// directory entries.
fn tape() -> Vec<u8> {
    let program = basic_program();
    let data_start = 64 + 30 * 32;
    let seq = b"SOME DATA".to_vec();
    let program_end = 0x0801 + program.len() as u16;
    let records = [
        t64_record(
            1,
            0x82,
            0x0801,
            program_end,
            data_start as u32,
            "ZRAX TAPE PRG",
        ),
        t64_record(
            1,
            0x81,
            0x1000,
            0x1000 + seq.len() as u16,
            (data_start + program.len()) as u32,
            "ZRAX DATA",
        ),
    ];
    let mut data = program;
    data.extend_from_slice(&seq);
    t64(30, &records, &data)
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

/// The value of custom metadata entry `key`, as text.
fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

#[test]
fn d64_programs_are_6502_code_after_their_load_address() {
    let image = d64();
    assert_eq!(image.len(), 174_848);
    assert_eq!(cbm::detect_weak(&image), Some(Layout::Disk(DiskImage::D64)));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::D64);
    assert!(p.format.confidence < 1.0, "D64 detection is weak");
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert_eq!(p.primary.bitwidth, 8);
    assert_eq!(p.primary.endianness, Endianness::Little);
    let program = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("PRG \"ZRAX DEMO\" at 0xC000"))
        .expect("program slice");
    assert_eq!(program.isa, Isa::Mcs6502);
    assert_eq!(program.offset, 0x15000, "stored at 17/0");
    assert_eq!(program.size, 256, "17/10 does not follow 17/0");
    let decoded = program.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "D64 sector chain");
    assert_eq!(decoded.size, 600, "the load address is not code");
    let seq = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("SEQ \"NOTES\""))
        .expect("SEQ slice");
    assert!(matches!(seq.isa, Isa::Unknown(_)), "SEQ files are data");
    assert_eq!(seq.offset, 0x17800, "stored at 19/0");
    assert_eq!(seq.decoded.as_ref().map(|d| d.size), Some(16));
    assert!(p
        .slices
        .iter()
        .any(|s| s.label.as_deref() == Some("USR \"DRIVE CODE\" (locked)")));
    assert_eq!(p.slices.len(), 3, "the DEL entry is skipped");
    assert!(has_note(
        &p,
        "Disk \"ZRAX TEST\" ID \"ZX\" DOS type \"2A\"; 35 tracks, 683 sectors of 256 B; 3 files \
            listed; 659 blocks free"
    ));
    assert!(has_note(&p, "1 DEL entry skipped"));
    assert!(has_note(&p, "SEQ \"NOTES\": opaque"));
    assert_eq!(metadata(&p, "cbm_disk_name"), Some("ZRAX TEST".to_string()));
    assert_eq!(metadata(&p, "cbm_blocks_free"), Some("659".to_string()));
}

#[test]
fn disks_without_programs_have_no_isa() {
    let files = [File::new(0x81, "ONLY DATA", &[(19, 0)], b"DATA".to_vec())];
    let p = classify(&disk_1541(Drive::C1541 { tracks: 35 }, &files, &[]));
    assert_eq!(p.format.format, FileFormat::D64);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    let empty = disk_1541(Drive::C1541 { tracks: 35 }, &[], &[]);
    let p = classify(&empty);
    assert_eq!(p.format.format, FileFormat::D64);
    assert!(has_note(&p, "0 files listed"));
}

#[test]
fn error_bytes_and_forty_tracks_are_recognized() {
    let mut image = d64();
    let mut errors = vec![0x01u8; 683];
    errors[5] = 0x05;
    image.extend_from_slice(&errors);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::D64);
    assert!(has_note(
        &p,
        "683 error bytes follow the sectors; 1 sector reports a drive error (first: sector 1/5, \
            code 0x05)"
    ));

    let drive = Drive::C1541 { tracks: 40 };
    let files = [File::new(
        0x82,
        "HIGH TRACK",
        &[(38, 0), (38, 1)],
        prg(0x0801, &code(400)),
    )];
    let image = disk_1541(drive, &files, &[]);
    assert_eq!(image.len(), 196_608);
    assert_eq!(
        cbm::detect_weak(&image),
        Some(Layout::Disk(DiskImage::D64Extended))
    );
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::D64);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    let program = &p.slices[0];
    assert_eq!(program.offset, drive.offset(38, 0) as u64);
    assert_eq!(program.size, 512, "38/0 and 38/1 are adjacent");
    let mut with_errors = image;
    with_errors.extend(vec![0x01u8; 768]);
    assert_eq!(with_errors.len(), 197_376);
    assert_eq!(
        cbm::detect_weak(&with_errors),
        Some(Layout::Disk(DiskImage::D64Extended))
    );
}

#[test]
fn d71_files_reach_the_second_side() {
    let drive = Drive::C1571;
    let files = [File::new(
        0x82,
        "SIDE ONE",
        &[(40, 0), (40, 6)],
        prg(0x1c01, &code(300)),
    )];
    let image = disk_1541(drive, &files, &[]);
    assert_eq!(image.len(), 349_696);
    assert_eq!(drive.offset(40, 0), 0x2ff00, "VICE D71 table");
    assert_eq!(cbm::detect_weak(&image), Some(Layout::Disk(DiskImage::D71)));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::D71);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert_eq!(
        p.slices[0].label.as_deref(),
        Some("PRG \"SIDE ONE\" at 0x1C01")
    );
    assert_eq!(p.slices[0].offset, 0x2ff00);
    // 1366 sectors minus tracks 18 and 53 (19 each) minus the two file
    // sectors on track 40.
    assert!(has_note(&p, "1 file listed; 1326 blocks free"));

    let mut single = image.clone();
    single[drive.offset(18, 0) + 3] = 0;
    assert_eq!(cbm::detect_weak(&single), None, "a D71 BAM is double-sided");
    assert!(cbm::parse_container(&single, Layout::Disk(DiskImage::D71)).is_err());
}

#[test]
fn d81_programs_and_partitions() {
    let drive = Drive::C1581;
    let files = [File::new(
        0x82,
        "D81 PROG",
        &[(39, 0), (39, 1), (39, 2)],
        prg(0x2000, &code(700)),
    )];
    let partition = entry(0x85, (41, 0), "PARTITION", 120);
    let image = disk_1581(&files, &[partition]);
    assert_eq!(image.len(), 819_200);
    assert_eq!(cbm::detect_weak(&image), Some(Layout::Disk(DiskImage::D81)));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::D81);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    let program = &p.slices[0];
    assert_eq!(program.label.as_deref(), Some("PRG \"D81 PROG\" at 0x2000"));
    assert_eq!(program.offset, drive.offset(39, 0) as u64);
    assert_eq!(
        program.size,
        3 * 256,
        "interleave 1 keeps the chain adjacent"
    );
    assert_eq!(program.decoded.as_ref().map(|d| d.size), Some(700));
    let part = &p.slices[1];
    assert_eq!(part.label.as_deref(), Some("CBM \"PARTITION\" partition"));
    assert_eq!(part.offset, 0x64000, "41/0");
    assert_eq!(part.size, 120 * 256);
    assert!(matches!(part.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "Disk \"ZRAX D81\" ID \"ZX\" DOS type \"3D\"; 80 tracks, 3200 sectors"
    ));
    // 79 tracks of 40 free sectors outside the directory track.
    assert_eq!(metadata(&p, "cbm_blocks_free"), Some((79 * 40).to_string()));

    let mut errors = image.clone();
    errors.extend(vec![0x01u8; 3200]);
    assert_eq!(errors.len(), 822_400);
    assert_eq!(classify(&errors).format.format, FileFormat::D81);

    for (sector, at) in [(0u8, 2usize), (1, 3), (2, 3)] {
        let mut bad = image.clone();
        bad[drive.offset(40, sector) + at] ^= 0x01;
        assert_eq!(cbm::detect_weak(&bad), None, "40/{sector} byte {at}");
        assert!(cbm::parse_container(&bad, Layout::Disk(DiskImage::D81)).is_err());
    }
}

#[test]
fn bam_signature_and_directory_chain_are_required() {
    let drive = Drive::C1541 { tracks: 35 };
    let image = d64();
    let bam = drive.offset(18, 0);
    let dir = drive.offset(18, 1);
    for (at, value) in [(bam, 17u8), (bam + 1, 4), (bam + 2, 0x42)] {
        let mut bad = image.clone();
        bad[at] = value;
        assert_eq!(cbm::detect_weak(&bad), None, "BAM byte 0x{at:X}");
        let error = cbm::parse_container(&bad, Layout::Disk(DiskImage::D64))
            .expect_err("invalid BAM")
            .to_string();
        assert!(
            error.starts_with("Commodore image parse error: Invalid BAM at 0x16500"),
            "{error}"
        );
    }
    // A directory link outside the disk.
    let mut bad = image.clone();
    bad[dir] = 36;
    bad[dir + 1] = 0;
    assert_eq!(cbm::detect_weak(&bad), None);
    let error = cbm::parse_container(&bad, Layout::Disk(DiskImage::D64))
        .expect_err("link outside the disk")
        .to_string();
    assert!(
        error.contains("sector 36/0 is outside the 35-track disk"),
        "{error}"
    );
    // A directory sector that links back to itself.
    let mut looped = image.clone();
    looped[dir] = 18;
    looped[dir + 1] = 1;
    assert_eq!(cbm::detect_weak(&looped), None);
    let error = cbm::parse_container(&looped, Layout::Disk(DiskImage::D64))
        .expect_err("loop")
        .to_string();
    assert!(
        error.contains("sector 18/1 at 0x16600 is linked twice"),
        "{error}"
    );
    // A one-byte size change is not a disk image.
    let mut longer = image.clone();
    longer.push(0);
    assert_eq!(cbm::detect_weak(&longer), None);
    assert!(cbm::parse_container(&longer, Layout::Disk(DiskImage::D64)).is_err());
}

#[test]
fn an_extended_directory_is_followed_off_track_18() {
    let drive = Drive::C1541 { tracks: 35 };
    let mut image = disk_1541(drive, &d64_files(), &[]);
    let dir = drive.offset(18, 1);
    image[dir] = 19;
    image[dir + 1] = 6;
    let next = drive.offset(19, 6);
    let extra = entry(0x82, (20, 0), "OFF TRACK", 1);
    image[next..next + 32].copy_from_slice(&extra);
    image[next] = 0;
    image[next + 1] = 0xff;
    write_chain(&mut image, drive, &[(20, 0)], &prg(0x0801, &code(20)));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::D64);
    assert!(p
        .slices
        .iter()
        .any(|s| s.label.as_deref() == Some("PRG \"OFF TRACK\" at 0x0801")));
    assert_eq!(metadata(&p, "cbm_directory_sectors"), Some("2".to_string()));
}

#[test]
fn damaged_files_are_notes_not_errors() {
    let drive = Drive::C1541 { tracks: 35 };
    let files = [
        // A chain that loops from 17/10 back to 17/0.
        File::new(0x82, "LOOP", &[(17, 0), (17, 10)], prg(0xc000, &code(400))),
        // A chain that links outside the disk.
        File::new(0x82, "OUTSIDE", &[(16, 0)], prg(0xc000, &code(100))),
        // A program of only its load address.
        File::new(0x82, "EMPTY", &[(15, 0)], prg(0x0801, &[])),
        // A file whose directory size is wrong.
        File::new(0x82, "MISCOUNT", &[(14, 0)], prg(0x0801, &code(30))),
        // A splat file (not closed).
        File::new(0x02, "SPLAT", &[(13, 0)], prg(0x0801, &code(30))),
    ];
    let mut image = disk_1541(drive, &files, &[entry(0x87, (12, 0), "BAD TYPE", 1)]);
    let loop_at = drive.offset(17, 10);
    image[loop_at] = 17;
    image[loop_at + 1] = 0;
    let outside = drive.offset(16, 0);
    image[outside] = 36;
    image[outside + 1] = 0;
    let dir = drive.offset(18, 1);
    image[dir + 3 * 32 + 30] = 9;
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::D64);
    assert!(has_note(
        &p,
        "Skipped PRG \"LOOP\" at 0x16600: its chain visits sector 17/0 twice"
    ));
    assert!(has_note(
        &p,
        "Skipped PRG \"OUTSIDE\" at 0x16620: its chain links to sector 36/0, outside the disk"
    ));
    assert!(has_note(
        &p,
        "PRG \"EMPTY\": 2 B hold no program after a load address"
    ));
    assert!(has_note(
        &p,
        "PRG \"MISCOUNT\": the directory lists 9 blocks; its chain has 1 sectors"
    ));
    assert!(has_note(
        &p,
        "Skipped entry \"BAD TYPE\" at 0x166A0: file type 0x87 is not defined for this drive"
    ));
    let labels: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(
        labels,
        [
            "PRG \"EMPTY\"",
            "PRG \"MISCOUNT\" at 0x0801",
            "PRG \"SPLAT\" at 0x0801 (not closed)"
        ]
    );
    assert!(
        matches!(p.slices[0].isa, Isa::Unknown(_)),
        "no code to classify"
    );
}

#[test]
fn t64_records_load_at_their_start_address() {
    let tape = tape();
    assert_eq!(cbm::detect(&tape), Some(Layout::T64));
    let p = classify(&tape);
    assert_eq!(p.format.format, FileFormat::T64);
    assert!(
        (p.format.confidence - 1.0).abs() < f64::EPSILON,
        "T64 detection is strong"
    );
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    let program = &p.slices[0];
    assert_eq!(
        program.label.as_deref(),
        Some("PRG \"ZRAX TAPE PRG\" at 0x0801")
    );
    assert_eq!(program.offset, 64 + 30 * 32);
    assert_eq!(
        program.size,
        basic_program().len() as u64,
        "no load address in T64 data"
    );
    assert!(program.decoded.is_none());
    let seq = &p.slices[1];
    assert_eq!(seq.label.as_deref(), Some("SEQ \"ZRAX DATA\""));
    assert!(matches!(seq.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "T64 version 1.1 tape \"ZRAX TAPE\"; 2 of 30 directory entries used; 2 files listed"
    ));
    assert_eq!(
        metadata(&p, "cbm_tape_description"),
        Some("ZRAX TAPE".to_string())
    );
    for signature in [&b"C64 tape image file"[..], b"C64S tape file\0\0\0\0\0\0"] {
        let mut other = tape.clone();
        other[..signature.len()].copy_from_slice(signature);
        assert_eq!(classify(&other).format.format, FileFormat::T64);
    }
}

#[test]
fn t64_end_addresses_are_repaired_as_vice_does() {
    let program = basic_program();
    let data_start = 64 + 2 * 32;
    // conv64 wrote 0xC3C6 as the end address of every file.
    let records = [
        t64_record(1, 0x82, 0x0801, 0xc3c6, data_start as u32, "FIRST"),
        t64_record(1, 0x82, 0x0801, 0xc3c6, (data_start + 100) as u32, "SECOND"),
    ];
    let p = classify(&t64(2, &records, &program));
    assert_eq!(p.format.format, FileFormat::T64);
    assert_eq!(p.slices[0].size, 100, "up to the next file");
    assert_eq!(
        p.slices[1].size,
        program.len() as u64 - 100,
        "up to the end of the tape"
    );
    assert!(has_note(
        &p,
        "Entry 1 \"FIRST\": end address 0xC3C6 names 48069 B; read as 100 B up to the next file"
    ));
    // A zero directory size is read as one entry.
    let records = [t64_record(1, 0x82, 0x0801, 0x0805, 0x60, "ZERO")];
    let mut tape = t64(1, &records, &[1, 2, 3, 4]);
    tape[0x22] = 0;
    tape[0x24] = 0;
    let p = classify(&tape);
    assert_eq!(p.slices.len(), 1);
    assert!(has_note(&p, "read as 1, as VICE does"));
}

#[test]
fn t64_header_and_record_damage() {
    let tape = tape();
    let mut used = tape.clone();
    used[0x24] = 31;
    let error = classify_error(&used);
    assert!(
        error.contains("Invalid T64 header: 31 used entries exceed 30 directory entries"),
        "{error}"
    );
    let mut short = tape.clone();
    short.truncate(64 + 10 * 32);
    let error = classify_error(&short);
    assert!(error.contains("Truncated T64 directory"), "{error}");
    let mut outside = tape.clone();
    outside[0x40 + 8..0x40 + 12].copy_from_slice(&0x10u32.to_le_bytes());
    let p = classify(&outside);
    assert!(has_note(
        &p,
        "Skipped entry 1 \"ZRAX TAPE PRG\": data offset 0x10 is outside the file data"
    ));
    let mut snapshot = tape.clone();
    snapshot[0x40] = 3;
    let p = classify(&snapshot);
    assert!(has_note(
        &p,
        "Skipped entry 1 \"ZRAX TAPE PRG\": entry type 3 is not read"
    ));
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

fn classify_error(data: &[u8]) -> String {
    detect_payload(data, &ClassifierOptions::new())
        .expect_err("parse error")
        .to_string()
}

#[test]
fn prefixes_are_not_disks_and_tapes_claim_only_present_bytes() {
    let image = d64();
    for end in 0..image.len() {
        assert_eq!(cbm::detect_weak(&image[..end]), None, "prefix {end}");
        assert!(cbm::parse_container(&image[..end], Layout::Disk(DiskImage::D64)).is_err());
    }
    for end in (0..image.len()).step_by(4093) {
        let _ = detect_payload(&image[..end], &ClassifierOptions::new());
    }
    let tape = tape();
    for end in 0..tape.len() {
        let prefix = &tape[..end];
        if let Ok(c) = cbm::parse_container(prefix, Layout::T64) {
            for child in &c.children {
                assert!(
                    child.offset + child.stored_size <= end,
                    "prefix {end}: {}",
                    child.label
                );
            }
        }
        let _ = detect_payload(prefix, &ClassifierOptions::new());
    }
}

/// Parse `image` as `layout` with each of 0x00, 0xFF and a bit flip at
/// each of `positions`, classifying every `classify_every`th.
fn mutate(image: &mut [u8], layout: Layout, positions: impl Iterator<Item = usize>, every: usize) {
    for (n, at) in positions.enumerate() {
        let original = image[at];
        for value in [0x00, 0xff, original ^ 0x01] {
            image[at] = value;
            let detected = cbm::detect(image).or_else(|| cbm::detect_weak(image));
            if let Some(found) = detected {
                assert_eq!(found, layout);
            }
            let _ = cbm::parse_container(image, layout);
            if n % every == 0 {
                let _ = detect_payload(image, &ClassifierOptions::new());
            }
        }
        image[at] = original;
    }
}

#[test]
fn mutations_never_panic() {
    let drive = Drive::C1541 { tracks: 35 };
    let mut image = d64();
    // The BAM and directory sectors, every file sector, then every 97th
    // byte.
    let sectors = [
        (18, 0),
        (18, 1),
        (17, 0),
        (17, 10),
        (17, 20),
        (19, 0),
        (16, 0),
    ];
    let positions: Vec<usize> = sectors
        .iter()
        .flat_map(|&(t, s)| drive.offset(t, s)..drive.offset(t, s) + SECTOR)
        .chain((0..image.len()).step_by(97))
        .collect();
    mutate(
        &mut image,
        Layout::Disk(DiskImage::D64),
        positions.into_iter(),
        61,
    );

    let files = [File::new(
        0x82,
        "D81 PROG",
        &[(39, 0), (39, 1)],
        prg(0x2000, &code(300)),
    )];
    let mut d81 = disk_1581(&files, &[entry(0x85, (41, 0), "PART", 120)]);
    let d81_drive = Drive::C1581;
    let positions: Vec<usize> = (0..4u8)
        .flat_map(|s| d81_drive.offset(40, s)..d81_drive.offset(40, s) + SECTOR)
        .chain(d81_drive.offset(39, 0)..d81_drive.offset(39, 2))
        .chain((0..d81.len()).step_by(4099))
        .collect();
    mutate(
        &mut d81,
        Layout::Disk(DiskImage::D81),
        positions.into_iter(),
        127,
    );

    let mut tape = tape();
    let len = tape.len();
    mutate(&mut tape, Layout::T64, 0..len, 13);
}

/// Link `sectors` into one chain; the last links to `last_link`.
fn link_sectors(image: &mut [u8], drive: Drive, sectors: &[(u8, u8)], last_link: (u8, u8)) {
    for (i, &(track, sector)) in sectors.iter().enumerate() {
        let at = drive.offset(track, sector);
        let (next_track, next_sector) = sectors.get(i + 1).copied().unwrap_or(last_link);
        image[at] = next_track;
        image[at + 1] = next_sector;
    }
}

#[test]
fn hostile_directories_stay_bounded() {
    // The directory runs from 40/3 through every sector of tracks 40-80,
    // 1637 sectors of 8 entries each, and every entry names a PRG whose
    // chain runs through all 1560 sectors of tracks 1-39 and then loops
    // back to 1/0. Listing examines at most 4096 entries, each walk ends
    // at the loop, and the problems are capped.
    let drive = Drive::C1581;
    let mut image = disk_1581(&[], &[]);
    let data: Vec<(u8, u8)> = (1..40u8)
        .flat_map(|t| (0..40u8).map(move |s| (t, s)))
        .collect();
    link_sectors(&mut image, drive, &data, (1, 0));
    let directory: Vec<(u8, u8)> = (40..=80u8)
        .flat_map(|t| (0..40u8).map(move |s| (t, s)))
        .filter(|&(t, s)| t != 40 || s >= 3)
        .collect();
    for &(track, sector) in &directory {
        let at = drive.offset(track, sector);
        for slot in 0..8 {
            let e = entry(0x82, (1, 0), "MANY", 1);
            image[at + slot * 32..at + slot * 32 + 32].copy_from_slice(&e);
        }
    }
    link_sectors(&mut image, drive, &directory, (0, 0xff));
    let started = std::time::Instant::now();
    let c = cbm::parse_container(&image, Layout::Disk(DiskImage::D81)).expect("parses");
    assert_eq!(c.children.len(), 0);
    let notes = c.notes.join("\n");
    assert!(
        notes.contains("9000 further directory entries were not examined (limit 4096)"),
        "{notes}"
    );
    assert!(
        notes.contains("4080 further problems were not listed"),
        "{notes}"
    );
    assert!(started.elapsed().as_secs() < 30, "bounded work");
}

#[test]
fn many_files_are_listed_up_to_the_component_limit() {
    // 37 directory sectors on track 40 and 600 more on tracks 41-56, all
    // entries naming one-sector programs on track 1.
    let drive = Drive::C1581;
    let mut image = disk_1581(&[], &[]);
    write_chain(&mut image, drive, &[(1, 0)], &prg(0x0801, &code(20)));
    let directory: Vec<(u8, u8)> = (40..=56u8)
        .flat_map(|t| (0..40u8).map(move |s| (t, s)))
        .filter(|&(t, s)| t != 40 || s >= 3)
        .collect();
    for &(track, sector) in &directory {
        let at = drive.offset(track, sector);
        for slot in 0..8 {
            let e = entry(0x82, (1, 0), "SAME", 1);
            image[at + slot * 32..at + slot * 32 + 32].copy_from_slice(&e);
        }
    }
    link_sectors(&mut image, drive, &directory, (0, 0xff));
    let c = cbm::parse_container(&image, Layout::Disk(DiskImage::D81)).expect("parses");
    assert_eq!(c.children.len(), 4096);
    let unexamined = directory.len() * 8 - 4096;
    assert!(c
        .notes
        .iter()
        .any(|n| n
            == &format!("{unexamined} further directory entries were not examined (limit 4096)")));
}
