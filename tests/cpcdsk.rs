//! Amstrad CPC and Spectrum +3 disk images: CPCEMU and Extended DSK
//! structure, the AMSDOS data, system and IBM formats and the +3 disk
//! specification, files reassembled from CP/M allocation blocks across
//! extents, AMSDOS and +3DOS headers (binary and CODE files as Z80 code,
//! BASIC and screens as opaque data), boot sectors, copy-protection notes,
//! standalone headered files, corrupt fields, and truncation and mutation
//! sweeps.

use zrax::formats::cpcdsk::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// A CPC routine, hand-assembled: `LD HL,0xC000` (21 00 C0), `LD DE,0xC001`
/// (11 01 C0), `LD BC,0x3FFF` (01 FF 3F), `LD (HL),0` (36 00), `LDIR` (ED
/// B0) to clear the screen, `CALL 0xBB18` (CD 18 BB, the firmware's `KM
/// WAIT KEY`), `RET` (C9).
const CPC_CODE: &[u8] = &[
    0x21, 0x00, 0xc0, 0x11, 0x01, 0xc0, 0x01, 0xff, 0x3f, 0x36, 0x00, 0xed, 0xb0, 0xcd, 0x18, 0xbb,
    0xc9,
];

/// A Spectrum routine, hand-assembled: `DI` (F3), `LD A,2` (3E 02), `OUT
/// (0xFE),A` (D3 FE) for a red border, `LD HL,0x4000` (21 00 40), then `LD
/// (HL),0xFF` (36 FF), `INC HL` (23), `LD A,H` (7C), `CP 0x58` (FE 58), `JR
/// NZ,-8` (20 F8) to fill the bitmap, `EI` (FB), `RET` (C9).
const SPECTRUM_CODE: &[u8] = &[
    0xf3, 0x3e, 0x02, 0xd3, 0xfe, 0x21, 0x00, 0x40, 0x36, 0xff, 0x23, 0x7c, 0xfe, 0x58, 0x20, 0xf8,
    0xfb, 0xc9,
];

/// The repository's synthetic x86-64 ELF header (256 B, two records).
const ELF_PAYLOAD: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/compressed/payload.elf"
);

const SECTOR_SIZE: usize = 512;
const BLOCK_SIZE: usize = 1024;
const RECORD_SIZE: usize = 128;
const HEADER_SIZE: usize = 128;
/// Records in one 16 KiB directory entry with 1 KiB blocks (EXM 0).
const RECORDS_PER_ENTRY: usize = 128;
/// AMSDOS file types ([AMSHDR]): contents in bits 1-3.
const AMSDOS_BASIC: u8 = 0x00;
const AMSDOS_BINARY: u8 = 0x02;
/// +3 BASIC header types ([P3MAN]).
const BASIC_PROGRAM: u8 = 0;
const BASIC_CODE: u8 = 3;
/// Data offset of a sector in a track block: after the 256-byte
/// Track-Info block.
const TRACK_INFO_SIZE: usize = 0x100;
/// The physical order of the CPC data and system formats: logical sectors
/// 0, 5, 1, 6, 2, 7, 3, 8, 4 (IDs C1, C6, C2, C7, ...).
const CPC_INTERLEAVE: [usize; 9] = [0, 5, 1, 6, 2, 7, 3, 8, 4];
const NO_INTERLEAVE: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];

/// `code` repeated to `len` bytes.
fn code(code: &[u8], len: usize) -> Vec<u8> {
    code.iter().copied().cycle().take(len).collect()
}

/// `value` divided by `divisor`, rounded up.
fn div_round_up(value: usize, divisor: usize) -> usize {
    value / divisor + usize::from(value % divisor != 0)
}

/// Recompute an AMSDOS header's checksum after a field changed.
fn fix_amsdos_checksum(file: &mut [u8]) {
    let sum: u16 = file[..67].iter().map(|&b| u16::from(b)).sum();
    file[67..69].copy_from_slice(&sum.to_le_bytes());
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn slice<'p>(p: &'p DetectionPayload, label: &str) -> &'p zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label}: {:?}", p.slices))
}

/// One sector of a track block.
#[derive(Clone)]
struct SectorData {
    /// ID field: cylinder, head, sector ID, size code.
    cylinder: u8,
    head: u8,
    id: u8,
    size_code: u8,
    /// FDC status registers recorded by the dump.
    st1: u8,
    st2: u8,
    /// Stored data.
    data: Vec<u8>,
}

/// A Track-Info block ([DSK], [EDSK]): `Track-Info\r\n` and a NUL
/// (0x00-0x0C), three unused bytes, track (0x10), side (0x11), data rate
/// and recording mode (0x12, 0x13: 0, unknown), sector size code (0x14),
/// sector count (0x15), gap 3 (0x16: 0x52), filler (0x17: 0xE5), then 8
/// bytes per sector (C, H, R, N, ST1, ST2 and the stored length in extended
/// images, zero in standard ones), zero to 0x100, then the sector data.
fn track_block(track: u8, side: u8, sectors: &[SectorData], extended: bool) -> Vec<u8> {
    let mut block = b"Track-Info\r\n\0".to_vec();
    block.resize(0x10, 0);
    block.extend_from_slice(&[track, side, 0, 0, 2]);
    block.push(u8::try_from(sectors.len()).expect("at most 29 sectors"));
    block.extend_from_slice(&[0x52, 0xe5]);
    for s in sectors {
        let length = if extended {
            u16::try_from(s.data.len()).expect("sector fits u16")
        } else {
            0
        };
        block.extend_from_slice(&[s.cylinder, s.head, s.id, s.size_code, s.st1, s.st2]);
        block.extend_from_slice(&length.to_le_bytes());
    }
    block.resize(TRACK_INFO_SIZE, 0);
    for s in sectors {
        block.extend_from_slice(&s.data);
    }
    block
}

/// The disk information block's first 0x30 bytes: the signature (34 B) and
/// the creator (14 B).
fn info_start(signature: &[u8; 34]) -> Vec<u8> {
    let mut info = signature.to_vec();
    info.extend_from_slice(b"zrax tests\0\0\0\0");
    info
}

/// A CPCEMU image ([DSK]): signature, creator, tracks (0x30), sides (0x31),
/// track block size (0x32, little-endian), zero to 0x100, then the track
/// blocks, each padded to that size.
fn standard_image(tracks: u8, sides: u8, blocks: &[Vec<u8>]) -> Vec<u8> {
    let size = blocks.iter().map(Vec::len).max().unwrap_or(TRACK_INFO_SIZE);
    let mut image = info_start(b"MV - CPCEMU Disk-File\r\nDisk-Info\r\n");
    image.extend_from_slice(&[tracks, sides]);
    image.extend_from_slice(&u16::try_from(size).expect("track fits u16").to_le_bytes());
    image.resize(0x100, 0);
    for block in blocks {
        let start = image.len();
        image.extend_from_slice(block);
        image.resize(start + size, 0);
    }
    image
}

/// An extended image ([EDSK]): signature, creator, tracks (0x30), sides
/// (0x31), two unused bytes, one size-table byte per track and side (block
/// size / 256; 0 for an unformatted track, which has no block), zero to
/// 0x100, then the blocks padded to 256-byte multiples.
fn extended_image(tracks: u8, sides: u8, blocks: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut image = info_start(b"EXTENDED CPC DSK File\r\nDisk-Info\r\n");
    image.extend_from_slice(&[tracks, sides, 0, 0]);
    let padded: Vec<Option<Vec<u8>>> = blocks
        .iter()
        .map(|block| {
            block.as_ref().map(|b| {
                let mut b = b.clone();
                b.resize(div_round_up(b.len(), 256) * 256, 0);
                b
            })
        })
        .collect();
    for block in &padded {
        let units = block.as_ref().map_or(0, |b| b.len() / 256);
        image.push(u8::try_from(units).expect("track fits the table"));
    }
    image.resize(0x100, 0);
    for block in padded.iter().flatten() {
        image.extend_from_slice(block);
    }
    image
}

/// A CP/M volume as AMSDOS or +3DOS lays it out: logical tracks of
/// 512-byte sectors with IDs from `first_id`, stored in `order`; `reserved`
/// system tracks, then 1 KiB blocks with the directory in blocks 0 and 1.
/// Unwritten bytes are the format filler 0xE5.
struct Volume {
    first_id: u8,
    sectors: usize,
    reserved: usize,
    order: Vec<usize>,
    /// Contents of each logical track.
    tracks: Vec<Vec<u8>>,
}

impl Volume {
    fn new(first_id: u8, sectors: usize, reserved: usize, tracks: usize, order: &[usize]) -> Self {
        Self {
            first_id,
            sectors,
            reserved,
            order: order[..sectors].to_vec(),
            tracks: vec![vec![0xe5; sectors * SECTOR_SIZE]; tracks],
        }
    }

    /// Write `bytes` at data-area address `address`.
    fn write(&mut self, address: usize, bytes: &[u8]) {
        let track_size = self.sectors * SECTOR_SIZE;
        for (i, &b) in bytes.iter().enumerate() {
            let at = address + i;
            self.tracks[self.reserved + at / track_size][at % track_size] = b;
        }
    }

    /// Write `bytes` at logical sector `index` of logical track `track`.
    fn write_sector(&mut self, track: usize, index: usize, bytes: &[u8]) {
        let start = index * SECTOR_SIZE;
        self.tracks[track][start..start + bytes.len()].copy_from_slice(bytes);
    }

    fn write_entry(&mut self, index: usize, entry: &[u8; 32]) {
        self.write(index * 32, entry);
    }

    /// Store `contents` in consecutive blocks from `first_block`, with one
    /// directory entry per 16 KiB extent from directory slot `slot`.
    /// Returns the next free slot.
    fn add_file(&mut self, slot: usize, name: &str, contents: &[u8], first_block: usize) -> usize {
        let blocks = div_round_up(contents.len(), BLOCK_SIZE);
        for i in 0..blocks {
            let end = contents.len().min((i + 1) * BLOCK_SIZE);
            self.write(
                (first_block + i) * BLOCK_SIZE,
                &contents[i * BLOCK_SIZE..end],
            );
        }
        let records = div_round_up(contents.len(), RECORD_SIZE);
        let extents = div_round_up(records, RECORDS_PER_ENTRY).max(1);
        for extent in 0..extents {
            let held = (records - extent * RECORDS_PER_ENTRY).min(RECORDS_PER_ENTRY);
            let first = first_block + extent * 16;
            let numbers: Vec<u8> = (first..first + div_round_up(held, 8))
                .map(|b| u8::try_from(b).expect("8-bit block numbers"))
                .collect();
            let entry = dir_entry(
                0,
                name,
                u8::try_from(extent).expect("EX"),
                u8::try_from(held).expect("RC"),
                &numbers,
            );
            self.write_entry(slot + extent, &entry);
        }
        slot + extents
    }

    /// The sectors of logical track `track` in physical order.
    fn track_sectors(&self, track: usize, cylinder: u8, head: u8) -> Vec<SectorData> {
        self.order
            .iter()
            .map(|&index| SectorData {
                cylinder,
                head,
                id: self.first_id + u8::try_from(index).expect("sector index"),
                size_code: 2,
                st1: 0,
                st2: 0,
                data: self.tracks[track][index * SECTOR_SIZE..(index + 1) * SECTOR_SIZE].to_vec(),
            })
            .collect()
    }

    fn blocks(&self, extended: bool) -> Vec<Vec<u8>> {
        (0..self.tracks.len())
            .map(|t| {
                let cylinder = u8::try_from(t).expect("track number");
                track_block(cylinder, 0, &self.track_sectors(t, cylinder, 0), extended)
            })
            .collect()
    }

    fn standard_image(&self) -> Vec<u8> {
        let tracks = u8::try_from(self.tracks.len()).expect("track count");
        standard_image(tracks, 1, &self.blocks(false))
    }

    fn extended_image(&self) -> Vec<u8> {
        let tracks = u8::try_from(self.tracks.len()).expect("track count");
        let blocks: Vec<Option<Vec<u8>>> = self.blocks(true).into_iter().map(Some).collect();
        extended_image(tracks, 1, &blocks)
    }
}

/// A CP/M directory entry ([DRI] Figure 5-2): user (0), `NAME.EXT` as 8
/// and 3 space-padded characters (1-11), EX (12), S1 (13: 0), S2 (14: 0),
/// RC (15), then sixteen 8-bit block numbers (16-31).
fn dir_entry(user: u8, name: &str, extent: u8, records: u8, blocks: &[u8]) -> [u8; 32] {
    let (base, extension) = name.split_once('.').unwrap_or((name, ""));
    let mut entry = [0u8; 32];
    entry[0] = user;
    entry[1..12].fill(b' ');
    entry[1..1 + base.len()].copy_from_slice(base.as_bytes());
    entry[9..9 + extension.len()].copy_from_slice(extension.as_bytes());
    entry[12] = extent;
    entry[15] = records;
    entry[16..16 + blocks.len()].copy_from_slice(blocks);
    entry
}

/// An AMSDOS header ([AMSHDR]): user 0 (0), name and extension
/// space-padded (1-11), zeros (12-17), file type (18), data length (19-20:
/// 0, as AMSDOS leaves it), load address (21-22), first-block flag (23:
/// 0xFF), logical length (24-25), entry address (26-27), real length
/// (64-66), and the checksum, the 16-bit sum of bytes 0-66 (67-68).
fn amsdos_header(name: &str, file_type: u8, load: u16, entry: u16, length: usize) -> Vec<u8> {
    let (base, extension) = name.split_once('.').unwrap_or((name, ""));
    let mut header = vec![0u8; HEADER_SIZE];
    header[1..12].fill(b' ');
    header[1..1 + base.len()].copy_from_slice(base.as_bytes());
    header[9..9 + extension.len()].copy_from_slice(extension.as_bytes());
    header[18] = file_type;
    header[21..23].copy_from_slice(&load.to_le_bytes());
    header[23] = 0xff;
    let length = u16::try_from(length).expect("AMSDOS length fits u16");
    header[24..26].copy_from_slice(&length.to_le_bytes());
    header[26..28].copy_from_slice(&entry.to_le_bytes());
    header[64..66].copy_from_slice(&length.to_le_bytes());
    let sum: u16 = header[..67].iter().map(|&b| u16::from(b)).sum();
    header[67..69].copy_from_slice(&sum.to_le_bytes());
    header
}

/// A +3DOS header ([P3MAN]): `PLUS3DOS` (0-7), 0x1A (8), issue 1 (9),
/// version 0 (10), file length including the header (11-14), the +3 BASIC
/// header: type (15), length (16-17), parameter 1 (18-19), parameter 2
/// (20-21); zeros; and the checksum, the sum of bytes 0-126 modulo 256
/// (127).
fn plus3_header(basic_type: u8, length: usize, parameter_1: u16, parameter_2: u16) -> Vec<u8> {
    let mut header = b"PLUS3DOS\x1a\x01\x00".to_vec();
    let total = u32::try_from(length + HEADER_SIZE).expect("file length fits u32");
    header.extend_from_slice(&total.to_le_bytes());
    header.push(basic_type);
    header.extend_from_slice(&u16::try_from(length).expect("u16").to_le_bytes());
    header.extend_from_slice(&parameter_1.to_le_bytes());
    header.extend_from_slice(&parameter_2.to_le_bytes());
    header.resize(HEADER_SIZE - 1, 0);
    let sum = header.iter().fold(0u8, |s, &b| s.wrapping_add(b));
    header.push(sum);
    header
}

fn headered(header: Vec<u8>, body: &[u8]) -> Vec<u8> {
    let mut file = header;
    file.extend_from_slice(body);
    file
}

/// Tokenized BASIC stand-in: line 10, length, a `PRINT` token and text.
fn basic_program() -> Vec<u8> {
    let mut program = vec![0x10, 0x00, 0x0a, 0x00, 0xbf, 0x20, 0x22];
    program.extend_from_slice(b"zrax test disc\"");
    program.resize(200, 0);
    program
}

/// The CPC binary of the data-disk fixture: 1500 B of code.
fn disc_bin_body() -> Vec<u8> {
    code(CPC_CODE, 1500)
}

/// An AMSDOS data-format volume of `tracks` tracks: `DISC.BIN` (an AMSDOS
/// binary in blocks 2-3), `MENU.BAS` (AMSDOS BASIC in block 4, across
/// tracks 0 and 1), `PAYLOAD.ELF` (headerless ELF in block 5) and
/// `README.TXT` (headerless text in block 6).
fn data_volume(tracks: usize) -> Volume {
    let mut volume = Volume::new(0xc1, 9, 0, tracks, &CPC_INTERLEAVE);
    let body = disc_bin_body();
    let disc = headered(
        amsdos_header("DISC.BIN", AMSDOS_BINARY, 0x4000, 0x4000, body.len()),
        &body,
    );
    let mut slot = volume.add_file(0, "DISC.BIN", &disc, 2);
    let basic = basic_program();
    let menu = headered(
        amsdos_header("MENU.BAS", AMSDOS_BASIC, 0x0170, 0, basic.len()),
        &basic,
    );
    slot = volume.add_file(slot, "MENU.BAS", &menu, 4);
    let elf = std::fs::read(ELF_PAYLOAD).expect("committed fixture");
    slot = volume.add_file(slot, "PAYLOAD.ELF", &elf, 5);
    let text = b"this disc was written for the zrax tests and holds no program\r\n".repeat(4);
    volume.add_file(slot, "README.TXT", &text, 6);
    volume
}

#[test]
fn amsdos_data_disks_list_headered_binaries_as_z80_and_basic_as_opaque() {
    let image = data_volume(40).extended_image();
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::CpcDsk);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Extended CPC disk image")
    );
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(has_note(&p, "Primary ISA selected from 0:DISC.BIN"));
    assert!(has_note(
        &p,
        "AMSDOS data format: 9 sectors of 512 B per track from ID 0xC1"
    ));
    assert!(has_note(
        &p,
        "0:DISC.BIN: AMSDOS binary; load address 0x4000; entry 0x4000; 1500 B"
    ));
    // DISC.BIN starts 128 B into block 2, logical sector 4 of track 0 (ID
    // 0xC5, the ninth sector stored): the stored run is the rest of that
    // sector, and the other sectors follow elsewhere.
    let disc = slice(&p, "0:DISC.BIN");
    assert_eq!(disc.isa, Isa::Z80);
    // The platform fixes the CPU; the code model's variant guess is replaced.
    assert_eq!(disc.variant.as_ref().map(|v| v.name.as_str()), Some("Z80"));
    assert_eq!(disc.offset, 0x200 + 8 * 512 + 128);
    assert_eq!(disc.size, 384);
    let decoded = disc.decoded.as_ref().expect("reassembled");
    assert_eq!(decoded.transform, "CP/M allocation blocks");
    assert_eq!(decoded.size, 1500);
    let menu = slice(&p, "0:MENU.BAS");
    assert!(matches!(menu.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "0:MENU.BAS: opaque; payload ISA analysis skipped"
    ));
    // PAYLOAD.ELF is block 5: logical sector 1 of track 1 (ID 0xC2, stored
    // third), in one piece. Track 1's block starts at 0x100 + 0x1300.
    let elf = slice(&p, "0:PAYLOAD.ELF");
    assert_eq!(elf.isa, Isa::X86_64);
    assert_eq!((elf.offset, elf.size), (0x1400 + 0x100 + 2 * 512, 256));
    assert!(elf.decoded.is_none());
    assert!(p
        .slices
        .iter()
        .all(|s| s.label.as_deref() != Some("0:README.TXT")));
    assert!(has_note(
        &p,
        "1 headerless in no recognized format (not listed)"
    ));
    assert!(p
        .metadata
        .iter()
        .any(|m| m.label == "Filesystem" && m.value.to_string() == "AMSDOS data format"));
}

#[test]
fn standard_images_read_the_same_volume() {
    let image = data_volume(40).standard_image();
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::CpcDsk);
    assert_eq!(p.format.variant_name.as_deref(), Some("CPCEMU disk image"));
    assert_eq!(p.primary.isa, Isa::Z80);
    assert_eq!(slice(&p, "0:DISC.BIN").isa, Isa::Z80);
    assert!(has_note(
        &p,
        "Tracks: 40 formatted, 0 unformatted; 360 sectors"
    ));
}

#[test]
fn reassembled_files_hold_the_header_body() {
    let image = data_volume(40).extended_image();
    let c = cpcdsk::parse_container(&image, Layout::Extended).unwrap();
    let disc = c
        .children
        .iter()
        .find(|child| child.label == "0:DISC.BIN")
        .expect("DISC.BIN");
    assert_eq!(&disc.data[..], &disc_bin_body()[..]);
    assert!(!disc.opaque);
    let menu = c
        .children
        .iter()
        .find(|child| child.label == "0:MENU.BAS")
        .unwrap();
    assert!(menu.opaque);
    assert_eq!(&menu.data[..], &basic_program()[..]);
}

#[test]
fn multi_extent_files_follow_their_extent_numbers() {
    let mut volume = Volume::new(0xc1, 9, 0, 40, &CPC_INTERLEAVE);
    let body = code(CPC_CODE, 20_000);
    let file = headered(
        amsdos_header("BIG.BIN", AMSDOS_BINARY, 0x0100, 0x0100, body.len()),
        &body,
    );
    // 20128 B: 158 records in extent 0 (128 records, blocks 2-17) and
    // extent 1 (30 records, blocks 18-21). The directory lists extent 1
    // first.
    volume.add_file(0, "BIG.BIN", &file, 2);
    let first = dir_entry(0, "BIG.BIN", 0, 0x80, &(2..18).collect::<Vec<u8>>());
    let second = dir_entry(0, "BIG.BIN", 1, 30, &[18, 19, 20, 21]);
    volume.write_entry(0, &second);
    volume.write_entry(1, &first);
    let image = volume.extended_image();
    let c = cpcdsk::parse_container(&image, Layout::Extended).unwrap();
    let big = c
        .children
        .iter()
        .find(|child| child.label == "0:BIG.BIN")
        .unwrap();
    assert_eq!(&big.data[..], &body[..]);
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(has_note(&p, "1 file in 2 entries"));
}

/// A +3 disk ([P3MAN] type 0): IDs 1-9 in order, one reserved track, the
/// disk specification and a bootstrap (checksum 3) in track 0 sector 1,
/// and `GAME.BIN` (+3DOS CODE at 0x8000) in block 2.
fn plus3_game_volume(tracks: usize) -> Volume {
    let mut volume = Volume::new(0x01, 9, 1, tracks, &NO_INTERLEAVE);
    // Disk specification: type 0, single-sided, 40 tracks, 9 sectors,
    // 512-byte sectors (2), 1 reserved track, 1 KiB blocks (3), 2 directory
    // blocks, gaps 0x2A and 0x52, five reserved bytes, the checksum fiddle
    // byte; the bootstrap is entered at offset 0x10.
    let mut boot = vec![0, 0, 40, 9, 2, 1, 3, 2, 0x2a, 0x52, 0, 0, 0, 0, 0, 0];
    boot.extend_from_slice(SPECTRUM_CODE);
    boot.resize(SECTOR_SIZE, 0);
    let sum = boot.iter().fold(0u8, |s, &b| s.wrapping_add(b));
    boot[15] = 3u8.wrapping_sub(sum);
    volume.write_sector(0, 0, &boot);
    let game_body = code(SPECTRUM_CODE, 600);
    let game = headered(
        plus3_header(BASIC_CODE, game_body.len(), 0x8000, 0),
        &game_body,
    );
    volume.add_file(0, "GAME.BIN", &game, 2);
    volume
}

/// The +3 game disk with `SCREEN.SCR` (CODE of the 6912 B display file,
/// blocks 3-9) and `DISK` (a BASIC program with autostart line 10, block
/// 10).
fn plus3_volume(tracks: usize) -> Volume {
    let mut volume = plus3_game_volume(tracks);
    let screen_body = vec![0x55u8; 6912];
    let screen = headered(plus3_header(BASIC_CODE, 6912, 0x4000, 0), &screen_body);
    let slot = volume.add_file(1, "SCREEN.SCR", &screen, 3);
    let program = basic_program();
    let disk = headered(plus3_header(BASIC_PROGRAM, program.len(), 10, 0), &program);
    volume.add_file(slot, "DISK", &disk, 10);
    volume
}

#[test]
fn plus3_disks_read_the_disk_specification_and_the_bootstrap() {
    let image = plus3_volume(40).standard_image();
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::CpcDsk);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(has_note(&p, "+3DOS/PCW disk specification (disk type 0)"));
    assert!(has_note(&p, "0:GAME.BIN: +3DOS CODE; load address 0x8000"));
    assert_eq!(slice(&p, "0:GAME.BIN").isa, Isa::Z80);
    assert!(matches!(slice(&p, "0:SCREEN.SCR").isa, Isa::Unknown(_)));
    assert!(has_note(&p, "the display file (SCREEN$)"));
    assert!(has_note(
        &p,
        "0:DISK: +3DOS BASIC program, autostart line 10"
    ));
    // The bootstrap comes last, after the files, and starts at its entry.
    let boot = p.slices.last().expect("bootstrap slice");
    assert_eq!(
        boot.label.as_deref(),
        Some("+3 bootstrap (track 0, sector 1)")
    );
    assert_eq!(boot.isa, Isa::Z80);
    assert_eq!((boot.offset, boot.size), (0x200 + 0x10, 512 - 0x10));
    assert!(has_note(
        &p,
        "DOS BOOT loads the sector at 0xFE00 and enters it at 0xFE10"
    ));
    assert!(has_note(
        &p,
        "Files: 0 with an AMSDOS header, 3 with a +3DOS header"
    ));
}

#[test]
fn unwritten_specifications_select_the_default_plus3_format() {
    let mut volume = plus3_volume(4);
    volume.write_sector(0, 0, &[0xe5; SECTOR_SIZE]);
    let image = volume.standard_image();
    let p = classify(&image);
    assert!(has_note(&p, "+3DOS/PCW default format"));
    assert_eq!(slice(&p, "0:GAME.BIN").isa, Isa::Z80);
    assert!(!has_note(&p, "bootstrap"));
}

/// An AMSDOS system-format volume ([AMSROM]): IDs 0x41-0x49, two reserved
/// tracks, a CP/M boot sector in track 0 sector 0x41 and `CPM.BIN` in
/// blocks 2-3.
fn system_volume(tracks: usize) -> Volume {
    let mut volume = Volume::new(0x41, 9, 2, tracks, &CPC_INTERLEAVE);
    volume.write_sector(0, 0, &code(CPC_CODE, SECTOR_SIZE));
    let body = code(CPC_CODE, 700);
    let file = headered(
        amsdos_header("CPM.BIN", AMSDOS_BINARY, 0x8000, 0x8003, body.len()),
        &body,
    );
    volume.add_file(0, "CPM.BIN", &file, 2);
    volume
}

#[test]
fn system_disks_list_the_boot_sector_last_and_note_copy_protection() {
    let volume = system_volume(40);
    let mut blocks: Vec<Option<Vec<u8>>> = volume.blocks(true).into_iter().map(Some).collect();
    // Track 39 is replaced by a protected track: an 8 KiB sector stored as
    // 0x1800 B with a data error (ST1 bit 5), and a weak 512 B sector
    // stored twice. Track 40 is unformatted.
    let protected = [
        SectorData {
            cylinder: 39,
            head: 0,
            id: 0xf1,
            size_code: 6,
            st1: 0x20,
            st2: 0x20,
            data: vec![0x4e; 0x1800],
        },
        SectorData {
            cylinder: 39,
            head: 0,
            id: 0xf2,
            size_code: 2,
            st1: 0,
            st2: 0,
            data: (0..=255u8).cycle().take(1024).collect(),
        },
    ];
    blocks[39] = Some(track_block(39, 0, &protected, true));
    blocks.push(None);
    let image = extended_image(41, 1, &blocks);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::CpcDsk);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(has_note(&p, "AMSDOS system format"));
    assert!(has_note(&p, "Tracks: 40 formatted, 1 unformatted"));
    assert!(has_note(&p, "1 sector carries FDC status flags"));
    assert!(has_note(&p, "1 sector stores several copies"));
    assert!(has_note(&p, "AMSDOS |CPM loads it at 0x0100"));
    assert_eq!(slice(&p, "0:CPM.BIN").isa, Isa::Z80);
    let boot = p.slices.last().unwrap();
    assert_eq!(
        boot.label.as_deref(),
        Some("CP/M boot sector (track 0, sector 0x41)")
    );
    assert_eq!((boot.offset, boot.size), (0x200, 512));
    assert!(p
        .metadata
        .iter()
        .any(|m| m.label == "Unformatted tracks" && m.value.to_string() == "1"));
}

#[test]
fn vendor_disks_without_boot_code_have_no_boot_child() {
    let mut volume = system_volume(4);
    volume.write_sector(0, 0, &[0xe5; SECTOR_SIZE]);
    let p = classify(&volume.extended_image());
    assert!(has_note(&p, "Track 0 sector 0x41 is filled with 0xE5"));
    assert!(p
        .slices
        .iter()
        .all(|s| s.label.as_deref() != Some("CP/M boot sector (track 0, sector 0x41)")));
}

#[test]
fn ibm_format_disks_have_eight_sectors_and_one_reserved_track() {
    let mut volume = Volume::new(0x01, 8, 1, 6, &NO_INTERLEAVE);
    let body = code(CPC_CODE, 300);
    let file = headered(
        amsdos_header("IBM.BIN", AMSDOS_BINARY, 0x1000, 0x1000, body.len()),
        &body,
    );
    volume.add_file(0, "IBM.BIN", &file, 2);
    let p = classify(&volume.extended_image());
    assert!(has_note(
        &p,
        "AMSDOS IBM format: 8 sectors of 512 B per track from ID 0x01, 1 reserved track"
    ));
    assert_eq!(slice(&p, "0:IBM.BIN").isa, Isa::Z80);
}

#[test]
fn unknown_sector_ids_leave_no_filesystem() {
    let mut volume = data_volume(3);
    volume.first_id = 0x81;
    let p = classify(&volume.extended_image());
    assert_eq!(p.format.format, FileFormat::CpcDsk);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "No CP/M filesystem: the lowest sector ID on track 0 is 0x81, not 0x41, 0xC1 or 0x01"
    ));
}

#[test]
fn directory_damage_skips_files_with_notes() {
    let mut volume = data_volume(40);
    let body = code(CPC_CODE, 100);
    let small = headered(
        amsdos_header("X.BIN", AMSDOS_BINARY, 0x4000, 0x4000, body.len()),
        &body,
    );
    volume.write(20 * BLOCK_SIZE, &small);
    // Slots 4-9: a missing first extent, a block past the format's 180, a
    // block listed twice, a directory block, a sparse first extent, and an
    // AMSDOS header declaring more than the directory stores.
    volume.write_entry(4, &dir_entry(0, "MISSING.BIN", 1, 2, &[20]));
    volume.write_entry(5, &dir_entry(0, "OUTSIDE.BIN", 0, 2, &[250]));
    volume.write_entry(6, &dir_entry(0, "TWICE.BIN", 0, 16, &[20, 20]));
    volume.write_entry(7, &dir_entry(0, "DIRBLK.BIN", 0, 2, &[1]));
    volume.write_entry(8, &dir_entry(0, "SPARSE.BIN", 0, 0x10, &[20, 21]));
    volume.write_entry(9, &dir_entry(0, "SPARSE.BIN", 1, 2, &[22]));
    let long = headered(
        amsdos_header("LONG.BIN", AMSDOS_BINARY, 0x4000, 0x4000, 5000),
        &body,
    );
    volume.write(30 * BLOCK_SIZE, &long);
    volume.write_entry(10, &dir_entry(0, "LONG.BIN", 0, 2, &[30]));
    let p = classify(&volume.extended_image());
    assert_eq!(p.primary.isa, Isa::Z80);
    for note in [
        "Skipped 0:MISSING.BIN: extent 0 is missing",
        "Skipped 0:OUTSIDE.BIN: block 250 is beyond the format's 180 blocks",
        "Skipped 0:TWICE.BIN: block 20 appears twice",
        "Skipped 0:DIRBLK.BIN: block 1 is a directory block",
        "Skipped 0:SPARSE.BIN: extent 0 holds 16 of 128 records (a sparse file)",
        "0:LONG.BIN: AMSDOS binary; load address 0x4000; entry 0x4000; 128 B; the header \
         declares 5000 B, the directory 128 B",
    ] {
        assert!(has_note(&p, note), "{note}: {:?}", p.notes);
    }
    assert_eq!(slice(&p, "0:LONG.BIN").size, 128);
}

#[test]
fn standalone_plus3dos_code_loads_at_its_address() {
    let body = code(SPECTRUM_CODE, 600);
    let file = headered(plus3_header(BASIC_CODE, body.len(), 0x8000, 0), &body);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Plus3Dos);
    assert!(p.format.confidence > 0.99);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(p.metadata.iter().any(|m| m.label == "CODE at 0x8000"));
    assert!(has_note(&p, "checksum 0x"));
    // Record padding after the declared end is noted.
    let mut padded = file.clone();
    padded.resize(div_round_up(file.len(), 128) * 128, 0x1a);
    let p = classify(&padded);
    assert!(has_note(&p, "B of record padding after the file's end"));
    // BASIC is listed as opaque data and names no ISA.
    let program = basic_program();
    let basic = headered(
        plus3_header(BASIC_PROGRAM, program.len(), 0x8000, 0),
        &program,
    );
    let p = classify(&basic);
    assert_eq!(p.format.format, FileFormat::Plus3Dos);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(&p, "+3DOS BASIC program (not machine code)"));
}

#[test]
fn corrupt_plus3dos_headers_are_errors() {
    let body = code(SPECTRUM_CODE, 64);
    let file = headered(plus3_header(BASIC_CODE, body.len(), 0x8000, 0), &body);
    let error = |data: &[u8]| {
        detect_payload(data, &ClassifierOptions::new())
            .unwrap_err()
            .to_string()
    };
    let mut bad = file.clone();
    bad[40] ^= 1;
    assert!(error(&bad).contains("Invalid +3DOS header checksum"));
    assert!(error(&file[..file.len() - 1]).contains("Truncated +3DOS file"));
    let mut issue = file.clone();
    issue[9] = 2;
    issue[127] = issue[127].wrapping_add(1);
    assert!(error(&issue).contains("Unsupported +3DOS header issue 2"));
    assert!(error(&file[..100]).starts_with("CPC disk image parse error: Truncated +3DOS header"));
}

#[test]
fn standalone_amsdos_files_are_weak_and_validated() {
    let body = code(CPC_CODE, 300);
    let file = headered(
        amsdos_header("GAME.BIN", AMSDOS_BINARY, 0x4000, 0x4010, body.len()),
        &body,
    );
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Amsdos);
    assert!(p.format.confidence < 1.0);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(p
        .metadata
        .iter()
        .any(|m| m.label == "Entry address" && m.value.to_string() == "16400"));
    assert!(has_note(
        &p,
        "AMSDOS header: user 0, \"GAME.BIN\", file type 0x02; checksum"
    ));
    let c = cpcdsk::parse_container(&file, Layout::Amsdos).unwrap();
    assert_eq!(c.entry, Some(0x4010));
    assert_eq!(c.sections[0].address, 0x4000);
    // A changed field breaks the checksum; a fixed-up checksum with a bad
    // field, a size beyond the record, or a truncation is not AMSDOS.
    let not_amsdos = |data: &[u8]| {
        detect_payload(data, &ClassifierOptions::new())
            .map_or(true, |p| p.format.format != FileFormat::Amsdos)
    };
    let mut bad = file.clone();
    bad[5] = b'X';
    assert!(not_amsdos(&bad));
    let mut zero_field = file.clone();
    zero_field[13] = 1;
    fix_amsdos_checksum(&mut zero_field);
    assert!(not_amsdos(&zero_field));
    let mut long = file.clone();
    long.resize(HEADER_SIZE + 384 + 1, 0);
    assert!(not_amsdos(&long));
    assert!(not_amsdos(&file[..file.len() - 1]));
    let basic = headered(
        amsdos_header("MENU.BAS", AMSDOS_BASIC, 0x170, 0, 200),
        &basic_program(),
    );
    let p = classify(&basic);
    assert_eq!(p.format.format, FileFormat::Amsdos);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

#[test]
fn corrupt_images_are_errors() {
    let image = data_volume(3).extended_image();
    let error = |data: &[u8]| {
        detect_payload(data, &ClassifierOptions::new())
            .unwrap_err()
            .to_string()
    };
    let mut tag = image.clone();
    tag[0x100] = b'X';
    assert!(error(&tag).contains("Missing Track-Info block for track 0 side 0 at 0x100"));
    let mut sides = image.clone();
    sides[0x31] = 3;
    assert!(error(&sides).contains("Invalid side count 3"));
    let mut lengths = image.clone();
    // The first sector's stored length grows past the track.
    lengths[0x100 + 0x18 + 7] = 0x40;
    assert!(error(&lengths).contains("sector data ends"));
    assert!(error(&image[..image.len() - 1]).contains("Truncated track 2 side 0"));
    let standard = data_volume(3).standard_image();
    let mut code = standard.clone();
    code[0x100 + 0x14] = 7;
    assert!(error(&code).contains("Unsupported sector size code 7"));
}

#[test]
fn trailing_data_is_noted() {
    let mut image = data_volume(3).extended_image();
    image.extend_from_slice(b"Offset-Info\r\n\0\0\0\0");
    let p = classify(&image);
    assert!(has_note(&p, "are a LibDsk Offset-Info block (not used)"));
}

/// Small fixtures for the sweeps: three-track data and +3 disks in both
/// layouts, and the standalone headered files.
fn sweep_fixtures() -> Vec<(Layout, Vec<u8>)> {
    let body = code(CPC_CODE, 200);
    let amsdos = headered(
        amsdos_header("GAME.BIN", AMSDOS_BINARY, 0x4000, 0x4000, body.len()),
        &body,
    );
    let plus3 = headered(plus3_header(BASIC_CODE, body.len(), 0x8000, 0), &body);
    vec![
        (Layout::Extended, data_volume(3).extended_image()),
        (Layout::Standard, plus3_game_volume(3).standard_image()),
        (Layout::Plus3Dos, plus3),
        (Layout::Amsdos, amsdos),
    ]
}

#[test]
fn every_prefix_is_an_error_or_not_claimed() {
    for (layout, file) in sweep_fixtures() {
        let format = layout.format();
        for end in 0..file.len() {
            let prefix = &file[..end];
            assert!(
                cpcdsk::parse_container(prefix, layout).is_err(),
                "{layout:?} {end}"
            );
            if end % 97 == 0 || end < 300 {
                if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
                    assert_ne!(p.format.format, format, "{layout:?} prefix of {end} B");
                }
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    for (layout, file) in sweep_fixtures() {
        for i in 0..file.len() {
            for value in [0x00, 0xff, file[i] ^ 0x01, file[i] ^ 0x80, file[i] ^ 0x10] {
                let mut mutated = file.clone();
                mutated[i] = value;
                let _ = cpcdsk::parse_container(&mutated, layout);
                if i % 251 == 0 || i < 0x110 {
                    let _ = detect_payload(&mutated, &ClassifierOptions::new());
                }
            }
        }
    }
}
