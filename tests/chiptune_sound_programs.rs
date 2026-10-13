//! More chiptune and sound-program formats: the PSF family (PSF1, PSF2,
//! SSF, DSF, USF, GSF, SNSF, 2SF, NCSF, QSF), HES, KSS, SAP, AY and SNDH
//! name or imply their platform's CPU, load code at the addresses they give,
//! keep sample, sequence and packed data opaque, and reject inconsistent
//! structure.

use zrax::formats::chiptune::{Layout, PsfPlatform};
use zrax::formats::container::{self, Kind};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

/// Compiled 32-bit Arm code (little-endian), from the repository's testbins.
const ARM_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/arm32_arm-unknown-linux-gnueabi_O0_min_float_add.bin"
);

/// Compiled 32-bit MIPS code (little-endian), from the repository's testbins.
const MIPS_LE_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/mips32_le_mipsel-unknown-linux-gnu_O0_min_add_chain.bin"
);

/// Compiled 64-bit MIPS code (big-endian), from the repository's testbins.
const MIPS64_BE_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/mips64_be_mips64-unknown-linux-gnuabi64_O0_int_crc32.bin"
);

/// A short 6502 driver: LDA #$00, STA $D208, LDX #$0F, loop DEX/BNE, RTS.
const DRIVER_6502: &[u8] = &[
    0xa9, 0x00, 0x8d, 0x08, 0xd2, 0xa2, 0x0f, 0xca, 0xd0, 0xfd, 0x60,
];

/// A short Z80 driver: LD A,7; OUT ($A0),A; LD A,$38; OUT ($A1),A; RET.
const DRIVER_Z80: &[u8] = &[0x3e, 0x07, 0xd3, 0xa0, 0x3e, 0x38, 0xd3, 0xa1, 0xc9];

/// A short 68000 routine: MOVEM.L D0-A6,-(SP); MOVEQ #0,D0; NOP;
/// MOVEM.L (SP)+,D0-A6; RTS.
const DRIVER_68000: &[u8] = &[
    0x48, 0xe7, 0xff, 0xfe, 0x70, 0x00, 0x4e, 0x71, 0x4c, 0xdf, 0x7f, 0xff, 0x4e, 0x75,
];

/// A short 65C816 routine: SEI; CLC; XCE; REP #$30; LDA #$1234; RTL.
const DRIVER_65816: &[u8] = &[0x78, 0x18, 0xfb, 0xc2, 0x30, 0xa9, 0x34, 0x12, 0x6b];

fn testbin(path: &str) -> Vec<u8> {
    let mut code = std::fs::read(path).expect("testbin is committed");
    code.truncate(code.len() / 4 * 4);
    code
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn layout(data: &[u8]) -> Option<Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: Kind::Chiptune(layout),
        } => Some(layout),
        _ => None,
    }
}

fn parse(data: &[u8]) -> zrax::Result<container::Container<'_>> {
    let layout = layout(data).expect("a chiptune layout");
    container::parse(data, Kind::Chiptune(layout))
}

fn error_text(data: &[u8]) -> String {
    match parse(data) {
        Ok(_) => panic!("expected a parse error"),
        Err(e) => e.to_string(),
    }
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn round_up(len: usize, unit: usize) -> usize {
    (len + unit - 1) / unit * unit
}

/// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), bit by bit.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    !crc
}

/// A zlib `compress()` stream (RFC 1950).
fn zlib(bytes: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(bytes, 6)
}

/// PSF (PSF v1.6, "Basic File Structure"): `PSF`, version byte, reserved
/// size R, compressed program size N and the CRC-32 of the compressed
/// program (little-endian), R reserved bytes, N zlib bytes, then `[TAG]`
/// and the tag text when `tags` is not empty.
fn psf(version: u8, reserved: &[u8], program: &[u8], tags: &str) -> Vec<u8> {
    let compressed = if program.is_empty() {
        Vec::new()
    } else {
        zlib(program)
    };
    let crc = if compressed.is_empty() {
        0
    } else {
        crc32(&compressed)
    };
    let mut file = b"PSF".to_vec();
    file.push(version);
    file.extend_from_slice(&(reserved.len() as u32).to_le_bytes());
    file.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    file.extend_from_slice(&crc.to_le_bytes());
    file.extend_from_slice(reserved);
    file.extend_from_slice(&compressed);
    if !tags.is_empty() {
        file.extend_from_slice(b"[TAG]");
        file.extend_from_slice(tags.as_bytes());
    }
    file
}

/// PS-X EXE (psx-spx): `PS-X EXE` (8), zero (8), initial PC (4) at 0x10,
/// text address (4) at 0x18, text size (4, a multiple of 0x800) at 0x1C,
/// stack base (4) at 0x30, region marker at 0x4C; the text at 0x800.
fn psx_exe(text: &[u8], address: u32) -> Vec<u8> {
    let size = round_up(text.len(), 0x800);
    let mut exe = vec![0u8; 0x800 + size];
    exe[..8].copy_from_slice(b"PS-X EXE");
    put_le32(&mut exe, 0x10, address);
    put_le32(&mut exe, 0x18, address);
    put_le32(&mut exe, 0x1c, size as u32);
    put_le32(&mut exe, 0x30, 0x801f_fff0);
    let marker = b"Sony Computer Entertainment Inc. for North America area";
    exe[0x4c..0x4c + marker.len()].copy_from_slice(marker);
    exe[0x800..0x800 + text.len()].copy_from_slice(text);
    exe
}

/// A 32-bit little-endian MIPS ELF header (52 bytes, IOP module type
/// 0xFF80) followed by code: magic, class 1, data 1, version 1, `e_type`,
/// `e_machine` 8 (MIPS), `e_version` 1, `e_ehsize` 52.
fn irx_module(code: &[u8]) -> Vec<u8> {
    let mut elf = vec![0u8; 52];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 1;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&0xff80u16.to_le_bytes());
    elf[18..20].copy_from_slice(&8u16.to_le_bytes());
    put_le32(&mut elf, 20, 1);
    elf[40..42].copy_from_slice(&52u16.to_le_bytes());
    elf.extend_from_slice(code);
    elf
}

/// A PSF2 filesystem node.
enum Node<'a> {
    /// Name, contents and block size.
    File(&'a str, &'a [u8], u32),
    /// Name and entries.
    Directory(&'a str, Vec<Node<'a>>),
}

/// A PSF2 directory appended to `area` (PSF v1.6 "PSF2: Virtual
/// filesystem format"): entry count, then 48-byte entries of name (36,
/// NUL-padded), offset, uncompressed size and block size (little-endian).
/// File data (a table of compressed block sizes, then zlib blocks of the
/// block size) and subdirectories follow the entries, so every offset lies
/// after its entry. Returns the directory's offset.
fn psf2_directory(area: &mut Vec<u8>, nodes: &[Node<'_>]) -> u32 {
    let at = area.len();
    area.extend_from_slice(&(nodes.len() as u32).to_le_bytes());
    area.resize(at + 4 + nodes.len() * 48, 0);
    for (i, node) in nodes.iter().enumerate() {
        let entry = at + 4 + i * 48;
        let (name, offset, size, block) = match node {
            Node::File(name, contents, block) => {
                let offset = area.len() as u32;
                let blocks: Vec<Vec<u8>> = contents.chunks(*block as usize).map(zlib).collect();
                for compressed in &blocks {
                    area.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
                }
                for compressed in &blocks {
                    area.extend_from_slice(compressed);
                }
                (*name, offset, contents.len() as u32, *block)
            }
            Node::Directory(name, entries) => (*name, psf2_directory(area, entries), 0, 0),
        };
        area[entry..entry + name.len()].copy_from_slice(name.as_bytes());
        put_le32(area, entry + 36, offset);
        put_le32(area, entry + 40, size);
        put_le32(area, entry + 44, block);
    }
    at as u32
}

/// SR64 (USF v1.1): `SR64`, then chunks of length, offset (4 + 4,
/// little-endian) and data, ended by a zero length.
fn sr64(chunks: &[(u32, &[u8])]) -> Vec<u8> {
    let mut segment = b"SR64".to_vec();
    for (offset, data) in chunks {
        segment.extend_from_slice(&(data.len() as u32).to_le_bytes());
        segment.extend_from_slice(&offset.to_le_bytes());
        segment.extend_from_slice(data);
    }
    segment.extend_from_slice(&0u32.to_le_bytes());
    segment
}

/// ROM bytes as USF stores them: every 32-bit word little-endian.
fn word_swapped(native: &[u8]) -> Vec<u8> {
    native
        .chunks(4)
        .flat_map(|word| word.iter().rev().copied())
        .collect()
}

/// A QSF block (PSF v1.6 "Version 0x41"): 3-character tag, start offset
/// and length (LSB-first), data.
fn qsf_block(tag: &[u8; 3], start: u32, data: &[u8]) -> Vec<u8> {
    let mut block = tag.to_vec();
    block.extend_from_slice(&start.to_le_bytes());
    block.extend_from_slice(&(data.len() as u32).to_le_bytes());
    block.extend_from_slice(data);
    block
}

/// An SDAT as NCSF stores it: `SDAT`, byte-order mark, version, then the
/// file size at bytes 8-11 (NCSF v1.0), header size and block count.
fn sdat(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    data[..4].copy_from_slice(b"SDAT");
    data[4..8].copy_from_slice(&[0xff, 0xfe, 0x00, 0x01]);
    put_le32(&mut data, 8, len as u32);
    data
}

/// HES (HES V1.00): `HESM`, version 0, start song 0, init address (LE),
/// MPR0-MPR7 (0xFF, 0xF8, then 0); `DATA`, declared size, load address,
/// reserved 0 (LE); data.
fn hes(init: u16, load: u32, declared: u32, code: &[u8]) -> Vec<u8> {
    let mut file = b"HESM".to_vec();
    file.extend_from_slice(&[0, 0]);
    file.extend_from_slice(&init.to_le_bytes());
    file.extend_from_slice(&[0xff, 0xf8, 0, 0, 0, 0, 0, 0]);
    file.extend_from_slice(b"DATA");
    file.extend_from_slice(&declared.to_le_bytes());
    file.extend_from_slice(&load.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(code);
    file
}

/// The fixed KSS header (KSS V1.03): magic, load address, initial data
/// length, init and play addresses (LE), first bank, bank count (bit 7: 8
/// KiB mapper), reserved byte or `KSSX` extra header size, device flags.
fn kss_header(magic: &[u8; 4], load: u16, initial: usize, banks: u8, extra: u8) -> Vec<u8> {
    let mut header = magic.to_vec();
    header.extend_from_slice(&load.to_le_bytes());
    header.extend_from_slice(&(initial as u16).to_le_bytes());
    header.extend_from_slice(&load.to_le_bytes());
    header.extend_from_slice(&(load + 3).to_le_bytes());
    header.extend_from_slice(&[4, banks, extra, 0]);
    header
}

/// `KSCC` with initial data and `banks` 16 KiB banks of 0xC9 (RET).
fn kscc(load: u16, initial: &[u8], banks: u8) -> Vec<u8> {
    let mut file = kss_header(b"KSCC", load, initial.len(), banks, 0);
    file.extend_from_slice(initial);
    file.resize(file.len() + usize::from(banks) * 0x4000, 0xc9);
    file
}

/// `KSSX` with a 16-byte extra header: end-of-file offset (4), reserved
/// (4), first and last song (2 + 2), four volumes; then the initial data.
fn kssx(load: u16, initial: &[u8]) -> Vec<u8> {
    let mut file = kss_header(b"KSSX", load, initial.len(), 0, 0x10);
    file.extend_from_slice(&(initial.len() as u32).to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&1u16.to_le_bytes());
    file.extend_from_slice(&5u16.to_le_bytes());
    file.extend_from_slice(&[0, 0, 0, 0]);
    file.extend_from_slice(initial);
    file
}

/// SAP (ASAP specification): the text header, then binary blocks of `FF
/// FF`, first and last address (LE) and data.
fn sap(header: &str, blocks: &[(u16, &[u8])]) -> Vec<u8> {
    let mut file = header.as_bytes().to_vec();
    for (start, data) in blocks {
        file.extend_from_slice(&[0xff, 0xff]);
        file.extend_from_slice(&start.to_le_bytes());
        file.extend_from_slice(&(start + data.len() as u16 - 1).to_le_bytes());
        file.extend_from_slice(data);
    }
    file
}

const SAP_TYPE_B: &str =
    "SAP\r\nAUTHOR \"Jakub Husak\"\r\nNAME \"Inside\"\r\nDATE \"1990\"\r\nSONGS 3\r\nTYPE B\r\nINIT 0F80\r\nPLAYER 0F83\r\nTIME 06:37.62\r\n";

/// A relative AY pointer stored at `from` that points to `to`
/// (big-endian, signed).
fn ay_pointer(file: &mut [u8], from: usize, to: usize) {
    let delta = i16::try_from(to as i64 - from as i64).expect("in range");
    file[from..from + 2].copy_from_slice(&delta.to_be_bytes());
}

/// AY `ZXAYEMUL` with two songs that share one data block list (Bulba's
/// description): header (20) with author and misc pointers, two song
/// records (name and song data pointers), song data (channels, length,
/// fade, register halves, pointers and blocks pointers), pointers records
/// (stack, init, interrupt), one block list (address, length, relative
/// offset; then a zero address), strings and the Z80 code.
fn ay(code: &[u8]) -> Vec<u8> {
    let songs_at = 20;
    let song_data_at = 28;
    let points_at = 56;
    let blocks_at = 68;
    let strings_at = 80;
    let code_at = 112;
    let mut file = vec![0u8; code_at];
    file[..8].copy_from_slice(b"ZXAYEMUL");
    file[9] = 3;
    file[16] = 1;
    ay_pointer(&mut file, 18, songs_at);
    let strings: [&[u8]; 4] = [b"Composer\0", b"Misc\0", b"One\0", b"Two\0"];
    let mut at = strings_at;
    let mut string_offsets = Vec::new();
    for text in strings {
        file[at..at + text.len()].copy_from_slice(text);
        string_offsets.push(at);
        at += text.len();
    }
    ay_pointer(&mut file, 12, string_offsets[0]);
    ay_pointer(&mut file, 14, string_offsets[1]);
    for song in 0..2 {
        let record = songs_at + song * 4;
        let data = song_data_at + song * 14;
        let points = points_at + song * 6;
        ay_pointer(&mut file, record, string_offsets[2 + song]);
        ay_pointer(&mut file, record + 2, data);
        file[data..data + 4].copy_from_slice(&[0, 1, 2, 3]);
        file[data + 4..data + 6].copy_from_slice(&3000u16.to_be_bytes());
        ay_pointer(&mut file, data + 10, points);
        ay_pointer(&mut file, data + 12, blocks_at);
        file[points..points + 2].copy_from_slice(&0xf000u16.to_be_bytes());
        file[points + 2..points + 4].copy_from_slice(&0x8000u16.to_be_bytes());
        file[points + 4..points + 6].copy_from_slice(&(0x8000 + song as u16).to_be_bytes());
    }
    file[blocks_at..blocks_at + 2].copy_from_slice(&0x8000u16.to_be_bytes());
    file[blocks_at + 2..blocks_at + 4].copy_from_slice(&(code.len() as u16).to_be_bytes());
    ay_pointer(&mut file, blocks_at + 4, code_at);
    file.extend_from_slice(code);
    file
}

/// SNDH (Revision 2.2): `bra.w` INIT, EXIT and PLAY (opcode 0x6000 and a
/// displacement from the opcode + 2), `SNDH`, tags, `HDNS`, then code.
fn sndh(tags: &[u8], code: &[u8]) -> Vec<u8> {
    let code_at = 16 + tags.len() + 4;
    let mut file = Vec::new();
    for (slot, target) in [(0usize, code_at), (4, code_at + 4), (8, code_at + 8)] {
        file.extend_from_slice(&[0x60, 0x00]);
        let displacement = i16::try_from(target - (slot + 2)).expect("short program");
        file.extend_from_slice(&displacement.to_be_bytes());
    }
    file.extend_from_slice(b"SNDH");
    file.extend_from_slice(tags);
    file.extend_from_slice(b"HDNS");
    file.extend_from_slice(code);
    file
}

/// Pack-Ice: `ICE!`, packed size including the 12-byte header and unpacked
/// size (big-endian), packed data.
fn pack_ice(packed: &[u8], unpacked: u32) -> Vec<u8> {
    let mut file = b"ICE!".to_vec();
    file.extend_from_slice(&(12 + packed.len() as u32).to_be_bytes());
    file.extend_from_slice(&unpacked.to_be_bytes());
    file.extend_from_slice(packed);
    file
}

fn psf1_file() -> Vec<u8> {
    let exe = psx_exe(&testbin(MIPS_LE_CODE), 0x8001_0000);
    psf(
        0x01,
        &[],
        &exe,
        "title=Earth Painting\ngame=Legend of Mana\nyear=1999\n",
    )
}

fn psf2_file() -> Vec<u8> {
    let module = irx_module(&testbin(MIPS_LE_CODE));
    let bank = [0x5au8; 300];
    let mut area = Vec::new();
    psf2_directory(
        &mut area,
        &[
            Node::File("psf2.irx", &module, 256),
            Node::Directory("sound", vec![Node::File("bank.hd", &bank, 128)]),
        ],
    );
    psf(0x02, &area, &[], "")
}

fn ssf_file() -> Vec<u8> {
    let mut program = 0x1000u32.to_le_bytes().to_vec();
    program.extend_from_slice(DRIVER_68000);
    psf(0x11, &[], &program, "")
}

fn dsf_file() -> Vec<u8> {
    let mut program = 0u32.to_le_bytes().to_vec();
    program.extend_from_slice(&testbin(ARM_CODE));
    psf(0x12, &[], &program, "")
}

fn usf_file() -> Vec<u8> {
    let rom = word_swapped(&testbin(MIPS64_BE_CODE));
    let mut state = 0x23d8_a6c8u32.to_le_bytes().to_vec();
    state.extend_from_slice(&0x0040_0000u32.to_le_bytes());
    let mut reserved = sr64(&[(0x1000, &rom)]);
    reserved.extend_from_slice(&sr64(&[(0, &state)]));
    psf(0x21, &reserved, &[], "_lib=game.usflib\n")
}

fn gsf_file() -> Vec<u8> {
    let rom = testbin(ARM_CODE);
    let mut program = Vec::new();
    program.extend_from_slice(&0x0800_0000u32.to_le_bytes());
    program.extend_from_slice(&0x0800_0000u32.to_le_bytes());
    program.extend_from_slice(&(rom.len() as u32).to_le_bytes());
    program.extend_from_slice(&rom);
    psf(0x22, &[], &program, "")
}

/// SNSF and 2SF programs: ROM offset and size (LE), then the ROM data.
fn offset_rom(version: u8, offset: u32, rom: &[u8]) -> Vec<u8> {
    let mut program = offset.to_le_bytes().to_vec();
    program.extend_from_slice(&(rom.len() as u32).to_le_bytes());
    program.extend_from_slice(rom);
    psf(version, &[], &program, "")
}

fn ncsf_file() -> Vec<u8> {
    psf(0x25, &3u32.to_le_bytes(), &sdat(64), "")
}

fn qsf_file(key: [u8; 11]) -> Vec<u8> {
    let mut program = qsf_block(b"KEY", 0, &key);
    program.extend_from_slice(&qsf_block(b"Z80", 0, DRIVER_Z80));
    program.extend_from_slice(&qsf_block(b"SMP", 0x10_0000, &[0x80; 64]));
    psf(0x41, &[], &program, "")
}

#[test]
fn psf_version_bytes_name_their_platform() {
    for (version, platform) in [
        (0x01, PsfPlatform::PlayStation),
        (0x02, PsfPlatform::PlayStation2),
        (0x11, PsfPlatform::Saturn),
        (0x12, PsfPlatform::Dreamcast),
        (0x13, PsfPlatform::Genesis),
        (0x21, PsfPlatform::Nintendo64),
        (0x22, PsfPlatform::GameBoyAdvance),
        (0x23, PsfPlatform::SuperNes),
        (0x24, PsfPlatform::NintendoDs),
        (0x25, PsfPlatform::NitroComposer),
        (0x41, PsfPlatform::QSound),
    ] {
        assert_eq!(PsfPlatform::from_version(version), Some(platform));
        assert_eq!(platform.version(), version);
        let file = psf(version, &[], &[], "");
        assert_eq!(layout(&file), Some(Layout::Psf(platform)));
    }
    // An unassigned version byte is not a PSF file.
    assert_eq!(layout(&psf(0x99, &[], &[], "")), None);
}

#[test]
fn psf1_program_is_a_ps_x_exe_child_with_its_own_classification() {
    let file = psf1_file();
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Psf);
    assert_eq!(p.format.variant_name.as_deref(), Some("PSF1 (PlayStation)"));
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Mips, Endianness::Little)
    );
    let crc = u32::from_le_bytes(file[12..16].try_into().expect("4 bytes"));
    assert!(has_note(
        &p,
        &format!("program CRC-32 0x{crc:08X} verified")
    ));
    assert!(has_note(
        &p,
        "Tags: title \"Earth Painting\"; game \"Legend of Mana\"; year \"1999\""
    ));
    let slice = &p.slices[0];
    assert_eq!(slice.label.as_deref(), Some("PS-X EXE program"));
    assert_eq!(slice.isa, Isa::Mips);
    let compressed = u32::from_le_bytes(file[8..12].try_into().expect("4 bytes"));
    assert_eq!((slice.offset, slice.size), (16, u64::from(compressed)));
    let decoded = slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "zlib");
    assert_eq!(decoded.size, 0x1000);
    assert!(has_note(&p, "PS-X EXE program: mips (contained PS-X EXE)"));
    assert_eq!(
        metadata(&p, "psf_tag_game").as_deref(),
        Some("Legend of Mana")
    );
}

#[test]
fn psf_library_tags_are_noted_but_not_resolved() {
    let exe = psx_exe(DRIVER_Z80, 0x8001_0000);
    let file = psf(
        0x01,
        &[],
        &exe,
        "  TITLE = Mini \n_lib=Hello/Library.psflib\n_lib2=extra.psflib\n_refresh=50\nnot a tag\ncomment=one\ncomment=two\n",
    );
    let p = classify(&file);
    assert!(has_note(
        &p,
        "Library references are not resolved: _lib \"Hello/Library.psflib\"; _lib2 \"extra.psflib\""
    ));
    assert!(has_note(&p, "Player settings: _refresh \"50\""));
    assert!(has_note(&p, "title \"Mini\""));
    assert!(has_note(&p, "comment \"one two\""));
}

#[test]
fn psf_crc_sizes_and_program_stream_are_checked() {
    let mut bad_crc = psf1_file();
    bad_crc[12] ^= 0x01;
    assert!(error_text(&bad_crc).contains("Invalid PSF program CRC-32"));
    // Areas beyond the file are not recognized; parsed anyway, they are
    // truncation errors.
    let playstation = Kind::Chiptune(Layout::Psf(PsfPlatform::PlayStation));
    let mut long_reserved = psf1_file();
    put_le32(&mut long_reserved, 4, 0x10_0000);
    assert_eq!(layout(&long_reserved), None);
    let error = container::parse(&long_reserved, playstation).expect_err("truncated");
    assert!(error
        .to_string()
        .contains("Truncated PSF reserved area at 0x10"));
    let mut long_program = psf1_file();
    put_le32(&mut long_program, 8, 0x10_0000);
    let error = container::parse(&long_program, playstation).expect_err("truncated");
    assert!(error.to_string().contains("Truncated PSF program at 0x10"));
    // A program that is not a zlib stream, with a matching CRC.
    let mut not_zlib = b"PSF\x01".to_vec();
    not_zlib.extend_from_slice(&0u32.to_le_bytes());
    not_zlib.extend_from_slice(&4u32.to_le_bytes());
    not_zlib.extend_from_slice(&crc32(b"junk").to_le_bytes());
    not_zlib.extend_from_slice(b"junk");
    assert!(error_text(&not_zlib).contains("Invalid PSF program at 0x10"));
    // Bytes after the program that are not a tag block are ignored.
    let mut trailing = psf(0x01, &[], &psx_exe(DRIVER_Z80, 0x8001_0000), "");
    trailing.extend_from_slice(b"garbage");
    let p = classify(&trailing);
    assert!(has_note(&p, "is not a [TAG] block; ignored"));
}

#[test]
fn psf2_lists_its_filesystem_and_the_elf_parser_names_the_irx_isa() {
    let file = psf2_file();
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Psf);
    assert_eq!(p.primary.isa, Isa::Mips);
    assert!(has_note(&p, "Primary ISA selected from psf2.irx"));
    let module_len = irx_module(&testbin(MIPS_LE_CODE)).len();
    assert!(has_note(
        &p,
        &format!(
            "PSF2 filesystem: 2 files ({} B) in 1 subdirectories",
            module_len + 300
        )
    ));
    let irx = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("psf2.irx"))
        .expect("psf2.irx is listed");
    assert_eq!(irx.isa, Isa::Mips);
    assert_eq!(
        irx.decoded.as_ref().map(|d| d.size),
        Some(module_len as u64)
    );
    assert_eq!(
        irx.decoded.as_ref().map(|d| d.transform.as_str()),
        Some("zlib")
    );
    // The data file is listed in the metadata but is not a slice.
    assert_eq!(p.slices.len(), 1);
    let irx_entry = metadata(&p, "psf_file_0").expect("psf2.irx listed");
    assert!(irx_entry.contains(&format!("{module_len} B in 3 zlib blocks of 256 B")));
    let bank = p
        .metadata
        .iter()
        .find(|m| m.label == "sound/bank.hd")
        .expect("bank listed");
    assert!(bank
        .value
        .to_string()
        .contains("300 B in 3 zlib blocks of 128 B"));
}

#[test]
fn psf2_entries_must_point_past_themselves_and_blocks_must_decode() {
    let mut area = Vec::new();
    psf2_directory(&mut area, &[Node::File("a.irx", &[1, 2, 3, 4], 4)]);
    // Point the file at its own entry, which starts at offset 4.
    put_le32(&mut area, 4 + 36, 4);
    let looped = psf(0x02, &area, &[], "");
    assert!(error_text(&looped).contains("does not lie after the entry"));
    let mut huge = Vec::new();
    psf2_directory(&mut huge, &[Node::File("b", &[1, 2], 2)]);
    put_le32(&mut huge, 0, 1000);
    assert!(error_text(&psf(0x02, &huge, &[], "")).contains("entries exceed the reserved area"));
    // A module whose block decodes to fewer bytes than the block size.
    let module = irx_module(DRIVER_Z80);
    let mut short = Vec::new();
    psf2_directory(&mut short, &[Node::File("psf2.irx", &module, 128)]);
    put_le32(&mut short, 4 + 40, 128);
    assert!(error_text(&psf(0x02, &short, &[], "")).contains("Invalid PSF2 block 0 of psf2.irx"));
}

#[test]
fn ssf_and_dsf_load_their_programs_at_the_given_address() {
    let ssf = classify(&ssf_file());
    assert_eq!(
        ssf.format.variant_name.as_deref(),
        Some("SSF (Sega Saturn)")
    );
    assert_eq!(
        (ssf.primary.isa, ssf.primary.endianness),
        (Isa::M68k, Endianness::Big)
    );
    assert!(has_note(
        &ssf,
        "Saturn sound CPU (68000) program loaded at 0x1000"
    ));
    let section = ssf
        .metadata
        .iter()
        .find(|m| m.label == "68000 program")
        .expect("section");
    assert!(section.value.to_string().contains("destination 0x1000; "));
    assert!(section.value.to_string().contains("B decoded (zlib)"));
    let dsf = classify(&dsf_file());
    assert_eq!(dsf.primary.isa, Isa::Arm);
    // The DSF document does not give the byte order; the code does.
    assert_eq!(dsf.primary.endianness, Endianness::Little);
    assert!(has_note(&dsf, "Code byte order from the loaded code"));
    assert!(has_note(&dsf, "does not state the ARM7 byte order"));
    // A program too short to hold its load address.
    let short = psf(0x11, &[], &[1, 2], "");
    assert!(error_text(&short).contains("Truncated 68000 program: 2 B, no load address"));
}

#[test]
fn usf_rom_chunks_are_swapped_back_to_big_endian_mips() {
    let p = classify(&usf_file());
    assert_eq!(p.format.variant_name.as_deref(), Some("USF (Nintendo 64)"));
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Mips64, Endianness::Big)
    );
    let rom = p
        .metadata
        .iter()
        .find(|m| m.label == "ROM 0x1000")
        .expect("ROM chunk section");
    assert!(rom.value.to_string().contains("(32-bit byte swap)"));
    assert!(has_note(&p, "identifier 0x23D8A6C8 present"));
    assert!(has_note(
        &p,
        "Library references are not resolved: _lib \"game.usflib\""
    ));
    // Anything but SR64 or four zero bytes is an error.
    let bad = psf(0x21, b"XXXX\0\0\0\0", &[], "");
    assert!(error_text(&bad).contains("Invalid USF ROM segment at 0x10"));
    let truncated = psf(0x21, b"SR64\x10\0\0\0", &[], "");
    assert!(error_text(&truncated).contains("Truncated USF ROM segment"));
}

#[test]
fn gsf_snsf_and_2sf_place_rom_data_at_their_offsets() {
    let gsf = classify(&gsf_file());
    assert_eq!(
        (gsf.primary.isa, gsf.primary.endianness),
        (Isa::Arm, Endianness::Little)
    );
    assert!(has_note(&gsf, "entry point 0x08000000"));
    assert!(gsf.metadata.iter().any(
        |m| m.label == "ROM 0x8000000" && m.value.to_string().contains("destination 0x8000000")
    ));
    let snsf = classify(&offset_rom(0x23, 0x8000, DRIVER_65816));
    assert_eq!(snsf.primary.isa, Isa::W65816);
    assert!(has_note(&snsf, "at ROM offset 0x8000"));
    let nds = classify(&offset_rom(0x24, 0, &testbin(ARM_CODE)));
    assert_eq!(nds.primary.isa, Isa::Arm);
    assert!(has_note(&nds, "Nintendo DS ROM image"));
    // The ROM size must fit the decoded program.
    let mut program = 0x0800_0000u32.to_le_bytes().to_vec();
    program.extend_from_slice(&0x0800_0000u32.to_le_bytes());
    program.extend_from_slice(&100u32.to_le_bytes());
    program.extend_from_slice(&[0; 10]);
    let short = psf(0x22, &[], &program, "");
    assert!(error_text(&short).contains("Truncated GSF ROM data: 100 B declared, 10 B decoded"));
    // An undocumented entry point is reported, not rejected.
    program[..4].copy_from_slice(&0x0300_0000u32.to_le_bytes());
    program[8..12].copy_from_slice(&10u32.to_le_bytes());
    let odd = classify(&psf(0x22, &[], &program, ""));
    assert!(has_note(
        &odd,
        "is not one of the documented GSF entry points"
    ));
}

#[test]
fn ncsf_holds_sound_data_and_no_code() {
    let p = classify(&ncsf_file());
    assert_eq!(p.format.format, FileFormat::Psf);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(&p, "Sequence number 3"));
    assert!(has_note(&p, "SDAT sound data: opaque"));
    assert_eq!(p.slices[0].label.as_deref(), Some("SDAT sound data"));
    assert_eq!(p.slices[0].decoded.as_ref().map(|d| d.size), Some(64));
    let bad_reserved = psf(0x25, &[1, 2], &sdat(64), "");
    assert!(error_text(&bad_reserved).contains("Invalid NCSF reserved area: 2 B"));
    let mut wrong_size = sdat(64);
    put_le32(&mut wrong_size, 8, 65);
    assert!(error_text(&psf(0x25, &[], &wrong_size, "")).contains("Invalid NCSF SDAT size"));
}

#[test]
fn qsf_z80_blocks_are_code_unless_the_key_encrypts_them() {
    let plain = classify(&qsf_file([0; 11]));
    assert_eq!(plain.primary.isa, Isa::Z80);
    assert!(has_note(
        &plain,
        "1 Z80 program blocks (9 B), 1 SMP sample blocks (64 B)"
    ));
    assert!(plain.metadata.iter().any(|m| m.label == "Z80 ROM 0x0"));
    let mut key = [0u8; 11];
    key[..4].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    let encrypted = classify(&qsf_file(key));
    assert_eq!(encrypted.primary.isa, Isa::Z80);
    assert!(has_note(
        &encrypted,
        "Kabuki-encrypted (swap keys 0x12345678, 0x00000000)"
    ));
    assert!(!encrypted.metadata.iter().any(|m| m.label == "Z80 ROM 0x0"));
    let unknown = psf(0x41, &[], &qsf_block(b"XYZ", 0, &[1]), "");
    assert!(error_text(&unknown).contains("Unknown QSF block tag XYZ"));
    let long_key = psf(0x41, &[], &qsf_block(b"KEY", 8, &[0; 4]), "");
    assert!(error_text(&long_key).contains("exceeds 11 B"));
}

#[test]
fn genesis_psf_is_recognized_without_interpretation() {
    let p = classify(&psf(0x13, &[1, 2, 3], &[9; 16], ""));
    assert_eq!(p.format.format, FileFormat::Psf);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(&p, "has no published layout"));
}

#[test]
fn hes_data_blocks_load_at_physical_addresses() {
    let file = hes(0xe000, 0, DRIVER_6502.len() as u32, DRIVER_6502);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Hes);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("PC Engine HES (HuC6280)")
    );
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::Mcs6502, 8));
    assert!(has_note(
        &p,
        "init 0xE000 (logical address); MPR0-MPR7 0xFF 0xF8"
    ));
    assert!(p
        .metadata
        .iter()
        .any(|m| m.label == "DATA 0x000000" && m.value.to_string().starts_with("file 0x20;")));
    // A size beyond the file is clipped, as players do.
    let long = classify(&hes(0xe000, 0, 0x1000, DRIVER_6502));
    assert!(has_note(&long, "declares 4096 B; 11 B present"));
    let mut version = file.clone();
    version[4] = 1;
    assert!(error_text(&version).contains("Unsupported HES version 1"));
    let mut no_data = file.clone();
    no_data[0x10..0x14].copy_from_slice(b"DATX");
    assert!(error_text(&no_data).contains("Missing HES DATA block at 0x10"));
    assert!(error_text(&hes(0xe000, 0, 0, &[])).contains("Missing HES program data"));
}

#[test]
fn kss_initial_data_and_banks_are_z80_sections() {
    let p = classify(&kscc(0x4000, DRIVER_Z80, 1));
    assert_eq!(p.format.format, FileFormat::Kss);
    assert_eq!(p.format.variant_name.as_deref(), Some("KSS (KSCC header)"));
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(has_note(&p, "KSS MSX mode: Z80 driver loaded at 0x4000; init 0x4000, play 0x4003; 1 banks of 16 KiB from bank 4"));
    assert!(p.metadata.iter().any(
        |m| m.label == "Bank 4" && m.value.to_string().contains("destination 0x8000; 16384 B")
    ));
    let extended = classify(&kssx(0x0100, DRIVER_Z80));
    assert_eq!(
        extended.format.variant_name.as_deref(),
        Some("KSS (KSSX header)")
    );
    assert!(has_note(&extended, "KSSX songs 1 to 5"));
    assert!(extended
        .metadata
        .iter()
        .any(|m| m.label == "Initial data" && m.value.to_string().starts_with("file 0x20;")));
    // A missing bank is reported; a missing header is an error.
    let mut cut = kscc(0x4000, DRIVER_Z80, 2);
    cut.truncate(cut.len() - 0x4000 - 100);
    let cut = classify(&cut);
    assert!(has_note(&cut, "holds 16284 B of 16384 B"));
    assert!(has_note(&cut, "2 banks declared; 1 present"));
    assert!(error_text(b"KSCC\0\0").contains("Truncated KSS header"));
    assert!(error_text(&kss_header(b"KSCC", 0x4000, 0, 0, 0)).contains("Missing KSS program data"));
}

#[test]
fn sap_blocks_are_6502_sections_and_the_header_is_validated() {
    let file = sap(SAP_TYPE_B, &[(0x0f80, DRIVER_6502), (0x2000, &[1, 2, 3])]);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Sap);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert!(has_note(&p, "SAP TYPE B: \"Inside\" by \"Jakub Husak\" (1990); 3 songs, 1 TIME tags; 6502 driver: init 0x0F80, player 0x0F83"));
    assert!(p.metadata.iter().any(|m| m.label == "Block 0x0F80-0x0F8A"));
    assert!(p.metadata.iter().any(|m| m.label == "Block 0x2000-0x2002"));
    let type_c = sap(
        "SAP\r\nTYPE C\r\nMUSIC 3000\r\nPLAYER 0500\r\n",
        &[(0x0500, DRIVER_6502)],
    );
    assert_eq!(parse(&type_c).expect("type C").entry, Some(0x0503));
    let raw = classify(
        &sap("SAP\r\nTYPE R\r\n", &[])
            .iter()
            .chain(&[1u8, 2, 3])
            .copied()
            .collect::<Vec<_>>(),
    );
    assert!(matches!(raw.primary.isa, Isa::Unknown(_)));
    assert!(has_note(
        &raw,
        "TYPE R: the data is a raw POKEY register dump"
    ));
    for (header, message) in [
        (
            "SAP\r\nTYPE B\r\nPLAYER 0F83\r\n",
            "Missing SAP INIT tag for TYPE B",
        ),
        (
            "SAP\r\nTYPE B\r\nINIT 0FG0\r\n",
            "Invalid SAP INIT tag at 0x",
        ),
        ("SAP\r\nINIT 0F80\r\n", "Missing SAP TYPE tag"),
        (
            "SAP\r\nTYPE C\r\nINIT 1000\r\nMUSIC 3000\r\nPLAYER 0500\r\n",
            "Invalid SAP INIT tag for TYPE C",
        ),
        (
            "SAP\r\nTYPE B\r\nINIT 1\r\nPLAYER 2\r\nSONGS 2\r\nDEFSONG 2\r\n",
            "Invalid SAP DEFSONG 2 for 2 songs",
        ),
        ("SAP\r\nTIME 6:3\r\n", "Invalid SAP TIME tag"),
    ] {
        let file = sap(header, &[(0x1000, DRIVER_6502)]);
        assert!(error_text(&file).contains(message), "{header:?}");
    }
    let mut no_marker = SAP_TYPE_B.as_bytes().to_vec();
    no_marker.extend_from_slice(&[0x00, 0x10]);
    assert!(error_text(&no_marker).contains("Invalid SAP header line"));
    // A block cut short is kept and reported.
    let mut cut = file.clone();
    cut.truncate(cut.len() - 2);
    assert!(has_note(&classify(&cut), "holds 1 B of 3 B; malformed"));
    let unknown = classify(&sap(
        &format!("{SAP_TYPE_B}FOO bar\r\n"),
        &[(0x0f80, DRIVER_6502)],
    ));
    assert!(has_note(&unknown, "Unknown SAP tags ignored: FOO"));
}

#[test]
fn ay_songs_share_data_blocks_listed_once() {
    let file = ay(DRIVER_Z80);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::AyTune);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(has_note(&p, "AY (ZXAYEMUL): 2 songs, first song 1; file version 0, player version 3; author \"Composer\"; misc \"Misc\""));
    assert!(has_note(
        &p,
        "Z80 driver of song 1 \"One\": init 0x8000, interrupt 0x8000, stack 0xF000"
    ));
    let blocks: Vec<_> = p
        .metadata
        .iter()
        .filter(|m| m.label == "Block 0x8000")
        .collect();
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0]
        .value
        .to_string()
        .starts_with("file 0x70; destination 0x8000; 9 B"));
    assert_eq!(parse(&file).expect("ay").entry, Some(0x8000));
    // A pointer leaving the file is an error; a block past the end is cut.
    let mut bad = file.clone();
    bad[18..20].copy_from_slice(&0x7000i16.to_be_bytes());
    assert!(error_text(&bad).contains("Invalid AY pointer at 0x12"));
    let mut long = file.clone();
    long[70..72].copy_from_slice(&100u16.to_be_bytes());
    assert!(has_note(&classify(&long), "shortened from 100 B to 9 B"));
}

#[test]
fn sndh_is_a_68000_program_with_header_tags() {
    let tags = b"TITLLed Storm\0COMMTim Follin\0##02TC50\0#!01\0\0";
    let file = sndh(tags, DRIVER_68000);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Sndh);
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::M68k, Endianness::Big)
    );
    assert!(has_note(&p, "SNDH 68000 program; title \"Led Storm\"; composer \"Tim Follin\"; 2 subtunes, default 1; replay TC50"));
    let code_at = 16 + tags.len() + 4;
    assert!(has_note(
        &p,
        &format!(
            "Entry branches (bra.w): INIT 0x{code_at:X}, EXIT 0x{:X}, PLAY 0x{:X}",
            code_at + 4,
            code_at + 8
        )
    ));
    assert!(p.metadata.iter().any(|m| m.label == "68000 program"
        && m.value
            .to_string()
            .starts_with("file 0x0; destination 0x0;")));
    let mut no_end = file.clone();
    let end = 16 + tags.len();
    no_end[end..end + 4].copy_from_slice(b"XXXX");
    assert!(has_note(&classify(&no_end), "no HDNS end tag before that"));
}

#[test]
fn pack_ice_files_are_opaque() {
    let file = pack_ice(&[0x55; 40], 1000);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::PackIce);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert!(has_note(
        &p,
        "Pack-Ice: 52 B packed, 1000 B unpacked; no Pack-Ice decoder is implemented"
    ));
    assert_eq!((p.slices[0].offset, p.slices[0].size), (12, 40));
    let mut truncated = file.clone();
    truncated.truncate(30);
    assert!(error_text(&truncated).contains("Truncated Pack-Ice data: 52 B declared, 30 B present"));
    assert!(error_text(&pack_ice(&[], 0)).contains("Invalid Pack-Ice unpacked size 0"));
}

/// Every layout's fixture.
fn fixtures() -> Vec<Vec<u8>> {
    vec![
        psf1_file(),
        psf2_file(),
        ssf_file(),
        dsf_file(),
        usf_file(),
        gsf_file(),
        offset_rom(0x23, 0x8000, DRIVER_65816),
        offset_rom(0x24, 0, DRIVER_Z80),
        ncsf_file(),
        qsf_file([0; 11]),
        hes(0xe000, 0, DRIVER_6502.len() as u32, DRIVER_6502),
        kscc(0x4000, DRIVER_Z80, 1),
        kssx(0x0100, DRIVER_Z80),
        sap(SAP_TYPE_B, &[(0x0f80, DRIVER_6502)]),
        ay(DRIVER_Z80),
        sndh(b"TITLTune\0##01\0", DRIVER_68000),
        pack_ice(&[0x55; 16], 64),
    ]
}

#[test]
fn every_fixture_is_detected_by_its_magic() {
    let expected = [
        Layout::Psf(PsfPlatform::PlayStation),
        Layout::Psf(PsfPlatform::PlayStation2),
        Layout::Psf(PsfPlatform::Saturn),
        Layout::Psf(PsfPlatform::Dreamcast),
        Layout::Psf(PsfPlatform::Nintendo64),
        Layout::Psf(PsfPlatform::GameBoyAdvance),
        Layout::Psf(PsfPlatform::SuperNes),
        Layout::Psf(PsfPlatform::NintendoDs),
        Layout::Psf(PsfPlatform::NitroComposer),
        Layout::Psf(PsfPlatform::QSound),
        Layout::Hes,
        Layout::Kss,
        Layout::Kssx,
        Layout::Sap,
        Layout::Ay,
        Layout::Sndh,
        Layout::PackIce,
    ];
    for (file, layout_expected) in fixtures().iter().zip(expected) {
        assert_eq!(layout(file), Some(layout_expected));
        assert!(parse(file).is_ok(), "{layout_expected:?}");
    }
}

#[test]
fn text_and_archive_paths_with_the_magics_are_not_taken_for_tunes() {
    // `PSFA` is QSF's signature in ASCII; its "sizes" exceed the file.
    assert_eq!(layout(b"PSFAILURE REPORT: all systems nominal\n"), None);
    // A first line of "SAP" without a SAP tag after it.
    assert_eq!(
        layout(b"SAP\r\nRelease notes for the next quarter\r\n"),
        None
    );
    // A tar member path with `SNDH` at offset 12.
    let mut tar_name = b"Music/Atari/SNDH/Composer/tune.sndh".to_vec();
    tar_name.resize(512, 0);
    assert_ne!(layout(&tar_name), Some(Layout::Sndh));
    // With a tag after `SNDH`, the same offset is an SNDH file.
    assert_eq!(layout(&sndh(b"COMMX\0", DRIVER_68000)), Some(Layout::Sndh));
}

#[test]
fn prefixes_never_claim_bytes_they_do_not_have() {
    for file in fixtures() {
        let layout = layout(&file).expect("detected");
        for end in 0..file.len() {
            let prefix = &file[..end];
            let _ = detect_payload(prefix, &ClassifierOptions::new());
            let Ok(c) = container::parse(prefix, Kind::Chiptune(layout)) else {
                continue;
            };
            assert!(c.consumed <= end, "{layout:?} at {end}");
            for section in &c.sections {
                assert!(
                    section.offset + section.stored_size <= end,
                    "{layout:?} at {end}"
                );
            }
            for child in &c.children {
                assert!(
                    child.offset + child.stored_size <= end,
                    "{layout:?} at {end}"
                );
            }
            // PSF areas and programs are exact: only the tag block may be cut.
            if let Layout::Psf(_) = layout {
                let reserved = u32::from_le_bytes(file[4..8].try_into().expect("4 bytes"));
                let program = u32::from_le_bytes(file[8..12].try_into().expect("4 bytes"));
                assert!(end >= 16 + reserved as usize + program as usize);
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    for file in fixtures() {
        for i in 0..file.len() {
            for value in [0x00, 0xff, file[i] ^ 0x01] {
                let mut mutated = file.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}
