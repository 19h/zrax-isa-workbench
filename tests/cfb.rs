//! OLE compound files: the sector tables and directory locate every stream,
//! streams in a recognized format are classified as members, Windows
//! Installer stream names are unpacked, and damaged tables are parse errors.

use zrax::formats::cfb::{self, Layout};
use zrax::{detect_payload, ClassifierError, ClassifierOptions, FileFormat, Isa};

const SECTOR: usize = 512;
const FAT_SECTOR_MARK: u32 = 0xffff_fffd;
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FREE: u32 = 0xffff_ffff;
const NO_STREAM: u32 = 0xffff_ffff;

/// A minimal x86-64 ELF header (`e_machine` 62) padded to `len` bytes: a
/// stream the classifier recognizes.
fn elf_x86_64(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    v[..4].copy_from_slice(b"\x7fELF");
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    v
}

/// A 128-byte directory entry: UTF-16LE name, name length with the
/// terminator, object type, left/right siblings, child, starting sector,
/// size.
fn dir_entry(
    name: &[u16],
    kind: u8,
    siblings: (u32, u32),
    child: u32,
    start: u32,
    size: u32,
) -> Vec<u8> {
    let mut e = vec![0u8; 128];
    for (i, unit) in name.iter().enumerate() {
        e[2 * i..2 * i + 2].copy_from_slice(&unit.to_le_bytes());
    }
    e[0x40..0x42].copy_from_slice(&((2 * name.len() + 2) as u16).to_le_bytes());
    e[0x42] = kind;
    e[0x44..0x48].copy_from_slice(&siblings.0.to_le_bytes());
    e[0x48..0x4c].copy_from_slice(&siblings.1.to_le_bytes());
    e[0x4c..0x50].copy_from_slice(&child.to_le_bytes());
    e[0x74..0x78].copy_from_slice(&start.to_le_bytes());
    e[0x78..0x7c].copy_from_slice(&size.to_le_bytes());
    e
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// A version 3 compound file (512 B sectors). Sector 0 is the FAT, 1 the
/// directory, 2 the mini FAT, 3 the mini stream (one 64-byte mini sector
/// holding the small `notes` stream), then the large `Program` stream
/// (`program`, at least 4096 B) to the end. Directory: root, `notes`,
/// `Program`, and an empty stream whose name is Windows Installer packed.
fn compound_file(program: &[u8]) -> Vec<u8> {
    assert!(program.len() >= 4096 && program.len() % SECTOR == 0);
    let program_sectors = program.len() / SECTOR;
    let mut header = vec![0u8; SECTOR];
    header[..8].copy_from_slice(&cfb::SIGNATURE);
    header[0x18..0x1a].copy_from_slice(&0x3eu16.to_le_bytes());
    header[0x1a..0x1c].copy_from_slice(&3u16.to_le_bytes());
    header[0x1c..0x1e].copy_from_slice(&0xfffeu16.to_le_bytes());
    header[0x1e..0x20].copy_from_slice(&9u16.to_le_bytes());
    header[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
    header[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes()); // FAT sectors
    header[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // first directory sector
    header[0x38..0x3c].copy_from_slice(&4096u32.to_le_bytes()); // mini stream cutoff
    header[0x3c..0x40].copy_from_slice(&2u32.to_le_bytes()); // first mini FAT sector
    header[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // mini FAT sectors
    header[0x44..0x48].copy_from_slice(&END_OF_CHAIN.to_le_bytes()); // no DIFAT sectors
    for i in 0..109 {
        let value: u32 = if i == 0 { 0 } else { FREE };
        header[0x4c + 4 * i..0x50 + 4 * i].copy_from_slice(&value.to_le_bytes());
    }

    let mut fat = vec![FREE; SECTOR / 4];
    fat[0] = FAT_SECTOR_MARK;
    fat[1] = END_OF_CHAIN;
    fat[2] = END_OF_CHAIN;
    fat[3] = END_OF_CHAIN;
    for i in 0..program_sectors {
        let n = 4 + i;
        fat[n] = if i + 1 == program_sectors {
            END_OF_CHAIN
        } else {
            (n + 1) as u32
        };
    }
    let fat: Vec<u8> = fat.iter().flat_map(|v| v.to_le_bytes()).collect();

    // Windows Installer packs "AB" into one code point: 0x3800 + A + (B << 6)
    // with A = 10, B = 11.
    let packed = [0x3800 + 10 + (11 << 6)];
    let mut directory = Vec::new();
    directory.extend(dir_entry(
        &utf16("Root Entry"),
        5,
        (NO_STREAM, NO_STREAM),
        1,
        3,
        64,
    ));
    directory.extend(dir_entry(
        &utf16("notes"),
        2,
        (NO_STREAM, 2),
        NO_STREAM,
        0,
        12,
    ));
    directory.extend(dir_entry(
        &utf16("Program"),
        2,
        (NO_STREAM, 3),
        NO_STREAM,
        4,
        program.len() as u32,
    ));
    directory.extend(dir_entry(
        &packed,
        2,
        (NO_STREAM, NO_STREAM),
        NO_STREAM,
        END_OF_CHAIN,
        0,
    ));

    let mut mini_fat = vec![0xffu8; SECTOR];
    mini_fat[..4].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
    let mut mini_stream = b"plain notes.".to_vec();
    mini_stream.resize(SECTOR, 0);

    [
        header,
        fat,
        directory,
        mini_fat,
        mini_stream,
        program.to_vec(),
    ]
    .concat()
}

#[test]
fn recognized_streams_are_members_and_supply_the_isa() {
    let v = compound_file(&elf_x86_64(4096));
    let p = detect_payload(&v, &ClassifierOptions::new()).unwrap();
    assert_eq!(p.format.format, FileFormat::Cfb);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let members: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    // The data stream `notes` is not a recognized format and is not listed.
    assert_eq!(members, ["Program"]);
    assert_eq!(p.slices[0].offset, 5 * 512);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("4 directory entries, 3 streams")));
}

#[test]
fn installer_stream_names_are_unpacked() {
    let v = compound_file(&elf_x86_64(4096));
    let c = cfb::parse_container(&v, Layout::CompoundFile).unwrap();
    let names: Vec<&str> = c.children.iter().map(|ch| ch.label.as_str()).collect();
    assert_eq!(names, ["notes", "Program"]);
    // The packed name belongs to an empty stream, which is not extracted.
    assert!(c.children.iter().all(|ch| ch.label != "AB"));
}

#[test]
fn truncated_and_corrupt_tables_are_parse_errors() {
    let v = compound_file(&elf_x86_64(4096));
    for end in 0..v.len() {
        assert!(
            cfb::parse_container(&v[..end], Layout::CompoundFile).is_err(),
            "{end}"
        );
    }
    // A FAT chain that points back into itself before the stream ends
    let mut looping = v.clone();
    let second = 512 + 4 * 5;
    looping[second..second + 4].copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(
        cfb::parse_container(&looping, Layout::CompoundFile),
        Err(ClassifierError::CfbParseError { message }) if message.contains("loops")
    ));
    // A directory tree that reaches an entry twice
    let mut cycle = v.clone();
    let program_right = 1024 + 2 * 128 + 0x48;
    cycle[program_right..program_right + 4].copy_from_slice(&1u32.to_le_bytes());
    assert!(cfb::parse_container(&cycle, Layout::CompoundFile).is_err());
    // Version 4 needs 4096-byte sectors
    let mut version = v.clone();
    version[0x1a] = 4;
    assert!(cfb::parse_container(&version, Layout::CompoundFile).is_err());
}

#[test]
fn byte_mutations_do_not_panic() {
    let v = compound_file(&elf_x86_64(4096));
    for i in (0..v.len()).step_by(3) {
        for x in [0x00, 0xff, v[i] ^ 0x80] {
            let mut m = v.clone();
            m[i] = x;
            let _ = detect_payload(&m, &ClassifierOptions::new());
        }
    }
}
