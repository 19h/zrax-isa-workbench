//! Amiga disk images: amitools-written ADF floppies (OFS, FFS, directory
//! cache, long names, HD) and a Rigid Disk Block hard disk, synthetic images
//! built from the documented layouts for what the fixtures do not cover
//! (bootable non-DOS floppies, unpartitioned hardfiles, damaged blocks,
//! loops, links, depth and size limits), and truncation and mutation sweeps.

use std::borrow::Cow;
use zrax::formats::adf::{self, Density, Layout};
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::{Child, Classify, Container};
use zrax::types::MetadataKey;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/adf");

/// A gzip-compressed fixture from `tests/fixtures/adf`, decompressed.
fn fixture(name: &str) -> Vec<u8> {
    let stored = std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed");
    compressed::decode(Codec::Gzip, &stored)
        .expect("the fixture is a gzip stream")
        .data
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse an image that must be valid.
fn parse(image: &[u8]) -> Container<'_> {
    let layout = adf::detect(image).expect("detected as an Amiga disk image");
    adf::parse_container(image, layout).expect("parses")
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

fn be_u32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn put_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn u32_of(value: usize) -> u32 {
    u32::try_from(value).expect("fits in 32 bits")
}

// ---------------------------------------------------------------------------
// Synthetic file contents, as tests/fixtures/adf/generate.py writes them
// ---------------------------------------------------------------------------

/// Hunk block types (`dos/doshunks.h`).
const HUNK_HEADER: u32 = 0x3f3;
const HUNK_CODE: u32 = 0x3e9;
const HUNK_END: u32 = 0x3f2;

/// `moveq #0,d0` (7000), `rts` (4E75).
const RETURN_ZERO: u32 = 0x7000_4e75;
/// `nop` (4E71) twice.
const TWO_NOPS: u32 = 0x4e71_4e71;
/// `nop` (4E71), `rts` (4E75).
const NOP_RETURN: u32 = 0x4e71_4e75;

/// A Hunk executable with one code hunk: `HUNK_HEADER`, no resident
/// libraries, a hunk table of one hunk (first 0, last 0, its size in
/// longs), `HUNK_CODE` with the size and the code, `HUNK_END`.
fn hunk(code: &[u32]) -> Vec<u8> {
    let size = u32_of(code.len());
    let mut words = vec![HUNK_HEADER, 0, 1, 0, 0, size, HUNK_CODE, size];
    words.extend_from_slice(code);
    words.push(HUNK_END);
    words.iter().flat_map(|word| word.to_be_bytes()).collect()
}

/// The 40-byte executable most fixture files hold.
fn small_hunk() -> Vec<u8> {
    hunk(&[RETURN_ZERO])
}

/// `/c/deep/big`: 80 KiB of code, 161 FFS or 168 OFS data blocks and two
/// extension blocks.
fn big_hunk() -> Vec<u8> {
    let mut code = vec![TWO_NOPS; 20_479];
    code.push(NOP_RETURN);
    hunk(&code)
}

/// The boot block code of `ffs.adf.gz`, entered at offset 12, then the
/// library name it looks up.
fn boot_code() -> Vec<u8> {
    let instructions: [&[u8]; 10] = [
        // lea dosname(pc),a1: 0x0E + 0x18 = 0x26
        &[0x43, 0xfa, 0x00, 0x18],
        // jsr -96(a6): exec FindResident
        &[0x4e, 0xae, 0xff, 0xa0],
        // tst.l d0
        &[0x4a, 0x80],
        // beq.s fail: 0x18 + 0x0A = 0x22
        &[0x67, 0x0a],
        // movea.l d0,a0: the dos.library resident tag
        &[0x20, 0x40],
        // movea.l 22(a0),a0: rt_Init, the completion function
        &[0x20, 0x68, 0x00, 0x16],
        // moveq #0,d0: boot succeeds
        &[0x70, 0x00],
        // rts
        &[0x4e, 0x75],
        // fail: moveq #-1,d0
        &[0x70, 0xff],
        // rts
        &[0x4e, 0x75],
    ];
    let mut code = instructions.concat();
    code.extend_from_slice(b"dos.library\0");
    code
}

/// The members of each amitools floppy, in walk order: the root's files by
/// hash slot (the three `file_*` names share one, [FAQ] 4.2.1), then `/c`
/// and `/c/deep`.
const FLOPPY_MEMBERS: [&str; 7] = [
    "/hello",
    "/caf\u{e9}",
    "/file_5u",
    "/file_24",
    "/file_1a",
    "/c/run",
    "/c/deep/big",
];

const LONG_NAME: &str = "/A file name that is longer than thirty characters";

struct FloppyFixture {
    name: &'static str,
    density: Density,
    dos_type: &'static str,
    filesystem: &'static str,
    ffs: bool,
}

const FLOPPIES: [FloppyFixture; 5] = [
    FloppyFixture {
        name: "ofs.adf.gz",
        density: Density::Double,
        dos_type: "DOS\\0",
        filesystem: "OFS",
        ffs: false,
    },
    FloppyFixture {
        name: "ffs.adf.gz",
        density: Density::Double,
        dos_type: "DOS\\1",
        filesystem: "FFS",
        ffs: true,
    },
    FloppyFixture {
        name: "dircache.adf.gz",
        density: Density::Double,
        dos_type: "DOS\\5",
        filesystem: "FFS, international mode, directory cache",
        ffs: true,
    },
    FloppyFixture {
        name: "longnames.adf.gz",
        density: Density::Double,
        dos_type: "DOS\\7",
        filesystem: "FFS, international mode, long file names",
        ffs: true,
    },
    FloppyFixture {
        name: "hd.adf.gz",
        density: Density::High,
        dos_type: "DOS\\3",
        filesystem: "FFS, international mode",
        ffs: true,
    },
];

/// The members `fixture` lists, in walk order.
fn floppy_members(floppy: &FloppyFixture) -> Vec<String> {
    let mut members: Vec<String> = FLOPPY_MEMBERS.iter().map(ToString::to_string).collect();
    if floppy.name == "longnames.adf.gz" {
        // Its hash slot follows those of the other root files.
        members.insert(5, LONG_NAME.to_string());
    }
    members
}

// ---------------------------------------------------------------------------
// The amitools fixtures
// ---------------------------------------------------------------------------

#[test]
fn amitools_floppies_list_their_executables_by_path() {
    for floppy in &FLOPPIES {
        let image = fixture(floppy.name);
        let layout = adf::detect(&image).expect("detected");
        assert_eq!(layout, Layout::Floppy(floppy.density), "{}", floppy.name);
        assert_eq!(layout.format(), FileFormat::Adf);
        assert!(!layout.is_weak());
        let c = parse(&image);
        let mut expected = floppy_members(floppy);
        if floppy.name == "ffs.adf.gz" {
            expected.push("Boot block code".to_string());
        }
        assert_eq!(labels(&c), expected, "{}", floppy.name);
        for member in &c.children[..floppy_members(floppy).len()] {
            assert_eq!(member.classify, Classify::IfRecognized, "{}", floppy.name);
            assert_eq!(member.target, None, "{}: files name no ISA", floppy.name);
            let contents = if member.label == "/c/deep/big" {
                big_hunk()
            } else {
                small_hunk()
            };
            assert_eq!(
                member.data.as_ref(),
                contents.as_slice(),
                "{}",
                member.label
            );
        }
        assert_eq!(c.consumed, image.len());
        assert_eq!(c.target, None);
        let walk = format!(
            "Directory walk: 3 directories, {} regular files; members in a recognized format: {}",
            floppy_members(floppy).len() + 1,
            floppy_members(floppy).len()
        );
        assert!(has_note(&c, &walk), "{}: {:?}", floppy.name, c.notes);
        assert!(
            !has_note(&c, "hash chain of another name"),
            "{}: every entry is in its name's chain",
            floppy.name
        );
        assert!(has_note(
            &c,
            "Bitmap: 1 block listed in the root block, checksums valid"
        ));
        for (key, value) in [
            ("adf_dos_type", floppy.dos_type),
            ("adf_filesystem", floppy.filesystem),
            ("adf_volume_name", "Zrax"),
            ("adf_created", "2001-09-09 01:46:40"),
            ("adf_modified", "2001-09-09 01:46:40"),
            (
                "adf_member_count",
                &floppy_members(floppy).len().to_string(),
            ),
        ] {
            assert_eq!(
                metadata(&c, key).as_deref(),
                Some(value),
                "{} {key}",
                floppy.name
            );
        }
        let root = if floppy.density == Density::High {
            "1760"
        } else {
            "880"
        };
        assert_eq!(metadata(&c, "adf_root_block").as_deref(), Some(root));
    }
}

#[test]
fn ffs_files_in_consecutive_blocks_are_borrowed_and_others_reassembled() {
    for floppy in &FLOPPIES {
        let image = fixture(floppy.name);
        let c = parse(&image);
        let hello = child(&c, "/hello");
        let big = child(&c, "/c/deep/big");
        if floppy.ffs {
            // One block, stored as it is at its offset.
            assert_eq!(hello.transform, None, "{}", floppy.name);
            assert!(matches!(hello.data, Cow::Borrowed(_)));
            let stored = &image[hello.offset..hello.offset + hello.stored_size];
            assert_eq!(stored, small_hunk().as_slice(), "{}", floppy.name);
            // The data blocks after the header's 72 follow an extension
            // block, so the file is reassembled; the first run is stored.
            assert_eq!(big.transform, Some("AmigaDOS FFS data blocks"));
            assert_eq!(big.stored_size % 512, 0, "{}", floppy.name);
            assert_eq!(
                &image[big.offset..big.offset + 4],
                &HUNK_HEADER.to_be_bytes()
            );
        } else {
            // OFS data blocks start with a 24-byte header.
            assert_eq!(hello.transform, Some("AmigaDOS OFS data blocks"));
            assert_eq!(hello.offset % 512, 24);
            assert_eq!(hello.stored_size, 40);
            assert_eq!(big.stored_size, 488);
            assert_eq!(
                &image[big.offset..big.offset + big.stored_size],
                &big_hunk()[..488]
            );
        }
    }
    let p = classify(&fixture("ofs.adf.gz"));
    let big = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("/c/deep/big"))
        .expect("listed");
    let decoded = big.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "AmigaDOS OFS data blocks");
    assert_eq!(decoded.size, big_hunk().len() as u64);
    assert_eq!(big.size, 488, "the stored bytes of the first data block");
}

#[test]
fn the_boot_block_code_is_680x0_code_listed_after_the_files() {
    let image = fixture("ffs.adf.gz");
    let c = parse(&image);
    let boot = c.children.last().expect("children");
    assert_eq!(boot.label, "Boot block code");
    assert_eq!((boot.offset, boot.data.len()), (12, 1012));
    let code = boot_code();
    assert_eq!(&boot.data[..code.len()], code.as_slice());
    assert_eq!(boot.classify, Classify::Code);
    let target = boot.target.expect("68000 target");
    assert_eq!(
        (target.isa, target.bits, target.endianness),
        (Isa::M68k, 32, Some(Endianness::Big))
    );
    assert!(has_note(
        &c,
        "Boot block code at 0xC-0x3FF (1012 B): the DOS signature and the boot block checksum \
         0xD2A50F18 are valid, so Kickstart runs it on the 680x0 from offset 12 (BB_ENTRY)"
    ));
    assert_eq!(
        metadata(&c, "adf_boot_checksum").as_deref(),
        Some("0xD2A50F18 (valid)")
    );
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Adf);
    assert_eq!(p.format.variant_name.as_deref(), Some("AmigaDOS DD floppy"));
    let last = p.slices.last().expect("slices");
    assert_eq!(last.label.as_deref(), Some("Boot block code"));
    assert_eq!((last.isa, last.bitwidth), (Isa::M68k, 32));
    // The first file decides the primary ISA, not the boot code.
    assert_eq!(p.primary.isa, Isa::M68k);
    assert!(
        p.notes
            .iter()
            .any(|n| n.message.contains("Primary ISA selected from /hello")),
        "{:?}",
        p.notes
    );
    // The other fixtures carry no boot code.
    let ofs = fixture("ofs.adf.gz");
    let c = parse(&ofs);
    assert!(has_note(
        &c,
        "Boot block code: none; the boot code area 0xC-0x3FF is zero"
    ));
}

#[test]
fn every_fixture_classifies_as_68000_code_from_its_members() {
    for floppy in &FLOPPIES {
        let p = classify(&fixture(floppy.name));
        assert_eq!(p.format.format, FileFormat::Adf, "{}", floppy.name);
        assert_eq!(p.primary.isa, Isa::M68k, "{}", floppy.name);
        let members = floppy_members(floppy);
        let listed: Vec<&str> = p
            .slices
            .iter()
            .filter_map(|s| s.label.as_deref())
            .take(members.len())
            .collect();
        assert_eq!(listed, members, "{}", floppy.name);
        assert!(
            p.slices.iter().all(|s| s.isa == Isa::M68k),
            "{}",
            floppy.name
        );
    }
}

#[test]
fn rigid_disk_partitions_are_walked_with_their_drive_names() {
    let image = fixture("rdb.hdf.gz");
    assert_eq!(adf::detect(&image), Some(Layout::RigidDisk));
    assert_eq!(Layout::RigidDisk.format(), FileFormat::AmigaHdf);
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "DH0:/hello",
            "DH0:/c/run",
            "DH1:/tool",
            "File system DOS\\3 version 45.13"
        ]
    );
    for label in ["DH0:/hello", "DH0:/c/run", "DH1:/tool"] {
        assert_eq!(
            child(&c, label).data.as_ref(),
            small_hunk().as_slice(),
            "{label}"
        );
    }
    // DH1 is OFS, so its file is reassembled from its data block.
    assert_eq!(
        child(&c, "DH1:/tool").transform,
        Some("AmigaDOS OFS data blocks")
    );
    let handler = child(&c, "File system DOS\\3 version 45.13");
    assert_eq!(handler.transform, Some("RDB LoadSeg blocks"));
    assert_eq!(handler.classify, Classify::Always);
    let code = hunk(&[RETURN_ZERO; 200]);
    assert_eq!(&handler.data[..code.len()], code.as_slice());
    for note in [
        "Rigid Disk Block at block 0 (0x0): 32 cylinders, 2 heads, 32 sectors per track (2048 \
         blocks of 512 B)",
        "Drive identification: vendor \"ZRAX\", product \"SYNTHETIC\", revision \"1.0\"",
        "DH0 (partition block 1): cylinders 1-15, 960 blocks from block 64 (0x8000); bootable, \
         boot priority 0",
        "DH0: AmigaDOS volume \"Work\": FFS, international mode (DOS\\3); 960 blocks, root block \
         480 at 0x44000",
        "DH1 (partition block 2): cylinders 16-31, 1024 blocks from block 1024 (0x80000)",
        "DH1: AmigaDOS volume \"Data\": OFS (DOS\\0); 1024 blocks, root block 512 at 0xC0000",
        "File system DOS\\3 version 45.13 (block 3): 2 load segment blocks from block 4, 836 B",
        "Directory walk: 3 directories, 4 regular files; members in a recognized format: 3",
    ] {
        assert!(has_note(&c, note), "{note}: {:?}", c.notes);
    }
    assert_eq!(
        metadata(&c, "adf_partition_1_volume_name").as_deref(),
        Some("Data")
    );
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AmigaHdf);
    assert_eq!(p.format.variant_name.as_deref(), Some("Rigid Disk Block"));
    assert_eq!(p.primary.isa, Isa::M68k);
    assert_eq!(p.slices.len(), 4);
}

/// Recompute the checksum of the Rigid Disk Block structure at `offset`:
/// its `SummedLongs` longs sum to zero, the checksum is the third long.
fn fix_rdb_checksum(image: &mut [u8], offset: usize) {
    let longs = usize::try_from(be_u32(image, offset + 4)).expect("small");
    put_u32(image, offset + 8, 0);
    let sum = (0..longs).fold(0u32, |sum, i| {
        sum.wrapping_add(be_u32(image, offset + 4 * i))
    });
    put_u32(image, offset + 8, 0u32.wrapping_sub(sum));
}

/// The `PART` blocks of the fixture: 1 (`DH0`) and 2 (`DH1`).
const DH0_PART: usize = 512;
const DH1_PART: usize = 1024;
/// `pb_Next`, and `pb_Environment[DE_LOWCYL]` and `[DE_SIZEBLOCK]`.
const PB_NEXT: usize = 0x10;
const PB_SIZE_BLOCK: usize = 0x80 + 4;
const PB_LOW_CYL: usize = 0x80 + 9 * 4;

#[test]
fn rigid_disk_damage_is_noted_or_an_error() {
    let image = fixture("rdb.hdf.gz");
    // A partition list that loops: DH1 links back to DH0.
    let mut looped = image.clone();
    put_u32(&mut looped, DH1_PART + PB_NEXT, 1);
    fix_rdb_checksum(&mut looped, DH1_PART);
    let c = parse(&looped);
    assert!(has_note(
        &c,
        "The partition list loops back to block 1; it ends there"
    ));
    assert_eq!(labels(&c).len(), 4);
    // A partition block whose checksum fails ends the list.
    let mut broken = image.clone();
    broken[DH1_PART + 0x30] ^= 1;
    let c = parse(&broken);
    assert!(
        has_note(
            &c,
            "The partition list ends early: the PART block 2 fails its checksum"
        ),
        "{:?}",
        c.notes
    );
    assert_eq!(
        labels(&c),
        [
            "DH0:/hello",
            "DH0:/c/run",
            "File system DOS\\3 version 45.13"
        ]
    );
    // An environment with another block size is not read.
    let mut sized = image.clone();
    put_u32(&mut sized, DH0_PART + PB_SIZE_BLOCK, 256);
    fix_rdb_checksum(&mut sized, DH0_PART);
    assert!(has_note(
        &parse(&sized),
        "DH0 (partition block 1): unsupported block size of 256 longs (only 128, 512 B, is \
         read); not read"
    ));
    // A partition that starts on the wrong cylinder holds no root block.
    let mut moved = image.clone();
    put_u32(&mut moved, DH0_PART + PB_LOW_CYL, 2);
    fix_rdb_checksum(&mut moved, DH0_PART);
    let c = parse(&moved);
    assert!(
        c.notes
            .iter()
            .any(|n| n.starts_with("DH0: the boot block starts with")),
        "{:?}",
        c.notes
    );
    // The Rigid Disk Block itself: a failing checksum is not detected,
    // and parsing it is an error naming the block.
    let mut damaged = image.clone();
    damaged[0x40] ^= 1;
    assert_eq!(adf::detect(&damaged), None);
    let error = adf::parse_container(&damaged, Layout::RigidDisk)
        .expect_err("no Rigid Disk Block")
        .to_string();
    assert_eq!(
        error,
        "Amiga disk image parse error: Invalid Rigid Disk Block: the RDSK block 0 fails its \
         checksum"
    );
    // Only 512-byte blocks are read.
    let mut large = image.clone();
    put_u32(&mut large, 0x10, 1024);
    fix_rdb_checksum(&mut large, 0);
    assert_eq!(
        adf::parse_container(&large, Layout::RigidDisk)
            .expect_err("unsupported")
            .to_string(),
        "Amiga disk image parse error: Unsupported rdb_BlockBytes 1024 at 0x10: only 512-byte \
         blocks are read"
    );
    assert_eq!(
        adf::parse_container(&[0u8; 8192], Layout::RigidDisk)
            .expect_err("missing")
            .to_string(),
        "Amiga disk image parse error: Missing Rigid Disk Block: no RDSK in the first 16 blocks"
    );
}

/// A POSIX ustar archive holding `contents` as the regular file `name`: a
/// 512-byte header (name, mode `0000644`, uid and gid 0, the size and mtime
/// 0 in octal, the checksum over the header with its own field as spaces,
/// type `0`, magic `ustar\0` and version `00`), the contents padded to a
/// block, and two zero blocks.
fn ustar(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut header = [0u8; BLOCK];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", contents.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut archive = header.to_vec();
    archive.extend_from_slice(contents);
    archive.resize(round_up_to_block(archive.len()), 0);
    archive.extend_from_slice(&[0u8; 2 * BLOCK]);
    archive
}

/// `size` rounded up to whole blocks.
fn round_up_to_block(size: usize) -> usize {
    (size / BLOCK + usize::from(size % BLOCK != 0)) * BLOCK
}

#[test]
fn a_rigid_disk_image_inside_a_tar_archive_is_the_archive_member() {
    // The disk's RDSK block lands in block 1 of the archive, where its
    // block pointers miss: the archive is not a Rigid Disk Block disk.
    let disk = fixture("rdb.hdf.gz");
    let archive = ustar("disk.hdf", &disk);
    assert_eq!(&archive[BLOCK..BLOCK + 4], b"RDSK");
    assert_eq!(adf::detect(&archive), None);
    assert!(adf::parse_container(&archive, Layout::RigidDisk)
        .expect_err("not a disk")
        .to_string()
        .contains("the RDSK block 1 follows other data"));
    let p = classify(&archive);
    assert_eq!(p.format.format, FileFormat::Tar);
    assert_eq!(p.primary.isa, Isa::M68k);
    let member = p.slices.first().expect("the disk is a member");
    assert_eq!(member.label.as_deref(), Some("disk.hdf"));
    assert_eq!(member.offset, BLOCK as u64);
}

// ---------------------------------------------------------------------------
// Synthetic volumes, built from the documented layout ([FAQ] 4.1-4.6)
// ---------------------------------------------------------------------------

const BLOCK: usize = 512;

/// Primary and secondary block types ([FAQ] 4.2-4.6; `ADFlib` `adf_blk.h`).
const T_HEADER: u32 = 2;
const T_DATA: u32 = 8;
const T_LIST: u32 = 16;
const ST_ROOT: u32 = 1;
const ST_USERDIR: u32 = 2;
/// -3 and -4, stored as two's complement longs.
const ST_FILE: u32 = 0xffff_fffd;
const ST_LINKFILE: u32 = 0xffff_fffc;

/// Block fields ([FAQ] 4.2, 4.4, 4.5).
const TYPE: usize = 0x000;
const HEADER_KEY: usize = 0x004;
const HIGH_SEQ: usize = 0x008;
const HT_SIZE: usize = 0x00c;
/// OFS data blocks: `seq_num`, `data_size`, `next_data`.
const SEQ_NUM: usize = 0x008;
const DATA_SIZE: usize = 0x00c;
const NEXT_DATA: usize = 0x010;
const FIRST_DATA: usize = 0x010;
const CHECKSUM: usize = 0x014;
/// The hash table (root, directories) or the data block pointers (file
/// headers, extension blocks), 72 longs.
const TABLE: usize = 0x018;
const TABLE_ENTRIES: usize = 72;
const BM_FLAG: usize = 0x138;
const BM_PAGES: usize = 0x13c;
const BYTE_SIZE: usize = 0x144;
const NAME: usize = 0x1b0;
const CREATION_DATE: usize = 0x1e4;
const HASH_CHAIN: usize = 0x1f0;
const PARENT: usize = 0x1f4;
const EXTENSION: usize = 0x1f8;
const SECONDARY_TYPE: usize = 0x1fc;

/// The boot block checksum ([FAQ] 4.1): the longs of the boot blocks but
/// the checksum itself, added with carry wraparound, complemented.
fn boot_checksum(boot: &[u8]) -> u32 {
    let sum = (0..boot.len() / 4)
        .filter(|&i| i != 1)
        .fold(0u32, |sum, i| {
            let (sum, carry) = sum.overflowing_add(be_u32(boot, 4 * i));
            sum + u32::from(carry)
        });
    !sum
}

/// Set the normal checksum of the block at `offset` ([FAQ] 4.2.3): the
/// negated sum of the other longs, at 0x14.
fn fix_checksum(image: &mut [u8], offset: usize) {
    put_u32(image, offset + CHECKSUM, 0);
    let sum = (0..BLOCK / 4).fold(0u32, |sum, i| {
        sum.wrapping_add(be_u32(image, offset + 4 * i))
    });
    put_u32(image, offset + CHECKSUM, 0u32.wrapping_sub(sum));
}

/// The hash table slot of `name` ([FAQ] 4.2.1, 5.4): starting from the
/// length, `hash * 13 + upper(c)` kept to 11 bits, modulo 72.
fn name_hash(name: &[u8], international: bool) -> usize {
    let upper = |c: u8| {
        let lower =
            c.is_ascii_lowercase() || (international && (224..=254).contains(&c) && c != 247);
        if lower {
            c - 32
        } else {
            c
        }
    };
    let hash = name.iter().fold(u32_of(name.len()), |hash, &c| {
        (hash * 13 + u32::from(upper(c))) & 0x7ff
    });
    usize::try_from(hash).expect("11 bits") % TABLE_ENTRIES
}

/// An `AmigaDOS` volume under construction: a floppy or a hardfile image.
struct Volume {
    image: Vec<u8>,
    /// Blocks in the volume.
    blocks: u32,
    root: u32,
    dos_type: u8,
    /// The next block to allocate.
    next_free: u32,
    /// Blocks whose normal checksum `finish` sets.
    checksummed: Vec<u32>,
    /// Boot code at offset 12, if any; `finish` sets the boot checksum.
    boot_code: Option<Vec<u8>>,
}

impl Volume {
    /// An empty DD floppy with DOS type `dos_type` (0 OFS, 1 FFS, ...).
    fn floppy(dos_type: u8) -> Self {
        Self::new(1760, 880, dos_type)
    }

    /// An empty volume of `blocks` blocks with its root block at `root`:
    /// - the boot block: `DOS`, the DOS type, `bb_dosblock` = `root`;
    /// - the root block: `T_HEADER`, `ht_size` 72, `bm_flag` -1 (valid),
    ///   `bm_pages[0]` = the next block, the volume name "Synthetic", the
    ///   creation date day 5615 (1993-05-17) 12:34:56, `ST_ROOT`;
    /// - the bitmap block after it: an all-zero map, checksum 0.
    fn new(blocks: u32, root: u32, dos_type: u8) -> Self {
        let size = usize::try_from(blocks).expect("small") * BLOCK;
        let mut volume = Self {
            image: vec![0; size],
            blocks,
            root,
            dos_type,
            next_free: root + 2,
            checksummed: vec![root],
            boot_code: None,
        };
        volume.image[..3].copy_from_slice(b"DOS");
        volume.image[3] = dos_type;
        put_u32(&mut volume.image, 8, root);
        volume.put(root, TYPE, T_HEADER);
        volume.put(root, HT_SIZE, u32_of(TABLE_ENTRIES));
        volume.put(root, BM_FLAG, 0xffff_ffff);
        volume.put(root, BM_PAGES, root + 1);
        volume.put_name(root, b"Synthetic");
        volume.put(root, CREATION_DATE, 5615);
        volume.put(root, CREATION_DATE + 4, 12 * 60 + 34);
        volume.put(root, CREATION_DATE + 8, 56 * 50);
        volume.put(root, SECONDARY_TYPE, ST_ROOT);
        volume
    }

    fn offset(block: u32) -> usize {
        usize::try_from(block).expect("small") * BLOCK
    }

    fn put(&mut self, block: u32, at: usize, value: u32) {
        put_u32(&mut self.image, Self::offset(block) + at, value);
    }

    fn get(&self, block: u32, at: usize) -> u32 {
        be_u32(&self.image, Self::offset(block) + at)
    }

    /// The name as a BCPL string at `NAME`: a length byte, then the
    /// characters.
    fn put_name(&mut self, block: u32, name: &[u8]) {
        let at = Self::offset(block) + NAME;
        self.image[at] = u8::try_from(name.len()).expect("short name");
        self.image[at + 1..at + 1 + name.len()].copy_from_slice(name);
    }

    fn is_ffs(&self) -> bool {
        self.dos_type & 1 != 0
    }

    fn is_international(&self) -> bool {
        self.dos_type & 0b110 != 0
    }

    fn alloc(&mut self) -> u32 {
        let block = self.next_free;
        self.next_free += 1;
        assert!(block < self.blocks, "the volume is full");
        block
    }

    /// Link `entry` named `name` into the hash table of `directory`: at the
    /// head of its slot's chain, the old head in the entry's `hash_chain`.
    fn link(&mut self, directory: u32, entry: u32, name: &[u8]) {
        let slot = TABLE + 4 * name_hash(name, self.is_international());
        let head = self.get(directory, slot);
        self.put(entry, HASH_CHAIN, head);
        self.put(directory, slot, entry);
    }

    /// An entry block: `T_HEADER`, its own number, the name, the parent
    /// directory and the secondary type, linked into `parent`.
    fn entry(&mut self, parent: u32, name: &[u8], secondary_type: u32) -> u32 {
        let block = self.alloc();
        self.put(block, TYPE, T_HEADER);
        self.put(block, HEADER_KEY, block);
        self.put_name(block, name);
        self.put(block, PARENT, parent);
        self.put(block, SECONDARY_TYPE, secondary_type);
        self.link(parent, block, name);
        self.checksummed.push(block);
        block
    }

    /// A user directory (`ST_USERDIR`) in `parent`.
    fn dir(&mut self, parent: u32, name: &[u8]) -> u32 {
        self.entry(parent, name, ST_USERDIR)
    }

    /// A hard link to a file (`ST_LINKFILE`) in `parent`.
    fn hard_link(&mut self, parent: u32, name: &[u8], target: u32) -> u32 {
        let block = self.entry(parent, name, ST_LINKFILE);
        // real_entry ([FAQ] 4.6.1).
        self.put(block, 0x1d4, target);
        block
    }

    /// A regular file (`ST_FILE`) in `parent`: the file header, then its
    /// data blocks, an extension block (`T_LIST`) before every further 72.
    /// Data blocks are raw on FFS; on OFS each starts with `T_DATA`, the
    /// header block, its sequence number from 1, its data size and the
    /// next data block, and is checksummed.
    fn file(&mut self, parent: u32, name: &[u8], contents: &[u8]) -> u32 {
        let header = self.entry(parent, name, ST_FILE);
        let data_size = if self.is_ffs() { BLOCK } else { BLOCK - 24 };
        let chunks: Vec<&[u8]> = contents.chunks(data_size).collect();
        self.put(header, BYTE_SIZE, u32_of(contents.len()));
        let mut table = header;
        let mut data_blocks = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let slot = i % TABLE_ENTRIES;
            if i > 0 && slot == 0 {
                let extension = self.alloc();
                self.put(extension, TYPE, T_LIST);
                self.put(extension, HEADER_KEY, extension);
                self.put(extension, PARENT, header);
                self.put(extension, SECONDARY_TYPE, ST_FILE);
                self.put(table, EXTENSION, extension);
                self.checksummed.push(extension);
                table = extension;
            }
            let block = self.alloc();
            // Data block pointers run backwards from the end of the table.
            self.put(table, TABLE + 4 * (TABLE_ENTRIES - 1 - slot), block);
            self.put(table, HIGH_SEQ, u32_of(slot + 1));
            let at = Self::offset(block);
            if self.is_ffs() {
                self.image[at..at + chunk.len()].copy_from_slice(chunk);
            } else {
                self.put(block, TYPE, T_DATA);
                self.put(block, HEADER_KEY, header);
                self.put(block, SEQ_NUM, u32_of(i + 1));
                self.put(block, DATA_SIZE, u32_of(chunk.len()));
                self.image[at + 24..at + 24 + chunk.len()].copy_from_slice(chunk);
                self.checksummed.push(block);
            }
            data_blocks.push(block);
        }
        if let Some(&first) = data_blocks.first() {
            self.put(header, FIRST_DATA, first);
        }
        if !self.is_ffs() {
            for pair in data_blocks.windows(2) {
                self.put(pair[0], NEXT_DATA, pair[1]);
            }
        }
        header
    }

    /// Boot code at `BB_ENTRY` (offset 12).
    fn boot(&mut self, code: &[u8]) {
        self.boot_code = Some(code.to_vec());
    }

    /// The image with every checksum set.
    fn finish(mut self) -> Vec<u8> {
        for block in std::mem::take(&mut self.checksummed) {
            fix_checksum(&mut self.image, Self::offset(block));
        }
        if let Some(code) = self.boot_code.take() {
            self.image[12..12 + code.len()].copy_from_slice(&code);
            let checksum = boot_checksum(&self.image[..1024]);
            put_u32(&mut self.image, 4, checksum);
        }
        self.image
    }
}

/// A DD FFS floppy holding `/a.exe`, `/text` and `/dir/b.exe`.
fn synthetic_floppy(dos_type: u8) -> Vec<u8> {
    let mut v = Volume::floppy(dos_type);
    let root = v.root;
    v.file(root, b"a.exe", &small_hunk());
    v.file(root, b"text", b"not a recognized format");
    let dir = v.dir(root, b"dir");
    v.file(dir, b"b.exe", &big_hunk());
    v.finish()
}

#[test]
fn synthetic_floppies_of_each_file_system_list_their_members() {
    for dos_type in [0, 1, 3] {
        let image = synthetic_floppy(dos_type);
        assert_eq!(adf::detect(&image), Some(Layout::Floppy(Density::Double)));
        let c = parse(&image);
        assert_eq!(labels(&c), ["/a.exe", "/dir/b.exe"], "DOS\\{dos_type}");
        assert_eq!(child(&c, "/a.exe").data.as_ref(), small_hunk().as_slice());
        assert_eq!(child(&c, "/dir/b.exe").data.as_ref(), big_hunk().as_slice());
        assert!(has_note(&c, "AmigaDOS volume \"Synthetic\": "));
        assert_eq!(
            metadata(&c, "adf_created").as_deref(),
            Some("1993-05-17 12:34:56")
        );
        assert!(has_note(&c, "Boot block code: none"));
    }
}

/// A DD floppy whose boot block holds `DOS\0`, the boot code and a valid
/// checksum, and whose other blocks are zero: a disk with a loader of its
/// own and no root block.
fn bootable_non_dos_floppy() -> Vec<u8> {
    let mut image = vec![0u8; 1760 * BLOCK];
    image[..4].copy_from_slice(b"DOS\0");
    let code = boot_code();
    image[12..12 + code.len()].copy_from_slice(&code);
    let checksum = boot_checksum(&image[..1024]);
    put_u32(&mut image, 4, checksum);
    image
}

#[test]
fn bootable_non_dos_floppies_list_their_boot_code() {
    let image = bootable_non_dos_floppy();
    let checksum = be_u32(&image, 4);
    assert_eq!(
        adf::detect(&image),
        Some(Layout::BootFloppy(Density::Double))
    );
    let c = parse(&image);
    assert_eq!(c.format, FileFormat::Adf);
    assert_eq!(labels(&c), ["Boot block code"]);
    assert!(
        has_note(
            &c,
            "Bootable disk with no AmigaDOS root block (block 880 at 0x6E000: its types are 0 \
             and 0, not T_HEADER (2) and ST_ROOT (1))"
        ),
        "{:?}",
        c.notes
    );
    let p = classify(&image);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Bootable non-DOS DD floppy")
    );
    assert_eq!(p.primary.isa, Isa::M68k, "{:?}", p.notes);
    assert_eq!(p.primary.endianness, Endianness::Big);

    // Any fourth byte: Kickstart checks only "DOS" and the checksum.
    let mut other = image.clone();
    other[3] = 0x42;
    let other_checksum = boot_checksum(&other[..1024]);
    put_u32(&mut other, 4, other_checksum);
    assert!(has_note(&parse(&other), "DOS type 0x42 is not one of 0-7"));

    // Without a valid checksum, or without code, it is not recognized.
    let mut unbootable = image.clone();
    unbootable[100] ^= 1;
    assert_eq!(adf::detect(&unbootable), None);
    assert_eq!(
        adf::parse_container(&unbootable, Layout::BootFloppy(Density::Double))
            .expect_err("not bootable")
            .to_string(),
        format!(
            "Amiga disk image parse error: Invalid boot block checksum 0x{checksum:08X} at 0x4: \
             0x{:08X} expected",
            boot_checksum(&unbootable[..1024])
        )
    );
    let mut empty = vec![0u8; 1760 * BLOCK];
    empty[..4].copy_from_slice(b"DOS\0");
    let empty_checksum = boot_checksum(&empty[..1024]);
    put_u32(&mut empty, 4, empty_checksum);
    assert_eq!(adf::detect(&empty), None);
    assert_eq!(
        adf::parse_container(&empty, Layout::BootFloppy(Density::Double))
            .expect_err("no code")
            .to_string(),
        "Amiga disk image parse error: Missing boot code: the boot code area 0xC-0x3FF is zero"
    );
    // A bootable AmigaDOS volume is not a bootable non-DOS floppy.
    let mut v = Volume::floppy(1);
    v.boot(&boot_code());
    let volume = v.finish();
    assert_eq!(adf::detect(&volume), Some(Layout::Floppy(Density::Double)));
    assert!(
        adf::parse_container(&volume, Layout::BootFloppy(Density::Double))
            .expect_err("holds a volume")
            .to_string()
            .contains("block 880 holds a valid root block")
    );
}

#[test]
fn boot_code_supplies_the_isa_only_when_no_file_does() {
    let mut v = Volume::floppy(1);
    let root = v.root;
    v.file(root, b"text", b"plain text");
    v.boot(&boot_code());
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(labels(&c), ["Boot block code"]);
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::M68k);
    assert!(
        p.notes.iter().any(|n| n
            .message
            .contains("Primary ISA selected from Boot block code")),
        "{:?}",
        p.notes
    );
    // A damaged boot block keeps its code out of the code model.
    let mut damaged = image.clone();
    damaged[20] ^= 0x80;
    let c = parse(&damaged);
    assert_eq!(labels(&c), Vec::<String>::new());
    assert!(has_note(
        &c,
        "Kickstart does not run it, so it is not classified"
    ));
    assert!(metadata(&c, "adf_boot_checksum")
        .expect("recorded")
        .contains("(invalid;"));
    assert_eq!(classify(&damaged).primary.isa, Isa::Unknown(0));
}

#[test]
fn unpartitioned_hardfiles_are_volumes_of_any_size() {
    // 2048 blocks (1 MiB): the root in the middle, block 1024.
    let mut v = Volume::new(2048, 1024, 3);
    let root = v.root;
    v.file(root, b"tool", &small_hunk());
    let image = v.finish();
    assert_eq!(adf::detect(&image), Some(Layout::Hardfile));
    let c = parse(&image);
    assert_eq!(c.format, FileFormat::AmigaHdf);
    assert_eq!(labels(&c), ["/tool"]);
    assert!(has_note(
        &c,
        "Hardfile without a Rigid Disk Block: one AmigaDOS volume of 2048 blocks of 512 B (1 MiB)"
    ));
    assert_eq!(
        classify(&image).format.variant_name.as_deref(),
        Some("Unpartitioned hardfile")
    );
    // An odd block count: (2 + 2049 - 1) / 2 = 1025 ([FAQ] 4.2) or
    // 2049 / 2 = 1024 (amitools); either holds the root.
    for root in [1025, 1024] {
        let mut v = Volume::new(2049, root, 1);
        let at = v.root;
        v.file(at, b"tool", &small_hunk());
        let image = v.finish();
        assert_eq!(adf::detect(&image), Some(Layout::Hardfile), "root {root}");
        assert_eq!(labels(&parse(&image)), ["/tool"]);
    }
    // Not a whole number of blocks.
    let mut odd = image.clone();
    odd.push(0);
    assert_eq!(adf::detect(&odd), None);
    assert!(adf::parse_container(&odd, Layout::Hardfile)
        .expect_err("not blocks")
        .to_string()
        .contains("Invalid hardfile size 1048577 B"));
}

#[test]
fn damaged_root_blocks_are_not_amigados_volumes() {
    let image = synthetic_floppy(1);
    let root = 880 * BLOCK;
    let mut damaged = image.clone();
    damaged[root + 0x100] ^= 1;
    assert_eq!(adf::detect(&damaged), None);
    let error = adf::parse_container(&damaged, Layout::Floppy(Density::Double))
        .expect_err("no root block")
        .to_string();
    assert_eq!(
        error,
        format!(
            "Amiga disk image parse error: Invalid root block: block 880 at 0x6E000: its \
             checksum is 0x{:08X}, not 0x{:08X}",
            be_u32(&damaged, root + CHECKSUM),
            be_u32(&damaged, root + CHECKSUM).wrapping_sub(1 << 24)
        )
    );
    let mut retyped = image.clone();
    put_u32(&mut retyped, root + SECONDARY_TYPE, ST_USERDIR);
    fix_checksum(&mut retyped, root);
    assert_eq!(adf::detect(&retyped), None);
    // DOS types beyond 7 are not AmigaDOS volumes.
    let mut unknown = image.clone();
    unknown[3] = 8;
    assert_eq!(adf::detect(&unknown), None);
    assert_eq!(
        adf::parse_container(&unknown, Layout::Floppy(Density::Double))
            .expect_err("unsupported")
            .to_string(),
        "Amiga disk image parse error: Unsupported DOS type 0x08 at 0x3: AmigaDOS defines 0-7"
    );
    // The image size must be a floppy's.
    assert!(adf::parse_container(
        &image[..image.len() - BLOCK],
        Layout::Floppy(Density::Double)
    )
    .expect_err("short")
    .to_string()
    .contains("Invalid image size 900608 B"));
    assert!(adf::parse_container(&image, Layout::Floppy(Density::High))
        .expect_err("density")
        .to_string()
        .contains("the size of a DD floppy, not HD"));
    let mut pfs = image.clone();
    pfs[..3].copy_from_slice(b"PFS");
    assert_eq!(adf::detect(&pfs), None);
    assert!(adf::parse_container(&pfs, Layout::Floppy(Density::Double))
        .expect_err("not DOS")
        .to_string()
        .contains("Missing DOS signature at 0x0: 50 46 53"));
}

#[test]
fn loops_and_cross_links_are_skipped_with_notes() {
    let mut v = Volume::floppy(1);
    let root = v.root;
    let a = v.file(root, b"a.exe", &small_hunk());
    let dir = v.dir(root, b"dir");
    v.file(dir, b"b.exe", &small_hunk());
    // a.exe's hash chain points to itself; dir's table names the root and
    // a.exe again (a loop and a cross-link).
    v.put(a, HASH_CHAIN, a);
    v.put(dir, TABLE + 4 * name_hash(b"loop", false), root);
    v.put(dir, TABLE + 4 * name_hash(b"again", false), a);
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/a.exe", "/dir/b.exe"]);
    for note in [
        format!(
            "Skipped an entry of /: block {a} is reached a second time (a loop or a cross-link)"
        ),
        "Skipped an entry of /dir: block 880 is reached a second time (a loop or a cross-link)"
            .to_string(),
        format!(
            "Skipped an entry of /dir: block {a} is reached a second time (a loop or a cross-link)"
        ),
    ] {
        assert!(has_note(&c, &note), "{note}: {:?}", c.notes);
    }
    // A directory that contains its parent ends there.
    let mut v = Volume::floppy(0);
    let root = v.root;
    let outer = v.dir(root, b"outer");
    let inner = v.dir(outer, b"inner");
    v.put(inner, TABLE + 4 * name_hash(b"outer", false), outer);
    let image = v.finish();
    let c = parse(&image);
    assert!(has_note(
        &c,
        &format!("Skipped an entry of /outer/inner: block {outer} is reached a second time")
    ));
    assert!(has_note(
        &c,
        "Directory walk: 3 directories, 0 regular files"
    ));
}

#[test]
fn damaged_entries_and_files_are_skipped_with_notes() {
    let mut v = Volume::floppy(0);
    let root = v.root;
    let checksum = v.file(root, b"checksum", &small_hunk());
    let key = v.file(root, b"key", &small_hunk());
    let slash = v.file(root, b"sla", &small_hunk());
    let kind = v.file(root, b"kind", &small_hunk());
    let sequence = v.file(root, b"sequence", &small_hunk());
    let high = v.file(root, b"high", &small_hunk());
    let extension = v.file(root, b"extension", &big_hunk());
    let size = v.file(root, b"size", &small_hunk());
    v.file(root, b"good", &small_hunk());
    v.put(key, HEADER_KEY, key + 100);
    // "sla/" with the slash after the hashed name.
    let at = Volume::offset(slash) + NAME;
    v.image[at] = 4;
    v.image[at + 4] = b'/';
    v.put(kind, SECONDARY_TYPE, 7);
    let first_data = v.get(sequence, FIRST_DATA);
    v.put(first_data, SEQ_NUM, 2);
    v.put(high, HIGH_SEQ, 2);
    v.put(extension, EXTENSION, 0);
    v.put(size, BYTE_SIZE, 5_000_000);
    let mut image = v.finish();
    image[Volume::offset(checksum) + 0x100] ^= 1;
    let c = parse(&image);
    assert_eq!(labels(&c), ["/good"]);
    for note in [
        format!("block {checksum} fails its checksum"),
        format!("block {key} gives its own number as {}", key + 100),
        format!("block {slash} holds the name \"sla/\", which contains / or :"),
        format!("block {kind} has the secondary type 7, not a directory, file or link"),
        format!(
            "Skipped /sequence: data block {first_data} names file header {sequence} and sequence \
             number 2, not {sequence} and 1"
        ),
        "Skipped /high: its file header lists 2 data blocks; 40 B need 1 there".to_string(),
        "Skipped /extension: its extension block chain ends after 0 blocks; 168 data blocks need 2"
            .to_string(),
        "Skipped /size: its size of 5000000 B needs 10246 data blocks; the input holds 1760 \
         blocks of the volume"
            .to_string(),
    ] {
        assert!(has_note(&c, &note), "{note}: {:?}", c.notes);
    }
}

#[test]
fn links_are_counted_and_not_followed() {
    let mut v = Volume::floppy(1);
    let root = v.root;
    let file = v.file(root, b"real.exe", &small_hunk());
    v.hard_link(root, b"link.exe", file);
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/real.exe"]);
    assert!(has_note(&c, "1 hard or soft link was not followed"));
    assert_eq!(metadata(&c, "adf_link_count").as_deref(), Some("1"));
}

#[test]
fn deep_trees_are_bounded() {
    let mut v = Volume::floppy(1);
    let mut parent = v.root;
    for _ in 0..66 {
        parent = v.dir(parent, b"d");
    }
    v.file(parent, b"deep.exe", &small_hunk());
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(labels(&c), Vec::<String>::new());
    assert!(has_note(
        &c,
        "1 directory deeper than 64 levels was not walked"
    ));
    assert!(has_note(&c, "Directory walk: 65 directories"));
}

#[test]
fn hash_chains_and_international_names_follow_the_hash() {
    // The three names share a slot ([FAQ] 4.2.1) and form a chain.
    let mut v = Volume::floppy(3);
    let root = v.root;
    for name in [&b"file_1a"[..], b"file_24", b"file_5u", b"caf\xe9"] {
        v.file(root, name, &small_hunk());
    }
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(labels(&c).len(), 4);
    assert!(labels(&c).contains(&"/caf\u{e9}".to_string()));
    assert!(!has_note(&c, "hash chain of another name"));
    // The same names hashed without the international mode: "café" lands
    // in another slot than an international volume expects.
    let mut plain = image.clone();
    plain[3] = 1;
    let c = parse(&plain);
    assert!(has_note(&c, "1 entry is in the hash chain of another name"));
}

// ---------------------------------------------------------------------------
// Truncation and mutation sweeps
// ---------------------------------------------------------------------------

/// Every member of a parse of a prefix is the same as in the whole image,
/// and its stored bytes lie inside the prefix.
fn assert_prefix_claims_nothing_missing(whole: &Container<'_>, prefix: &Container<'_>, end: usize) {
    for member in &prefix.children {
        let full = whole
            .children
            .iter()
            .find(|c| c.label == member.label)
            .unwrap_or_else(|| panic!("prefix {end} lists {}", member.label));
        assert_eq!(member.data, full.data, "prefix {end} {}", member.label);
        assert!(member.offset + member.stored_size <= end, "prefix {end}");
    }
}

#[test]
fn prefixes_are_not_floppies_and_claim_nothing_missing() {
    for name in ["ofs.adf.gz", "hd.adf.gz"] {
        let image = fixture(name);
        let whole = parse(&image);
        let layout = adf::detect(&image).expect("detected");
        for end in 0..image.len() {
            let prefix = &image[..end];
            assert!(
                adf::parse_container(prefix, layout).is_err(),
                "{name} {end}"
            );
            match adf::detect(prefix) {
                None => {}
                // Without its last block the volume's middle is still its
                // root block, so the prefix is a hardfile of one block
                // fewer.
                Some(Layout::Hardfile) => {
                    assert_eq!(end, image.len() - BLOCK, "{name}");
                    let c = adf::parse_container(prefix, Layout::Hardfile).expect("parses");
                    assert_prefix_claims_nothing_missing(&whole, &c, end);
                }
                Some(other) => panic!("{name}: prefix {end} is {other:?}"),
            }
        }
    }
}

#[test]
fn rigid_disk_prefixes_claim_nothing_missing() {
    let image = fixture("rdb.hdf.gz");
    let whole = parse(&image);
    let ends = (0..4 * BLOCK)
        .chain((4 * BLOCK..image.len()).step_by(BLOCK))
        .chain((BLOCK - 1..image.len()).step_by(BLOCK * 7));
    for end in ends {
        let prefix = &image[..end];
        match adf::detect(prefix) {
            Some(Layout::RigidDisk) => {
                let c = adf::parse_container(prefix, Layout::RigidDisk).expect("parses");
                assert_prefix_claims_nothing_missing(&whole, &c, end);
            }
            None => assert!(end < BLOCK, "prefix {end} holds the RDSK block"),
            Some(other) => panic!("prefix {end} is {other:?}"),
        }
    }
}

/// Mutate each byte at `positions` to 0x00, 0xFF and a bit flip, detect
/// and parse each result, and classify every `classify_every`th.
fn mutate(image: &mut [u8], positions: impl Iterator<Item = usize>, classify_every: usize) {
    for (n, at) in positions.enumerate() {
        let original = image[at];
        for value in [0x00, 0xff, original ^ 0x01] {
            image[at] = value;
            if let Some(layout) = adf::detect(image) {
                let _ = adf::parse_container(image, layout);
            }
            if n % classify_every == 0 {
                let _ = detect_payload(image, &ClassifierOptions::new());
            }
        }
        image[at] = original;
    }
}

/// File offsets of the blocks of `image` that hold file system structure:
/// header, extension and OFS data blocks with a valid checksum.
fn structure_blocks(image: &[u8]) -> Vec<usize> {
    image
        .chunks_exact(BLOCK)
        .enumerate()
        .filter(|(_, block)| {
            let kind = be_u32(block, TYPE);
            let sum = (0..BLOCK / 4).fold(0u32, |sum, i| sum.wrapping_add(be_u32(block, 4 * i)));
            matches!(kind, T_HEADER | T_LIST | T_DATA) && sum == 0
        })
        .map(|(i, _)| i * BLOCK)
        .collect()
}

#[test]
fn fixture_mutations_never_panic() {
    for (name, classify_every) in [("ofs.adf.gz", 97), ("ffs.adf.gz", 89)] {
        let mut image = fixture(name);
        let blocks = structure_blocks(&image);
        assert!(blocks.len() > 10, "{name}");
        // The boot block header and every 16th byte of its code, the whole
        // root block, the fields of the first 24 structure blocks (for OFS
        // these include data blocks), and every 4099th byte.
        let root = blocks
            .iter()
            .copied()
            .find(|&offset| be_u32(&image, offset + SECONDARY_TYPE) == ST_ROOT)
            .expect("root block");
        let positions: Vec<usize> = (0..64)
            .chain((64..1024).step_by(16))
            .chain(root..root + BLOCK)
            .chain(
                blocks
                    .iter()
                    .take(24)
                    .flat_map(|&offset| field_offsets(offset)),
            )
            .chain((0..image.len()).step_by(4099))
            .collect();
        mutate(&mut image, positions.into_iter(), classify_every);
    }
    let mut image = fixture("rdb.hdf.gz");
    // The 256-byte RDSK, PART and FSHD structures and the LSEG blocks, the
    // fields of both partitions' boot and root blocks, and every 4099th
    // byte.
    let positions: Vec<usize> = (0..6)
        .flat_map(|block| block * BLOCK..block * BLOCK + BLOCK / 2)
        .chain(0x8000..0x8040)
        .chain(field_offsets(0x44000))
        .chain(0x80000..0x80040)
        .chain(field_offsets(0xc0000))
        .chain((0..image.len()).step_by(4099))
        .collect();
    mutate(&mut image, positions.into_iter(), 101);
}

/// The fields of the structure block at `offset` that the parser reads:
/// the types, keys, counts, sizes and checksum (0x00-0x1F), the end of the
/// table and the size (0x130-0x14F), the name (0x1B0-0x1CF), and the
/// chain, parent, extension and secondary type (0x1F0-0x1FF).
fn field_offsets(offset: usize) -> impl Iterator<Item = usize> {
    (offset..offset + 0x20)
        .chain(offset + 0x130..offset + 0x150)
        .chain(offset + 0x1b0..offset + 0x1d0)
        .chain(offset + 0x1f0..offset + BLOCK)
}

#[test]
fn synthetic_mutations_never_panic() {
    let mut v = Volume::floppy(0);
    let root = v.root;
    v.file(root, b"a.exe", &small_hunk());
    let dir = v.dir(root, b"dir");
    v.file(dir, b"b.exe", &big_hunk());
    let mut image = v.finish();
    // The root, bitmap, file header, directory and first data blocks.
    let positions = (880 * BLOCK..890 * BLOCK).chain(0..1024);
    mutate(&mut image, positions, 307);
    let mut bootable = bootable_non_dos_floppy();
    mutate(&mut bootable, 0..1024, 101);
}
