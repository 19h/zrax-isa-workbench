//! FAT12, FAT16, FAT32 and exFAT volumes: mkfs.fat, mtools and exfatprogs
//! fixtures (long names, fragmented chains, deleted entries, `FSInfo`,
//! boot code, exFAT checksums), synthetic volumes built from the
//! Microsoft layouts for what the fixtures do not cover (FAT type
//! boundaries, BPB disagreements, long-name damage, loops and cross-links,
//! boot-code stubs, truncated dumps, limits), corrupted fields and
//! checksums, and truncation and mutation sweeps.

use std::borrow::Cow;
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::{Child, Classify, Container};
use zrax::formats::fat::{self, Layout};
use zrax::types::MetadataKey;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// A gzip-compressed fixture, decompressed.
fn gunzip(path: &str) -> Vec<u8> {
    compressed::decode(Codec::Gzip, &fixture(path))
        .expect("the fixture is a gzip stream")
        .data
}

/// The synthetic x86-64 ELF header the fixtures and synthetic volumes hold.
fn payload_elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

/// `frag/split.elf` as `generate.sh` writes it: `payload.elf`, then 60
/// lines `zrax split line NN`.
fn split_elf() -> Vec<u8> {
    let mut bytes = payload_elf();
    for i in 0..60 {
        bytes.extend(format!("zrax split line {i:02}\n").bytes());
    }
    bytes
}

/// `frag/split.elf` as `generate-exfat.sh` writes it: `payload.elf`, then
/// lines `zrax split line NNN`, cut to 6000 B.
fn exfat_split_elf() -> Vec<u8> {
    let mut bytes = payload_elf();
    for i in 0..300 {
        bytes.extend(format!("zrax split line {i:03}\n").bytes());
    }
    bytes.truncate(6000);
    bytes
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse a FAT12/16/32 volume that must be valid.
fn parse(image: &[u8]) -> Container<'_> {
    let layout = fat::detect_weak(image).expect("detected as FAT");
    fat::parse_container(image, layout).expect("parses")
}

/// Detect and parse an exFAT volume that must be valid.
fn parse_exfat(image: &[u8]) -> Container<'_> {
    assert_eq!(fat::detect(image), Some(Layout::ExFat));
    fat::parse_container(image, Layout::ExFat).expect("parses")
}

/// The error text of an exFAT volume that does not parse.
fn exfat_error(image: &[u8]) -> String {
    assert_eq!(
        fat::detect(image),
        Some(Layout::ExFat),
        "the name is the magic"
    );
    fat::parse_container(image, Layout::ExFat)
        .expect_err("does not parse")
        .to_string()
}

/// The error text of a FAT volume that is not detected, parsed as `layout`.
fn fat_error(image: &[u8], layout: Layout) -> String {
    assert_eq!(fat::detect_weak(image), None, "not detected");
    fat::parse_container(image, layout)
        .expect_err("does not parse")
        .to_string()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("{label} is listed: {:?}", labels(c)))
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
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

fn u8_of(value: usize) -> u8 {
    u8::try_from(value).expect("fits in 8 bits")
}

fn u16_of(value: usize) -> u16 {
    u16::try_from(value).expect("fits in 16 bits")
}

fn u32_of(value: usize) -> u32 {
    u32::try_from(value).expect("fits in 32 bits")
}

fn le_u16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(data[at..at + 2].try_into().expect("2 bytes"))
}

fn le_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn put_u16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// mkfs.fat and mtools fixtures (tests/fixtures/fat/README.md)
// ---------------------------------------------------------------------------

/// The three FAT fixtures, decompressed, with their layout and the offset
/// of their boot code (`BS_jmpBoot` targets the end of the boot sector
/// fields: 0x3E for FAT12/16, 0x5A for FAT32).
fn fat_fixtures() -> Vec<(&'static str, Vec<u8>, Layout, usize)> {
    vec![
        ("fat12.img", fixture("fat/fat12.img"), Layout::Fat12, 0x3e),
        ("fat16.img", gunzip("fat/fat16.img.gz"), Layout::Fat16, 0x3e),
        ("fat32.img", gunzip("fat/fat32.img.gz"), Layout::Fat32, 0x5a),
    ]
}

/// The recognized children of every FAT fixture: the root's files, then
/// each subdirectory's, in walk order, and the boot code last, so that the
/// files supply the primary ISA.
const FAT_CHILDREN: [&str; 5] = [
    "/PAYLOAD.ELF",
    "/Long File Name Payload.elf",
    "/BOOT/payload.elf.gz",
    "/FRAG/SPLIT.ELF",
    "Volume boot code",
];

#[test]
fn mkfs_fat_volumes_are_typed_by_their_cluster_count() {
    for (name, image, layout, _) in fat_fixtures() {
        assert_eq!(fat::detect_weak(&image), Some(layout), "{name}");
        assert_eq!(fat::detect(&image), None, "{name}: no exFAT name");
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::Fat, "{name}");
        assert_eq!(
            p.format.variant_name.as_deref(),
            Some(layout.label()),
            "{name}"
        );
        assert!(
            p.format.confidence < 1.0,
            "{name}: structure-only detection"
        );
    }
    let fat12 = fixture("fat/fat12.img");
    let c = parse(&fat12);
    assert!(
        has_note(
            &c,
            "FAT12 volume: 221 clusters of 512 B (the cluster count decides the FAT type); 512 \
             B sectors; 2 FATs of 1 sector; 512 root directory entries"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "The 2 FAT copies are identical"));
    assert_eq!(metadata(&c, "fat_cluster_count").as_deref(), Some("221"));
    assert_eq!(
        metadata(&c, "fat_volume_serial").as_deref(),
        Some("5A52-4146")
    );
    assert_eq!(
        metadata(&c, "fat_volume_label").as_deref(),
        Some("ZRAXFAT12")
    );
    assert_eq!(
        metadata(&c, "fat_directory_label").as_deref(),
        Some("ZRAXFAT12")
    );
    assert_eq!(metadata(&c, "fat_oem_name").as_deref(), Some("mkfs.fat"));
    assert_eq!(
        metadata(&c, "fat_media_descriptor").as_deref(),
        Some("0xF8")
    );
}

#[test]
fn members_are_listed_by_path_and_classified_on_their_own() {
    let elf = payload_elf();
    let gzip = fixture("compressed/payload.elf.gz");
    for (name, image, _, _) in fat_fixtures() {
        let c = parse(&image);
        assert_eq!(labels(&c), FAT_CHILDREN, "{name}");
        let (_, members) = c.children.split_last().expect("children");
        assert!(
            members
                .iter()
                .all(|member| member.classify == Classify::IfRecognized),
            "{name}"
        );
        // Contiguous members are stored as they are, at their file offset.
        for (label, bytes) in [
            ("/PAYLOAD.ELF", &elf),
            ("/Long File Name Payload.elf", &elf),
            ("/BOOT/payload.elf.gz", &gzip),
        ] {
            let member = child(&c, label);
            assert_eq!(member.transform, None, "{name} {label}");
            assert_eq!(
                &image[member.offset..member.offset + member.stored_size],
                &bytes[..],
                "{name} {label}"
            );
        }
        assert!(
            has_note(
                &c,
                "Directory walk: 3 directories, 6 regular files; members in a recognized \
                 format: 4"
            ),
            "{name}: {:?}",
            c.notes
        );
        assert!(has_note(&c, "1 deleted entry ignored"), "{name}");
        assert_eq!(
            metadata(&c, "fat_deleted_entry_count").as_deref(),
            Some("1")
        );

        let p = classify(&image);
        assert_eq!(p.slices.len(), 5, "{name}");
        let (_, members) = p.slices.split_last().expect("slices");
        assert!(members.iter().all(|s| s.isa == Isa::X86_64), "{name}");
    }
}

#[test]
fn fragmented_files_are_reassembled_from_their_chains() {
    let expected = split_elf();
    for (name, image, layout, _) in fat_fixtures() {
        let c = parse(&image);
        let split = child(&c, "/FRAG/SPLIT.ELF");
        assert_eq!(split.data.as_ref(), expected.as_slice(), "{name}");
        // The first stored run starts with the ELF header.
        assert_eq!(&image[split.offset..split.offset + 4], b"\x7fELF", "{name}");
        if layout == Layout::Fat32 {
            // mtools allocated it contiguously on the FAT32 volume.
            assert_eq!(split.transform, None, "{name}");
            continue;
        }
        assert_eq!(split.transform, Some("FAT cluster chain"), "{name}");
        assert_eq!(split.stored_size, 512, "{name}: the first cluster");
        let p = classify(&image);
        let slice = p
            .slices
            .iter()
            .find(|s| s.label.as_deref() == Some("/FRAG/SPLIT.ELF"))
            .expect("listed");
        let decoded = slice.decoded.as_ref().expect("decoded range");
        assert_eq!(decoded.transform, "FAT cluster chain");
        assert_eq!(decoded.size, expected.len() as u64);
    }
}

#[test]
fn the_boot_code_is_x86_real_mode_code() {
    for (name, image, _, code_start) in fat_fixtures() {
        let c = parse(&image);
        let boot = child(&c, "Volume boot code");
        assert_eq!(boot.offset, code_start, "{name}");
        assert_eq!(boot.data.as_ref(), &image[code_start..0x1fe], "{name}");
        assert_eq!(boot.classify, Classify::Code, "{name}");
        let target = boot.target.expect("x86 target");
        assert_eq!(
            (target.isa, target.bits, target.endianness),
            (Isa::X86, 16, Some(Endianness::Little)),
            "{name}"
        );
        let p = classify(&image);
        let boot = p.slices.last().expect("the boot code is the last slice");
        assert_eq!(boot.label.as_deref(), Some("Volume boot code"));
        assert_eq!((boot.isa, boot.bitwidth), (Isa::X86, 16), "{name}");
        // The files decide the primary ISA; the boot stub does not.
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth),
            (Isa::X86_64, 64),
            "{name}"
        );
        assert!(
            p.notes
                .iter()
                .any(|n| n.message.contains("Primary ISA selected from /PAYLOAD.ELF")),
            "{name}: {:?}",
            p.notes
        );
    }
}

#[test]
fn fat32_fsinfo_and_backup_boot_sector_are_checked() {
    let mut image = gunzip("fat/fat32.img.gz");
    let c = parse(&image);
    assert!(
        has_note(
            &c,
            "FSInfo sector 1: free cluster count 68517 and next free cluster 14 are hints, not \
             verified"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "The backup boot sector at sector 6 matches sector 0"
    ));
    assert_eq!(metadata(&c, "fat_root_cluster").as_deref(), Some("2"));
    assert_eq!(
        metadata(&c, "fat_fsinfo_free_count").as_deref(),
        Some("68517")
    );
    // A damaged FSInfo lead signature and backup boot sector.
    image[512] ^= 0xff;
    image[6 * 512 + 100] ^= 0xff;
    let c = parse(&image);
    assert!(has_note(
        &c,
        "FSInfo sector 1 has invalid signatures; not used"
    ));
    assert!(has_note(
        &c,
        "The backup boot sector at sector 6 differs from sector 0"
    ));
}

#[test]
fn gzip_wrapped_volumes_report_their_decoded_members() {
    let p = classify(&fixture("fat/fat16.img.gz"));
    assert_eq!(p.format.format, FileFormat::Gzip);
    let labels: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(labels, FAT_CHILDREN);
    assert!(p
        .slices
        .iter()
        .all(|s| s.decoded.as_ref().is_some_and(|d| d.transform == "gzip")));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message == "Decoded payload: FAT filesystem"));
}

// ---------------------------------------------------------------------------
// exFAT fixture (tests/fixtures/fat/README.md)
// ---------------------------------------------------------------------------

fn exfat_image() -> Vec<u8> {
    gunzip("fat/exfat.img.gz")
}

/// `BootChecksum` of [EXFAT] Figure 1 over the first 11 sectors of 512 B,
/// skipping `VolumeFlags` (106-107) and `PercentInUse` (112).
fn boot_checksum(sectors: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (i, &b) in sectors[..11 * 512].iter().enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        sum = (if sum & 1 != 0 { 0x8000_0000 } else { 0 }) + (sum >> 1) + u32::from(b);
    }
    sum
}

/// Rewrite the main boot checksum sector (sector 11) after an edit.
fn fix_boot_checksum(image: &mut [u8]) {
    let sum = boot_checksum(image);
    for at in (11 * 512..12 * 512).step_by(4) {
        put_u32(image, at, sum);
    }
}

/// `EntrySetChecksum` of [EXFAT] Figure 2 over `secondary_count + 1`
/// entries at `at`, skipping the `SetChecksum` field itself.
fn set_checksum(image: &[u8], at: usize, secondary_count: usize) -> u16 {
    let mut sum = 0u16;
    for (i, &b) in image[at..at + (secondary_count + 1) * 32]
        .iter()
        .enumerate()
    {
        if i == 2 || i == 3 {
            continue;
        }
        sum = (if sum & 1 != 0 { 0x8000 } else { 0 }) + (sum >> 1) + u16::from(b);
    }
    sum
}

/// Rewrite the `SetChecksum` of the File entry at `at` after an edit.
fn fix_set_checksum(image: &mut [u8], at: usize) {
    let count = usize::from(image[at + 1]);
    let sum = set_checksum(image, at, count);
    put_u16(image, at + 2, sum);
}

/// The File entry (type 0x85) of `name`: its first File Name entry (type
/// 0xC1, 15 UTF-16 characters from offset 2, zero-padded) follows the
/// File and Stream Extension entries.
fn file_entry(image: &[u8], name: &str) -> usize {
    let mut field: Vec<u8> = name
        .encode_utf16()
        .take(15)
        .flat_map(u16::to_le_bytes)
        .collect();
    field.resize(30, 0);
    let name_at = (0..image.len() - 32)
        .step_by(32)
        .find(|&at| image[at] == 0xc1 && image[at + 2..at + 32] == field[..])
        .unwrap_or_else(|| panic!("{name} has a File Name entry"));
    let file = name_at - 64;
    assert_eq!(image[file], 0x85, "{name}: File entry");
    file
}

/// File offset of exFAT cluster `cluster`: `ClusterHeapOffset` (88) in
/// sectors of `1 << BytesPerSectorShift` (108), clusters of
/// `1 << SectorsPerClusterShift` (109) sectors.
fn exfat_cluster(image: &[u8], cluster: u32) -> usize {
    let sector = 1usize << image[108];
    let cluster_size = sector << image[109];
    le_u32(image, 88) as usize * sector + (cluster as usize - 2) * cluster_size
}

const EXFAT_MEMBERS: [&str; 4] = [
    "/payload.elf",
    "/Long File Name Payload.elf",
    "/boot/payload.elf.gz",
    "/frag/split.elf",
];

#[test]
fn exfat_volumes_list_members_and_verify_checksums() {
    let image = exfat_image();
    let c = parse_exfat(&image);
    assert_eq!(labels(&c), EXFAT_MEMBERS);
    let split = child(&c, "/frag/split.elf");
    assert_eq!(split.transform, Some("exFAT cluster chain"));
    assert_eq!(split.data.as_ref(), exfat_split_elf().as_slice());
    assert_eq!(split.stored_size, 4096, "the first cluster");
    let elf = child(&c, "/payload.elf");
    assert_eq!(elf.transform, None);
    assert_eq!(
        &image[elf.offset..elf.offset + 256],
        payload_elf().as_slice()
    );
    for note in [
        "exFAT volume, revision 1.00: 508 clusters of 4 KiB; 512 B sectors; 1 FAT of 8 \
         sectors; root directory at cluster 5",
        "Main boot region checksum verified (sectors 0-10)",
        "Backup boot region checksum verified; it matches the main boot region",
        "No boot code: the boot code area is filled with 0x00",
        "Directory walk: 3 directories, 6 regular files; members in a recognized format: 4",
        "1 deleted entry ignored",
    ] {
        assert!(has_note(&c, note), "{note}: {:?}", c.notes);
    }
    assert!(c
        .notes
        .iter()
        .any(|n| n.starts_with("Up-case table checksum 0x") && n.ends_with(" verified")));
    assert_eq!(
        metadata(&c, "exfat_volume_label").as_deref(),
        Some("ZRAXEXFAT")
    );
    assert_eq!(metadata(&c, "exfat_cluster_count").as_deref(), Some("508"));

    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::ExFat);
    assert_eq!(p.format.variant_name.as_deref(), Some("exFAT"));
    assert!(p.format.confidence >= 1.0, "magic-bearing");
    assert_eq!(
        p.primary.isa,
        Isa::X86_64,
        "from /payload.elf; no boot code"
    );
    assert!(p.slices.iter().all(|s| s.isa == Isa::X86_64));
}

#[test]
fn exfat_boot_region_damage_is_a_parse_error() {
    let image = exfat_image();
    let mut serial = image.clone();
    serial[100] ^= 0xff;
    let message = exfat_error(&serial);
    assert!(
        message.starts_with("FAT filesystem parse error: Invalid main boot checksum 0x"),
        "{message}"
    );
    // VolumeFlags and PercentInUse are outside the checksum.
    let mut dirty = image.clone();
    dirty[106] |= 0x02;
    dirty[112] = 7;
    let c = parse_exfat(&dirty);
    assert!(has_note(&c, "VolumeFlags: the volume is marked dirty"));
    assert_eq!(metadata(&c, "exfat_percent_in_use").as_deref(), Some("7"));

    let cases: [(usize, u8, &str); 6] = [
        (1, 0x77, "Invalid JumpBoot EB 77 90: EB 76 90 expected"),
        (20, 0x01, "Invalid MustBeZero field: byte 0x14 is not 0"),
        (
            105,
            0x02,
            "Unsupported FileSystemRevision 2.00: major revision 1 expected",
        ),
        (108, 13, "Invalid BytesPerSectorShift 13: 9 to 12 expected"),
        (110, 3, "Invalid NumberOfFats 3: 1 or 2 expected"),
        (
            96,
            0,
            "Invalid FirstClusterOfRootDirectory 0: not a cluster of the heap",
        ),
    ];
    for (at, value, message) in cases {
        let mut corrupt = image.clone();
        corrupt[at] = value;
        fix_boot_checksum(&mut corrupt);
        assert_eq!(
            exfat_error(&corrupt),
            format!("FAT filesystem parse error: {message}")
        );
    }
    assert_eq!(
        exfat_error(&image[..4096]),
        "FAT filesystem parse error: Truncated main boot region: 6144 B needed, 4096 B present"
    );
    assert_eq!(
        exfat_error(&image[..1 << 20]),
        "FAT filesystem parse error: Truncated volume: 2097152 B declared, 1048576 B present"
    );
    // A dump that ends a few clusters early is still read, with a note.
    let c = parse_exfat(&image[..image.len() - 8192]);
    assert!(has_note(
        &c,
        "Truncated dump: the volume declares 2097152 B and the input ends 8192 B early"
    ));
}

#[test]
fn exfat_entry_sets_and_root_entries_are_checked() {
    let image = exfat_image();
    // A changed name without a matching SetChecksum skips the set.
    let elf = file_entry(&image, "payload.elf");
    let mut renamed = image.clone();
    renamed[elf + 64 + 2] = b'P';
    let c = parse_exfat(&renamed);
    assert!(!labels(&c).contains(&"/payload.elf".to_string()));
    assert!(
        has_note(
            &c,
            "1 directory entry set failed its SetChecksum and skipped"
        ),
        "{:?}",
        c.notes
    );
    fix_set_checksum(&mut renamed, elf);
    assert!(labels(&parse_exfat(&renamed)).contains(&"/Payload.elf".to_string()));

    // ValidDataLength (stream offset 8) below DataLength: the rest reads
    // as zeros.
    let mut short = image.clone();
    short[elf + 40..elf + 48].copy_from_slice(&128u64.to_le_bytes());
    fix_set_checksum(&mut short, elf);
    let c = parse_exfat(&short);
    let member = child(&c, "/payload.elf");
    assert_eq!(member.transform, Some("exFAT valid data length"));
    assert_eq!(&member.data[..128], &payload_elf()[..128]);
    assert!(member.data[128..].iter().all(|&b| b == 0));
    assert_eq!((member.data.len(), member.stored_size), (256, 128));

    // NameLength 15 leaves the second File Name entry as an extra
    // secondary; as an unknown critical type it makes the set unrecognized.
    let long = file_entry(&image, "Long File Name Payload.elf");
    let mut unknown = image.clone();
    unknown[long + 32 + 3] = 15;
    unknown[long + 96] = 0xc2;
    fix_set_checksum(&mut unknown, long);
    let c = parse_exfat(&unknown);
    assert!(
        has_note(
            &c,
            "1 directory entry set holds unrecognized critical entries and skipped"
        ),
        "{:?}",
        c.notes
    );
    // As a benign type (vendor extension) it is ignored.
    unknown[long + 96] = 0xe2;
    fix_set_checksum(&mut unknown, long);
    assert!(labels(&parse_exfat(&unknown)).contains(&"/Long File Name ".to_string()));

    // The root needs its up-case table; an unknown critical primary entry
    // invalidates the volume.
    let root = exfat_cluster(&image, le_u32(&image, 96));
    let upcase = (root..root + 4096)
        .step_by(32)
        .find(|&at| image[at] == 0x82)
        .expect("up-case table entry");
    let mut no_upcase = image.clone();
    no_upcase[upcase] = 0x02;
    assert_eq!(
        exfat_error(&no_upcase),
        "FAT filesystem parse error: Invalid root directory: 0 up-case table entries, 1 expected"
    );
    let mut unknown_primary = image.clone();
    unknown_primary[upcase] = 0x84;
    assert!(exfat_error(&unknown_primary).contains("critical primary entry 0x84"));
    let mut bad_table = image.clone();
    bad_table[upcase + 4] ^= 0xff;
    assert!(has_note(
        &parse_exfat(&bad_table),
        "does not match (computed 0x"
    ));

    // A critical primary entry other than File in a subdirectory
    // invalidates that directory only, including the sets before it: here
    // the deleted File entry after payload.elf.gz's set becomes an
    // allocation bitmap entry.
    let gz = file_entry(&image, "payload.elf.gz");
    assert_eq!(image[gz + 96], 0x05, "the deleted File entry");
    let mut bitmap_in_boot = image.clone();
    bitmap_in_boot[gz + 96] = 0x81;
    let c = parse_exfat(&bitmap_in_boot);
    assert_eq!(
        labels(&c),
        [
            "/payload.elf",
            "/Long File Name Payload.elf",
            "/frag/split.elf"
        ]
    );
    assert!(
        has_note(&c, "Skipped /boot: critical primary entry 0x81"),
        "{:?}",
        c.notes
    );
}

#[test]
fn exfat_boot_code_is_classified_when_present() {
    let mut image = exfat_image();
    image[120..120 + BOOT_CODE.len()].copy_from_slice(&BOOT_CODE);
    // Extended boot sector 1 with boot code for a processor the format does
    // not name.
    image[512..516].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    fix_boot_checksum(&mut image);
    let c = parse_exfat(&image);
    let boot = child(&c, "Volume boot code");
    assert_eq!(boot.offset, 0x78);
    assert_eq!(boot.target.map(|t| (t.isa, t.bits)), Some((Isa::X86, 16)));
    let extended = child(&c, "Extended boot sector 1");
    assert_eq!((extended.offset, extended.stored_size), (512, 508));
    assert_eq!(extended.target, None);
    assert_eq!(extended.classify, Classify::Code);
    // The HLT fill [EXFAT] 3.1.19 prescribes when there is no boot code.
    let mut halt = exfat_image();
    halt[120..510].fill(0xf4);
    fix_boot_checksum(&mut halt);
    assert!(has_note(
        &parse_exfat(&halt),
        "No boot code: the boot code area is filled with 0xF4"
    ));
}

// ---------------------------------------------------------------------------
// Synthetic volumes ([FATGEN] layouts)
// ---------------------------------------------------------------------------

/// Bytes per sector of every synthetic volume.
const SECTOR: usize = 512;

/// `BPB_Media` and the low byte of FAT[0].
const MEDIA: u8 = 0xf8;

/// `DIR_Attr` values.
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = 0x0f;

/// Real-mode boot code: `cli; xor ax, ax; mov ds, ax; mov ss, ax; mov sp,
/// 0x7C00; sti; mov ah, 0x0E; mov al, 'A'; int 0x10; hlt; jmp $-1`.
const BOOT_CODE: [u8; 20] = [
    0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xd0, 0xbc, 0x00, 0x7c, 0xfb, 0xb4, 0x0e, 0xb0, 0x41, 0xcd,
    0x10, 0xf4, 0xeb, 0xfd,
];

/// FAT entry widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bits {
    Fat12,
    Fat16,
    Fat32,
}

impl Bits {
    fn width(self) -> usize {
        match self {
            Bits::Fat12 => 12,
            Bits::Fat16 => 16,
            Bits::Fat32 => 32,
        }
    }

    /// The end-of-chain mark Microsoft drivers write.
    fn end(self) -> u32 {
        match self {
            Bits::Fat12 => 0x0fff,
            Bits::Fat16 => 0xffff,
            Bits::Fat32 => 0x0fff_ffff,
        }
    }

    fn fs_type(self) -> &'static [u8; 8] {
        match self {
            Bits::Fat12 => b"FAT12   ",
            Bits::Fat16 => b"FAT16   ",
            Bits::Fat32 => b"FAT32   ",
        }
    }
}

/// A directory of a synthetic volume: the root (the FAT12/FAT16 root
/// region, or cluster 2 on FAT32) or a chain of clusters, and the index of
/// its next free entry.
#[derive(Debug, Clone)]
struct Dir {
    is_root: bool,
    clusters: Vec<u32>,
    next: usize,
}

/// A FAT volume built from [FATGEN] "Boot Sector and BPB": 512-byte
/// sectors unless given, two FATs, 1 reserved sector and 512 root entries
/// for FAT12 and FAT16, 32 reserved sectors (`FSInfo` at 1, backup boot
/// sector at 6) and the root directory at cluster 2 for FAT32.
struct Volume {
    bits: Bits,
    image: Vec<u8>,
    sector_size: usize,
    sectors_per_cluster: usize,
    reserved: usize,
    fat_sectors: usize,
    root_entries: usize,
    clusters: u32,
    next_free: u32,
}

impl Volume {
    fn new(bits: Bits, clusters: u32) -> Self {
        Self::with_cluster_sectors(bits, clusters, 1)
    }

    fn with_cluster_sectors(bits: Bits, clusters: u32, sectors_per_cluster: usize) -> Self {
        Self::with_geometry(bits, clusters, SECTOR, sectors_per_cluster)
    }

    /// A volume of `clusters` clusters of `sectors_per_cluster` sectors of
    /// `sector_size` bytes.
    fn with_geometry(
        bits: Bits,
        clusters: u32,
        sector_size: usize,
        sectors_per_cluster: usize,
    ) -> Self {
        let (reserved, root_entries) = match bits {
            Bits::Fat32 => (32, 0),
            Bits::Fat12 | Bits::Fat16 => (1, 512),
        };
        let fat_bytes = (clusters as usize + 2) * bits.width() / 8 + 1;
        let fat_sectors = fat_bytes / sector_size + 1;
        let root_sectors = root_entries * 32 / sector_size;
        let total =
            reserved + 2 * fat_sectors + root_sectors + clusters as usize * sectors_per_cluster;
        let mut v = Self {
            bits,
            image: vec![0; total * sector_size],
            sector_size,
            sectors_per_cluster,
            reserved,
            fat_sectors,
            root_entries,
            clusters,
            next_free: 2,
        };
        v.boot_sector(total);
        v.set_fat(0, u32::from(MEDIA) | (bits.end() & !0xff));
        v.set_fat(1, bits.end());
        if bits == Bits::Fat32 {
            assert_eq!(v.allocate(1), [2], "the root directory");
        }
        v
    }

    /// Sector 0: `BS_jmpBoot` to the boot code, the BPB, the extended
    /// fields with `BS_BootSig` 0x29, boot code and the signature; for
    /// FAT32 also the `FSInfo` sector.
    fn boot_sector(&mut self, total: usize) {
        let fat32 = self.bits == Bits::Fat32;
        let code_start = if fat32 { 0x5a } else { 0x3e };
        let b = &mut self.image;
        b[0..3].copy_from_slice(&[0xeb, u8_of(code_start - 2), 0x90]);
        b[3..11].copy_from_slice(b"ZRAXTEST");
        put_u16(b, 11, u16_of(self.sector_size)); // BPB_BytsPerSec
        b[13] = u8_of(self.sectors_per_cluster); // BPB_SecPerClus
        put_u16(b, 14, u16_of(self.reserved)); // BPB_RsvdSecCnt
        b[16] = 2; // BPB_NumFATs
        put_u16(b, 17, u16_of(self.root_entries)); // BPB_RootEntCnt
        if total < 0x1_0000 && !fat32 {
            put_u16(b, 19, u16_of(total)); // BPB_TotSec16
        } else {
            put_u32(b, 32, u32_of(total)); // BPB_TotSec32
        }
        b[21] = MEDIA; // BPB_Media
        put_u16(b, 24, 32); // BPB_SecPerTrk
        put_u16(b, 26, 2); // BPB_NumHeads
        let extended = if fat32 {
            put_u32(b, 36, u32_of(self.fat_sectors)); // BPB_FATSz32
            put_u32(b, 44, 2); // BPB_RootClus
            put_u16(b, 48, 1); // BPB_FSInfo
            put_u16(b, 50, 6); // BPB_BkBootSec
            64
        } else {
            put_u16(b, 22, u16_of(self.fat_sectors)); // BPB_FATSz16
            36
        };
        b[extended] = 0x80; // BS_DrvNum
        b[extended + 2] = 0x29; // BS_BootSig
        put_u32(b, extended + 3, 0x1234_5678); // BS_VolID
        b[extended + 7..extended + 18].copy_from_slice(b"SYNTHETIC  "); // BS_VolLab
        b[extended + 18..extended + 26].copy_from_slice(self.bits.fs_type()); // BS_FilSysType
        b[code_start..code_start + BOOT_CODE.len()].copy_from_slice(&BOOT_CODE);
        b[510] = 0x55;
        b[511] = 0xaa;
        if fat32 {
            // FSInfo: lead, structure and trail signatures, unknown hints.
            let info = self.sector_size;
            put_u32(b, info, 0x4161_5252);
            put_u32(b, info + 484, 0x6141_7272);
            put_u32(b, info + 488, u32::MAX);
            put_u32(b, info + 492, u32::MAX);
            put_u32(b, info + 508, 0xaa55_0000);
        }
    }

    fn cluster_size(&self) -> usize {
        self.sectors_per_cluster * self.sector_size
    }

    fn fat_offset(&self, copy: usize) -> usize {
        (self.reserved + copy * self.fat_sectors) * self.sector_size
    }

    fn root_offset(&self) -> usize {
        self.fat_offset(2)
    }

    fn cluster_offset(&self, cluster: u32) -> usize {
        self.root_offset() + self.root_entries * 32 + (cluster as usize - 2) * self.cluster_size()
    }

    /// Write FAT entry `n` in both FATs. A FAT12 entry is 12 bits at
    /// `n + n / 2`: the low 12 bits of the word for even `n`, the high 12
    /// for odd `n`.
    fn set_fat(&mut self, n: u32, value: u32) {
        let n = n as usize;
        for copy in 0..2 {
            let fat = self.fat_offset(copy);
            match self.bits {
                Bits::Fat12 => {
                    let at = fat + n + n / 2;
                    let word = le_u16(&self.image, at);
                    let value = u16::try_from(value & 0x0fff).expect("12 bits");
                    let word = if n % 2 == 1 {
                        (word & 0x000f) | (value << 4)
                    } else {
                        (word & 0xf000) | value
                    };
                    put_u16(&mut self.image, at, word);
                }
                Bits::Fat16 => {
                    let value = u16::try_from(value & 0xffff).expect("16 bits");
                    put_u16(&mut self.image, fat + 2 * n, value);
                }
                Bits::Fat32 => put_u32(&mut self.image, fat + 4 * n, value),
            }
        }
    }

    /// Chain `clusters` in the FAT, ending with an end-of-chain mark.
    fn link(&mut self, clusters: &[u32]) {
        for pair in clusters.windows(2) {
            self.set_fat(pair[0], pair[1]);
        }
        if let Some(&last) = clusters.last() {
            self.set_fat(last, self.bits.end());
        }
    }

    /// Allocate and chain `count` contiguous clusters.
    fn allocate(&mut self, count: u32) -> Vec<u32> {
        assert!(
            self.next_free + count <= self.clusters + 2,
            "volume is full"
        );
        let clusters: Vec<u32> = (self.next_free..self.next_free + count).collect();
        self.next_free += count;
        self.link(&clusters);
        clusters
    }

    /// Write `bytes` across `clusters`, in order.
    fn write(&mut self, clusters: &[u32], bytes: &[u8]) {
        for (&cluster, part) in clusters.iter().zip(bytes.chunks(self.cluster_size())) {
            let at = self.cluster_offset(cluster);
            self.image[at..at + part.len()].copy_from_slice(part);
        }
    }

    fn root(&self) -> Dir {
        let clusters = if self.bits == Bits::Fat32 {
            vec![2]
        } else {
            Vec::new()
        };
        Dir {
            is_root: true,
            clusters,
            next: 0,
        }
    }

    /// Append a 32-byte entry to `dir`.
    fn put(&mut self, dir: &mut Dir, entry: &[u8; 32]) {
        let index = dir.next;
        dir.next += 1;
        let at = if dir.clusters.is_empty() {
            assert!(index < self.root_entries, "root directory is full");
            self.root_offset() + index * 32
        } else {
            let per_cluster = self.cluster_size() / 32;
            let cluster = dir.clusters[index / per_cluster];
            self.cluster_offset(cluster) + index % per_cluster * 32
        };
        self.image[at..at + 32].copy_from_slice(entry);
    }

    /// A regular file of `contents` in contiguous clusters, with long-name
    /// entries for `long_name` when given. Returns its clusters.
    fn file(
        &mut self,
        dir: &mut Dir,
        name: &[u8; 11],
        long_name: Option<&str>,
        contents: &[u8],
    ) -> Vec<u32> {
        let count = contents.len() / self.cluster_size()
            + usize::from(contents.len() % self.cluster_size() != 0);
        let clusters = self.allocate(u32_of(count));
        self.write(&clusters, contents);
        if let Some(long_name) = long_name {
            for entry in long_entries(long_name, checksum(name)) {
                self.put(dir, &entry);
            }
        }
        let first = clusters.first().copied().unwrap_or(0);
        let size = u32_of(contents.len());
        self.put(dir, &short_entry(name, ATTR_ARCHIVE, first, size));
        clusters
    }

    /// A subdirectory of `clusters` clusters with its dot and dotdot
    /// entries; dotdot holds 0 when the parent is the root.
    fn directory(&mut self, parent: &mut Dir, name: &[u8; 11], clusters: u32) -> Dir {
        let allocated = self.allocate(clusters);
        self.put(parent, &short_entry(name, ATTR_DIRECTORY, allocated[0], 0));
        let parent_cluster = if parent.is_root {
            0
        } else {
            parent.clusters[0]
        };
        let mut dir = Dir {
            is_root: false,
            clusters: allocated,
            next: 0,
        };
        let own = dir.clusters[0];
        self.put(
            &mut dir,
            &short_entry(b".          ", ATTR_DIRECTORY, own, 0),
        );
        self.put(
            &mut dir,
            &short_entry(b"..         ", ATTR_DIRECTORY, parent_cluster, 0),
        );
        dir
    }

    /// The image; FAT32 volumes get their backup boot sector.
    fn finish(mut self) -> Vec<u8> {
        if self.bits == Bits::Fat32 {
            let size = self.sector_size;
            let (boot, rest) = self.image.split_at_mut(size);
            rest[5 * size..6 * size].copy_from_slice(boot);
        }
        self.image
    }
}

/// A short directory entry: `DIR_Name` (0, 11), `DIR_Attr` (11),
/// `DIR_FstClusHI` (20), `DIR_FstClusLO` (26), `DIR_FileSize` (28).
fn short_entry(name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; 32] {
    let mut entry = [0u8; 32];
    entry[..11].copy_from_slice(name);
    entry[11] = attr;
    let [low_0, low_1, high_0, high_1] = cluster.to_le_bytes();
    entry[20..22].copy_from_slice(&[high_0, high_1]);
    entry[26..28].copy_from_slice(&[low_0, low_1]);
    put_u32(&mut entry, 28, size);
    entry
}

/// `ChkSum` of [FATGEN] "FAT Long Directory Entries".
fn checksum(name: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in name {
        sum = (if sum & 1 != 0 { 0x80 } else { 0 }) + (sum >> 1);
        sum = sum.wrapping_add(b);
    }
    sum
}

/// The long entries of `name` in stored order (the last part first):
/// `LDIR_Ord` (0, with 0x40 on the last part), `LDIR_Name1` (1, five
/// characters), `LDIR_Attr` (11), `LDIR_Chksum` (13), `LDIR_Name2` (14,
/// six), `LDIR_Name3` (28, two). The name ends with a NUL and 0xFFFF
/// padding unless it fills its entries.
fn long_entries(name: &str, checksum: u8) -> Vec<[u8; 32]> {
    const POSITIONS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut units: Vec<u16> = name.encode_utf16().collect();
    if units.len() % 13 != 0 {
        units.push(0);
        while units.len() % 13 != 0 {
            units.push(0xffff);
        }
    }
    let parts: Vec<&[u16]> = units.chunks(13).collect();
    (0..parts.len())
        .rev()
        .map(|i| {
            let mut entry = [0u8; 32];
            let last = if i + 1 == parts.len() { 0x40 } else { 0 };
            entry[0] = u8_of(i + 1) | last;
            entry[11] = ATTR_LONG_NAME;
            entry[13] = checksum;
            for (&unit, at) in parts[i].iter().zip(POSITIONS) {
                put_u16(&mut entry, at, unit);
            }
            entry
        })
        .collect()
}

/// A FAT12 volume of 64 clusters (99 sectors): `/A.ELF` (long name
/// `alpha.elf`, cluster 2), `/NOTES.TXT` (3), `/SUB` (4) and `/SUB/B.ELF`
/// (5).
fn synthetic_fat12() -> Vec<u8> {
    let mut v = Volume::new(Bits::Fat12, 64);
    let elf = payload_elf();
    let mut root = v.root();
    v.file(&mut root, b"A       ELF", Some("alpha.elf"), &elf);
    v.file(
        &mut root,
        b"NOTES   TXT",
        None,
        b"not a recognized format\n",
    );
    let mut sub = v.directory(&mut root, b"SUB        ", 1);
    v.file(&mut sub, b"B       ELF", None, &elf);
    v.finish()
}

#[test]
fn synthetic_volumes_of_each_type_list_their_members() {
    let elf = payload_elf();
    let cases = [
        (Bits::Fat12, 64, Layout::Fat12),
        (Bits::Fat16, 4200, Layout::Fat16),
        (Bits::Fat32, 65600, Layout::Fat32),
    ];
    for (bits, clusters, layout) in cases {
        let mut v = Volume::new(bits, clusters);
        let mut root = v.root();
        v.file(&mut root, b"A       ELF", Some("alpha.elf"), &elf);
        let mut sub = v.directory(&mut root, b"SUB        ", 1);
        v.file(&mut sub, b"B       ELF", None, &elf);
        let image = v.finish();
        assert_eq!(fat::detect_weak(&image), Some(layout), "{bits:?}");
        let c = parse(&image);
        assert_eq!(
            labels(&c),
            ["/alpha.elf", "/SUB/B.ELF", "Volume boot code"],
            "{bits:?}"
        );
        assert_eq!(child(&c, "/SUB/B.ELF").data.as_ref(), elf.as_slice());
        let p = classify(&image);
        assert_eq!(p.format.variant_name.as_deref(), Some(layout.label()));
    }
}

#[test]
fn larger_sectors_scale_every_region() {
    // FAT12 with 4 KiB sectors and clusters, and FAT16 with 1 KiB sectors
    // and 2 KiB clusters; a 5000 B file spans two clusters, reversed in the
    // FAT12 chain.
    let mut contents = payload_elf();
    contents.resize(5000, 0x5a);
    for (bits, clusters, sector_size, sectors_per_cluster, layout) in [
        (Bits::Fat12, 64, 4096, 1, Layout::Fat12),
        (Bits::Fat16, 4100, 1024, 2, Layout::Fat16),
    ] {
        let mut v = Volume::with_geometry(bits, clusters, sector_size, sectors_per_cluster);
        let mut root = v.root();
        let mut sub = v.directory(&mut root, b"SUB        ", 1);
        let parts = v.file(&mut sub, b"BIG     ELF", Some("big.elf"), &contents);
        if bits == Bits::Fat12 {
            // Store the second half first: clusters b, a in the heap order.
            let (first, second) = (parts[0], parts[1]);
            v.write(&[second, first], &contents);
            let entry_at = v.cluster_offset(sub.clusters[0]) + 3 * 32;
            put_u16(
                &mut v.image,
                entry_at + 26,
                u16::try_from(second).expect("small"),
            );
            v.link(&[second, first]);
        }
        let image = v.finish();
        assert_eq!(fat::detect_weak(&image), Some(layout), "{bits:?}");
        let c = parse(&image);
        assert_eq!(
            metadata(&c, "fat_bytes_per_sector"),
            Some(sector_size.to_string())
        );
        let big = child(&c, "/SUB/big.elf");
        assert_eq!(big.data.as_ref(), contents.as_slice(), "{bits:?}");
        let cluster_size = sector_size * sectors_per_cluster;
        if bits == Bits::Fat12 {
            assert_eq!(big.transform, Some("FAT cluster chain"));
            assert_eq!(big.stored_size, cluster_size);
        } else {
            assert_eq!(big.transform, None);
        }
    }
}

#[test]
fn the_cluster_count_alone_decides_the_type() {
    // 4084 clusters are FAT12 and 4085 FAT16, whatever BS_FilSysType says.
    let fat12 = Volume::new(Bits::Fat12, 4084).finish();
    assert_eq!(fat::detect_weak(&fat12), Some(Layout::Fat12));
    let mut fat16 = Volume::new(Bits::Fat16, 4085).finish();
    fat16[54..62].copy_from_slice(b"FAT12   ");
    assert_eq!(fat::detect_weak(&fat16), Some(Layout::Fat16));
    let c = parse(&fat16);
    assert!(
        has_note(
            &c,
            "BS_FilSysType \"FAT12\" does not name the FAT type; it is informational, and the \
             cluster count makes the volume FAT16"
        ),
        "{:?}",
        c.notes
    );
    assert_eq!(
        fat::parse_container(&fat16, Layout::Fat12)
            .expect_err("not FAT12")
            .to_string(),
        "FAT filesystem parse error: Invalid FAT type: the cluster count makes the volume \
         FAT16, not FAT12"
    );
    let fat16_max = Volume::new(Bits::Fat16, 65524).finish();
    assert_eq!(fat::detect_weak(&fat16_max), Some(Layout::Fat16));
    let fat32_min = Volume::new(Bits::Fat32, 65525).finish();
    assert_eq!(fat::detect_weak(&fat32_min), Some(Layout::Fat32));
}

#[test]
fn bpb_layouts_that_disagree_with_the_cluster_count_are_not_fat() {
    // FAT32 fields on a volume whose cluster count makes it FAT16, as
    // `mkfs.fat -F 32` writes on small volumes.
    let mut small = Volume::new(Bits::Fat32, 65525).finish();
    let total = le_u32(&small, 32);
    put_u32(&mut small, 32, total - 100);
    assert_eq!(
        fat_error(&small, Layout::Fat32),
        "FAT filesystem parse error: Invalid BPB: FAT32 fields (BPB_FATSz16 0) on a volume of \
         65425 clusters, which the cluster count makes FAT16"
    );
    // A FAT16 BPB on a volume of FAT32 size.
    let mut large = Volume::new(Bits::Fat16, 65524).finish();
    large.resize(large.len() + SECTOR, 0);
    let total = le_u32(&large, 32);
    put_u32(&mut large, 32, total + 1);
    assert_eq!(
        fat_error(&large, Layout::Fat16),
        "FAT filesystem parse error: Invalid BPB: 65525 clusters make the volume FAT32, but \
         BPB_FATSz16 is not 0"
    );
}

#[test]
fn inconsistent_boot_sectors_are_not_detected() {
    let image = synthetic_fat12();
    assert_eq!(fat::detect_weak(&image), Some(Layout::Fat12));
    let cases: [(usize, &[u8], &str); 10] = [
        (
            0,
            &[0x00],
            "Invalid BS_jmpBoot 00 3C 90: not an x86 short or near jump",
        ),
        (
            2,
            &[0x00],
            "Invalid BS_jmpBoot EB 3C 00: not an x86 short or near jump",
        ),
        (510, &[0x00], "Missing boot sector signature 55 AA at 0x1FE"),
        (
            11,
            &[0x00, 0x03],
            "Invalid BPB_BytsPerSec 768: 512, 1024, 2048 or 4096 expected",
        ),
        (13, &[3], "Invalid BPB_SecPerClus 3: not a power of two"),
        (14, &[0, 0], "Invalid BPB_RsvdSecCnt 0"),
        (16, &[0], "Invalid BPB_NumFATs 0"),
        (
            16,
            &[3],
            "Unsupported BPB_NumFATs 3: 1 or 2 FATs are accepted",
        ),
        (21, &[0xf7], "Invalid BPB_Media 0xF7"),
        (
            17,
            &[0, 0],
            "Invalid BPB_RootEntCnt 0: FAT12 needs a root directory region",
        ),
    ];
    for (at, bytes, message) in cases {
        let mut corrupt = image.clone();
        corrupt[at..at + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            fat_error(&corrupt, Layout::Fat12),
            format!("FAT filesystem parse error: {message}"),
            "offset {at}"
        );
    }
    let mut no_fat0 = image.clone();
    no_fat0[SECTOR] = 0x00;
    assert_eq!(
        fat_error(&no_fat0, Layout::Fat12),
        "FAT filesystem parse error: Invalid FAT[0] 0xF00: not a media descriptor with every \
         other bit set"
    );
    let mut no_total = image.clone();
    put_u16(&mut no_total, 19, 0);
    assert_eq!(
        fat_error(&no_total, Layout::Fat12),
        "FAT filesystem parse error: Invalid BPB_TotSec16 and BPB_TotSec32: both are 0"
    );
    let mut tiny = image.clone();
    put_u16(&mut tiny, 19, 20);
    assert!(fat_error(&tiny, Layout::Fat12).contains("leave no cluster"));
    let mut small_fat = image.clone();
    put_u16(&mut small_fat, 19, 4000);
    small_fat.resize(4000 * SECTOR, 0);
    assert!(fat_error(&small_fat, Layout::Fat12).contains("Invalid BPB_FATSz"));
    assert_eq!(
        fat_error(&image[..511], Layout::Fat12),
        "FAT filesystem parse error: Truncated boot sector: 511 B, 512 B needed"
    );
    assert_eq!(
        fat_error(&image[..1024], Layout::Fat12),
        "FAT filesystem parse error: Truncated volume: the reserved sectors, FATs and root \
         directory need 17920 B, 1024 B present"
    );
}

#[test]
fn fat32_fields_are_checked() {
    let image = Volume::new(Bits::Fat32, 65600).finish();
    let cases: [(usize, &[u8], &str); 4] = [
        (
            42,
            &[1, 0],
            "Unsupported BPB_FSVer 0.1: only version 0.0 is defined",
        ),
        (
            44,
            &[0, 0, 0, 0],
            "Invalid BPB_RootClus 0: not a cluster of the volume",
        ),
        (
            40,
            &[0x82, 0],
            "Invalid BPB_ExtFlags 0x0082: the active FAT index is 2, the volume has 2 FATs",
        ),
        (
            17,
            &[0, 2],
            "Invalid BPB_RootEntCnt 512: FAT32 has no fixed root directory",
        ),
    ];
    for (at, bytes, message) in cases {
        let mut corrupt = image.clone();
        corrupt[at..at + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            fat_error(&corrupt, Layout::Fat32),
            format!("FAT filesystem parse error: {message}"),
            "offset {at}"
        );
    }
    // Mirroring disabled with the second FAT active.
    let mut second = image.clone();
    second[40] = 0x81;
    let c = parse(&second);
    assert!(has_note(
        &c,
        "FAT mirroring is disabled (BPB_ExtFlags); FAT 2 is active"
    ));
}

#[test]
fn master_boot_records_are_not_fat_volumes() {
    // A DOS-style MBR: code, a partition table at 0x1BE and the signature.
    let mut mbr = vec![0u8; 64 << 10];
    mbr[..4].copy_from_slice(&[0x33, 0xc0, 0x8e, 0xd0]);
    mbr[0x1be] = 0x80;
    mbr[0x1c2] = 0x0c;
    put_u32(&mut mbr, 0x1c6, 1);
    put_u32(&mut mbr, 0x1ca, 127);
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    assert_eq!(fat::detect_weak(&mbr), None);
    // A GRUB-style MBR jumps over a zero BPB area.
    mbr[..3].copy_from_slice(&[0xeb, 0x63, 0x90]);
    assert_eq!(fat::detect_weak(&mbr), None);
    // A FAT volume whose boot sector also holds a partition table, as
    // `mkfs.fat --mbr` writes it, is still FAT.
    let mut volume = synthetic_fat12();
    volume[0x1be] = 0x80;
    volume[0x1c2] = 0x01;
    put_u32(&mut volume, 0x1c6, 0);
    put_u32(&mut volume, 0x1ca, 99);
    assert_eq!(fat::detect_weak(&volume), Some(Layout::Fat12));
}

#[test]
fn long_names_need_a_matching_checksum_and_sequence() {
    let mut v = Volume::new(Bits::Fat12, 64);
    let elf = payload_elf();
    let mut root = v.root();
    v.file(
        &mut root,
        b"GOOD    ELF",
        Some("A long and valid name.elf"),
        &elf,
    );
    // A long name whose checksum belongs to another short name.
    for entry in long_entries("mismatched.elf", checksum(b"OTHER   ELF")) {
        v.put(&mut root, &entry);
    }
    v.file(&mut root, b"MISMAT~1ELF", None, &elf);
    // A set whose last entry (stored first) is missing: an orphan.
    let parts = long_entries("orphaned long name.elf", checksum(b"ORPHAN~1ELF"));
    v.put(&mut root, &parts[1]);
    v.file(&mut root, b"ORPHAN~1ELF", None, &elf);
    // A long name with a character long names may not hold.
    v.file(&mut root, b"SLASH   ELF", Some("a/b.elf"), &elf);
    // A deleted long name before a deleted short entry.
    let mut deleted = long_entries("deleted.elf", checksum(b"DELETED ELF"));
    deleted[0][0] = 0xe5;
    v.put(&mut root, &deleted[0]);
    let mut gone = short_entry(b"DELETED ELF", ATTR_ARCHIVE, 0, 0);
    gone[0] = 0xe5;
    v.put(&mut root, &gone);
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/A long and valid name.elf",
            "/MISMAT~1.ELF",
            "/ORPHAN~1.ELF",
            "/SLASH.ELF",
            "Volume boot code"
        ]
    );
    assert!(
        has_note(&c, "3 long-name entry sets were not used"),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "1 deleted entry ignored"));
}

#[test]
fn labels_dot_entries_and_invalid_entries() {
    let mut v = Volume::new(Bits::Fat16, 4200);
    let elf = payload_elf();
    let mut root = v.root();
    let label = short_entry(b"MY VOLUME  ", ATTR_VOLUME_ID | ATTR_ARCHIVE, 0, 0);
    v.put(&mut root, &label);
    let mut sub = v.directory(&mut root, b"SUB        ", 1);
    for (name, attr) in [
        (b"LABEL      ", ATTR_VOLUME_ID),
        (b"BOTH       ", ATTR_VOLUME_ID | ATTR_DIRECTORY),
        (b"BAD*NAMEELF", ATTR_ARCHIVE),
        (b" LEADINGELF", ATTR_ARCHIVE),
    ] {
        v.put(&mut sub, &short_entry(name, attr, 0, 0));
    }
    v.file(&mut sub, b"\x05KANJI  ELF", None, &elf);
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/SUB/_KANJI.ELF", "Volume boot code"]);
    assert_eq!(
        metadata(&c, "fat_directory_label").as_deref(),
        Some("MY VOLUME")
    );
    assert!(
        has_note(&c, "4 invalid directory entries skipped"),
        "{:?}",
        c.notes
    );
}

#[test]
fn loops_cross_links_and_broken_chains_are_skipped_with_notes() {
    let mut v = Volume::new(Bits::Fat12, 64);
    let elf = payload_elf();
    let three_clusters = [elf.as_slice(), &[0; 1024]].concat();
    let mut root = v.root();
    let mut sub = v.directory(&mut root, b"SUB        ", 1);
    // A subdirectory entry pointing back at its own directory: a loop.
    let own = sub.clusters[0];
    v.put(
        &mut sub,
        &short_entry(b"LOOP       ", ATTR_DIRECTORY, own, 0),
    );
    // A second entry for the same directory: a cross-link.
    v.put(
        &mut root,
        &short_entry(b"SUBAGAIN   ", ATTR_DIRECTORY, own, 0),
    );
    // A file whose chain loops: three clusters needed, the chain is
    // a -> b -> a.
    let looped = v.file(&mut root, b"LOOPED  ELF", None, &three_clusters);
    v.set_fat(looped[1], looped[0]);
    // A file whose chain ends early, and one that reaches a free cluster.
    let short = v.file(&mut root, b"SHORT   ELF", None, &three_clusters);
    v.set_fat(short[1], 0xfff);
    let free = v.file(&mut root, b"FREE    ELF", None, &three_clusters);
    v.set_fat(free[0], 0);
    // A file whose chain is longer than its size needs.
    let long = v.file(&mut root, b"LONG    ELF", None, &elf);
    let extra = v.allocate(1);
    v.set_fat(long[0], extra[0]);
    // A file that starts outside the heap.
    v.put(
        &mut root,
        &short_entry(b"OUTSIDE ELF", ATTR_ARCHIVE, 4000, 256),
    );
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/LONG.ELF", "Volume boot code"]);
    for note in [
        "Skipped /SUB/LOOP: cluster 2 is already part of another directory (a loop or a \
         cross-link)",
        "Skipped /SUBAGAIN: cluster 2 is already part of another directory",
        &format!(
            "Skipped /LOOPED.ELF: the cluster chain loops back from cluster {} to {}",
            looped[1], looped[0]
        ),
        "Skipped /SHORT.ELF: the cluster chain ends after 2 clusters; 1280 B need 3",
        &format!(
            "Skipped /FREE.ELF: cluster {} links to a free cluster",
            free[0]
        ),
        "1 member's cluster chain is longer than the file size needs",
        "Skipped /OUTSIDE.ELF: first cluster 4000 is not in the cluster heap",
    ] {
        assert!(has_note(&c, note), "{note}: {:?}", c.notes);
    }
}

#[test]
fn deep_trees_and_large_files_are_bounded() {
    let mut v = Volume::new(Bits::Fat12, 200);
    let elf = payload_elf();
    let mut root = v.root();
    // A recognized file of eight clusters whose size field says 65 MiB,
    // more than the 64 MiB extraction limit.
    let mut prefix = elf.clone();
    prefix.resize(4096, 0);
    v.file(&mut root, b"HUGE    ELF", None, &prefix);
    let size_field = v.root_offset() + 28;
    put_u32(&mut v.image, size_field, 65 << 20);
    let mut parent = root;
    let mut shallow = String::new();
    for level in 0..70 {
        let name: [u8; 11] = format!("D{level:<10}")
            .as_bytes()
            .try_into()
            .expect("11 bytes");
        let mut directory = v.directory(&mut parent, &name, 1);
        if level < 64 {
            shallow.push_str(&format!("/D{level}"));
        }
        if level == 63 {
            v.file(&mut directory, b"SHALLOW ELF", None, &elf);
        }
        parent = directory;
    }
    v.file(&mut parent, b"DEEP    ELF", None, &elf);
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            format!("{shallow}/SHALLOW.ELF"),
            "Volume boot code".to_string()
        ]
    );
    assert!(
        has_note(&c, "1 directory deeper than 64 levels was not walked"),
        "{:?}",
        c.notes
    );
    assert!(
        has_note(
            &c,
            "1 recognized file exceeds the 64 MiB extraction limit; not extracted"
        ),
        "{:?}",
        c.notes
    );
}

#[test]
fn the_total_extraction_limit_stops_extraction() {
    // Five 60 MiB files sharing one chain of 64 KiB clusters: four fit in
    // the 256 MiB limit.
    let mut v = Volume::with_cluster_sectors(Bits::Fat12, 1000, 128);
    let mut root = v.root();
    let size = 60 << 20;
    let mut contents = vec![0u8; size];
    contents[..256].copy_from_slice(&payload_elf());
    let clusters = v.file(&mut root, b"PART0   ELF", None, &contents);
    for i in 1..5 {
        let mut name = *b"PART0   ELF";
        name[4] = b'0' + i;
        let entry = short_entry(&name, ATTR_ARCHIVE, clusters[0], u32_of(size));
        v.put(&mut root, &entry);
    }
    let image = v.finish();
    let c = parse(&image);
    assert_eq!(c.children.len(), 1 + 4);
    let (_, members) = c.children.split_last().expect("children");
    assert!(members.iter().all(|member| member.data.len() == size));
    assert!(
        has_note(
            &c,
            "1 recognized file was not extracted: the 256 MiB total extraction limit was \
             reached"
        ),
        "{:?}",
        c.notes
    );
}

#[test]
fn boot_code_stubs_are_not_classified() {
    let image = synthetic_fat12();
    let mut zeros = image.clone();
    zeros[0x3e..0x1fe].fill(0);
    let c = parse(&zeros);
    assert!(!labels(&c).contains(&"Volume boot code".to_string()));
    assert!(has_note(
        &c,
        "No boot code: the boot code area is filled with 0x00"
    ));
    let mut idle = image.clone();
    idle[0x3e..0x41].copy_from_slice(&[0xf4, 0xeb, 0xfd]);
    assert!(has_note(
        &parse(&idle),
        "No boot code: the code at 0x3E is an idle loop"
    ));
    let mut to_self = image.clone();
    to_self[..3].copy_from_slice(&[0xeb, 0xfe, 0x90]);
    assert!(has_note(
        &parse(&to_self),
        "No boot code: the jump field leads into the boot parameters (0x0)"
    ));
    // A near jump to code at 0x100.
    let mut near = image.clone();
    near[..3].copy_from_slice(&[0xe9, 0xfd, 0x00]);
    near[0x100..0x100 + BOOT_CODE.len()].copy_from_slice(&BOOT_CODE);
    let c = parse(&near);
    let boot = child(&c, "Volume boot code");
    assert_eq!((boot.offset, boot.stored_size), (0x100, 0xfe));
    // Without boot code the primary ISA comes from the first member.
    let p = classify(&zeros);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("Primary ISA selected from /alpha.elf")));
}

#[test]
fn truncated_dumps_and_trailing_data_are_noted() {
    let image = synthetic_fat12();
    assert_eq!(image.len(), 99 * SECTOR);
    // The last two sectors (clusters 64 and 65) are missing.
    let truncated = &image[..image.len() - 2 * SECTOR];
    let c = parse(truncated);
    assert!(
        has_note(
            &c,
            "Truncated dump: the volume declares 50688 B and the input ends 1024 B early"
        ),
        "{:?}",
        c.notes
    );
    assert_eq!(c.consumed, truncated.len());
    assert_eq!(labels(&c).len(), 3, "the members are all before the cut");
    // More than an eighth of the volume missing is not FAT.
    assert_eq!(fat::detect_weak(&image[..image.len() - 13 * SECTOR]), None);

    let mut padded = image.clone();
    padded.extend_from_slice(&[0xff; SECTOR]);
    let c = parse(&padded);
    assert!(has_note(&c, "512 B after the volume at 0xC600 are padding"));
    assert_eq!(c.consumed, image.len());
    let mut trailing = image.clone();
    trailing.extend_from_slice(b"trailing data");
    assert!(has_note(
        &parse(&trailing),
        "13 B after the volume at 0xC600 are data that is not part of the volume"
    ));

    // A member whose cluster lies past the end of a truncated dump.
    let mut v = Volume::new(Bits::Fat12, 64);
    let mut root = v.root();
    v.next_free = 63;
    v.file(&mut root, b"LAST    ELF", None, &payload_elf());
    let image = v.finish();
    let c = parse(&image[..image.len() - 3 * SECTOR]);
    assert!(
        has_note(
            &c,
            "Skipped /LAST.ELF: cluster 63 at 0xC000 lies beyond the end of the input"
        ),
        "{:?}",
        c.notes
    );
}

#[test]
fn fat_copies_and_reserved_entries_are_reported() {
    let mut v = Volume::new(Bits::Fat16, 4200);
    let mut root = v.root();
    v.file(&mut root, b"A       ELF", None, &payload_elf());
    // FAT[1] without the clean-shutdown bit (0x8000).
    v.set_fat(1, 0x7fff);
    let second_fat = v.fat_offset(1);
    let mut image = v.finish();
    // The second FAT differs in an unused entry; FAT[0] in both names
    // media 0xF0 while BPB_Media is 0xF8.
    image[second_fat + 100] = 0x12;
    image[SECTOR] = 0xf0;
    image[second_fat] = 0xf0;
    let c = parse(&image);
    for note in [
        "FAT copy 2 differs from FAT 1, which is used",
        "FAT[0] holds media descriptor 0xF0, BPB_Media is 0xF8; FAT[1] marks the volume dirty \
         (not cleanly unmounted)",
    ] {
        assert!(has_note(&c, note), "{note}: {:?}", c.notes);
    }
}

// ---------------------------------------------------------------------------
// Truncation and mutation sweeps
// ---------------------------------------------------------------------------

/// Every member of a parse of a prefix is the same as in the whole image,
/// and its stored bytes lie inside the prefix: a prefix never claims
/// missing bytes.
fn assert_prefix_claims_nothing_missing(
    name: &str,
    whole: &Container<'_>,
    prefix: &Container<'_>,
    end: usize,
) {
    for member in &prefix.children {
        let full = whole
            .children
            .iter()
            .find(|c| c.label == member.label)
            .unwrap_or_else(|| panic!("{name}: prefix {end} lists {}", member.label));
        assert_eq!(
            member.data, full.data,
            "{name}: prefix {end} {}",
            member.label
        );
        assert!(
            member.offset + member.stored_size <= end,
            "{name}: prefix {end} {}",
            member.label
        );
        if let Cow::Borrowed(bytes) = member.data {
            assert!(member.offset + bytes.len() <= end, "{name}: prefix {end}");
        }
    }
}

#[test]
fn prefixes_never_claim_missing_bytes() {
    let image = fixture("fat/fat12.img");
    let whole = parse(&image);
    for end in 0..image.len() {
        let prefix = &image[..end];
        let Some(layout) = fat::detect_weak(prefix) else {
            continue;
        };
        let c = fat::parse_container(prefix, layout).expect("a detected prefix parses");
        assert!(
            end >= image.len() - image.len() / 8,
            "fat12.img: prefix {end} is FAT"
        );
        assert_prefix_claims_nothing_missing("fat12.img", &whole, &c, end);
    }
    let images = [
        ("fat16.img", gunzip("fat/fat16.img.gz")),
        ("exfat.img", exfat_image()),
    ];
    for (name, image) in images {
        let detect = |data: &[u8]| fat::detect(data).or_else(|| fat::detect_weak(data));
        let layout = detect(&image).expect("detected");
        let whole = fat::parse_container(&image, layout).expect("parses");
        for end in (0..image.len()).step_by(4093) {
            let prefix = &image[..end];
            if let Some(Ok(c)) = detect(prefix).map(|layout| fat::parse_container(prefix, layout)) {
                assert_prefix_claims_nothing_missing(name, &whole, &c, end);
            }
            if end % (4093 * 16) == 0 {
                let _ = detect_payload(prefix, &ClassifierOptions::new());
            }
        }
    }
}

/// Parse `image` with each of 0x00, 0xFF and a bit flip at each of
/// `positions`, and classify every `classify_every`th, restoring the byte
/// afterwards.
fn mutate(image: &mut [u8], positions: impl Iterator<Item = usize>, classify_every: usize) {
    for (n, at) in positions.enumerate() {
        let original = image[at];
        for value in [0x00, 0xff, original ^ 0x01] {
            image[at] = value;
            if let Some(layout) = fat::detect(image).or_else(|| fat::detect_weak(image)) {
                let _ = fat::parse_container(image, layout);
            }
            if n % classify_every == 0 {
                let _ = detect_payload(image, &ClassifierOptions::new());
            }
        }
        image[at] = original;
    }
}

#[test]
fn fixture_mutations_never_panic() {
    // FAT12: the boot sector, both FATs, the root directory and the first
    // data clusters, then every 97th byte.
    let mut image = fixture("fat/fat12.img");
    let positions = (0..0x5800).chain((0x5800..image.len()).step_by(97));
    mutate(&mut image, positions, 61);
    // FAT16: the boot sector, the start of both FATs, the root directory
    // and the first data clusters, and every 4099th byte.
    let mut fat16 = gunzip("fat/fat16.img.gz");
    let positions = (0..0x300)
        .chain(0x2600..0x2700)
        .chain(0x4a00..0x4c00)
        .chain(0x8a00..0x9c00)
        .chain((0..fat16.len()).step_by(4099));
    mutate(&mut fat16, positions, 127);
    // FAT32: the boot and FSInfo sectors, the backup boot sector, the start
    // of both FATs, the root directory and the first data clusters, and
    // every 65537th byte.
    let mut fat32 = gunzip("fat/fat32.img.gz");
    let positions = (0..0x400)
        .chain(0xc00..0xe00)
        .chain(0x4000..0x4100)
        .chain(0x47000..0x47100)
        .chain(0x8a000..0x8b600)
        .chain((0..fat32.len()).step_by(65_537));
    mutate(&mut fat32, positions, 997);
    // exFAT: the main boot sector, the FAT, the root directory and both
    // subdirectories, and every 1009th byte.
    let mut exfat = exfat_image();
    let positions = (0..0x200)
        .chain(0x3000..0x3100)
        .chain(0x7000..0x7300)
        .chain(0xb000..0xb100)
        .chain(0xd000..0xd100)
        .chain((0..exfat.len()).step_by(1009));
    mutate(&mut exfat, positions, 89);
}

#[test]
fn synthetic_mutations_never_panic() {
    let mut image = synthetic_fat12();
    // Everything up to the end of /SUB/B.ELF (cluster 5).
    let used = 0x4600 + 4 * SECTOR;
    mutate(&mut image, 0..used, 41);
    for end in (0..image.len()).step_by(257) {
        let _ = detect_payload(&image[..end], &ClassifierOptions::new());
    }
}
