//! NTFS volumes: three ntfs-3g fixtures (512 B sectors with 4 KiB clusters,
//! 4 KiB sectors, 512 B clusters; resident, fragmented, sparse, LZNT1 and
//! attribute-list files, named streams, hard and symbolic links), synthetic
//! volumes built from the documented layout for what the fixtures do not
//! cover ($DATA extents in extension records, a fragmented $MFT with its own
//! attribute list, records split across runs, orphans and cycles, encrypted,
//! WOF and unsupported compressed files, damaged records), corrupted
//! fields, and truncation and mutation sweeps.

#[path = "support/truncated_volume.rs"]
mod truncated_volume;

use std::borrow::Cow;
use truncated_volume::{assert_members_inside, prefix_ends};
use zrax::formats::container::{Child, Container};
use zrax::formats::ntfs::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// The contents of a gzip file written by `gzip -n` (RFC 1952): a 10-byte
/// header without optional fields, a DEFLATE stream and an 8-byte trailer.
fn gunzip(file: &[u8]) -> Vec<u8> {
    assert_eq!(&file[..4], &[0x1f, 0x8b, 8, 0], "gzip -n header");
    miniz_oxide::inflate::decompress_to_vec(&file[10..file.len() - 8]).expect("inflates")
}

fn ntfs_img() -> Vec<u8> {
    gunzip(&fixture("ntfs/ntfs.img.gz"))
}

fn ntfs_4k_img() -> Vec<u8> {
    gunzip(&fixture("ntfs/ntfs-4k.img.gz"))
}

fn ntfs_512_img() -> Vec<u8> {
    gunzip(&fixture("ntfs/ntfs-512.img.gz"))
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse a volume that must be valid.
fn parse(image: &[u8]) -> Container<'_> {
    let layout = ntfs::detect(image).expect("detected as NTFS");
    ntfs::parse_container(image, layout).expect("parses")
}

/// The error text of a volume that is detected but does not parse.
fn parse_error(image: &[u8]) -> String {
    let layout = ntfs::detect(image).expect("detected as NTFS");
    ntfs::parse_container(image, layout)
        .expect_err("does not parse")
        .to_string()
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

fn metadata(c: &Container<'_>, key: &str) -> String {
    c.metadata
        .iter()
        .find(|entry| matches!(&entry.key, zrax::MetadataKey::Custom(k) if k == key))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
        .to_string()
}

fn le16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(data[at..at + 2].try_into().expect("2 bytes"))
}

fn le64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// UTF-16LE code units of `text`.
fn units(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// `n` rounded up to a multiple of 8.
fn align8(n: usize) -> usize {
    (n + 7) & !7
}

// ---------------------------------------------------------------------------
// Fixture members (tests/fixtures/ntfs/README.md)
// ---------------------------------------------------------------------------

/// `head`, followed by `text` repeated, cut to `size` bytes, as
/// `generate.sh` builds its members with `pad`.
fn padded(head: &[u8], size: usize, text: &[u8]) -> Vec<u8> {
    let mut body = head.to_vec();
    while body.len() < size {
        body.extend_from_slice(text);
    }
    body.truncate(size);
    body
}

/// `text` repeated without newlines, cut to `size` bytes.
fn repeated(size: usize, text: &[u8]) -> Vec<u8> {
    padded(b"", size, text)
}

fn payload_elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

/// The PE32+ image of `pe32-sections.bin` after its 4-byte section header.
fn pe_image() -> Vec<u8> {
    fixture("uefi/pe32-sections.bin")[4..432].to_vec()
}

fn app_exe() -> Vec<u8> {
    padded(&pe_image(), 12288, b"zrax synthetic PE overlay ")
}

fn kernel_macho() -> Vec<u8> {
    fixture("apple/kernel.macho")
}

fn zrax_macho() -> Vec<u8> {
    padded(
        &kernel_macho(),
        102_400,
        b"zrax synthetic compressed member ",
    )
}

fn fragmented_elf() -> Vec<u8> {
    padded(&payload_elf(), 40960, b"zrax synthetic fragmented member ")
}

/// The ELF header, a hole to 128 KiB, then 4 KiB of text.
fn sparse_elf() -> Vec<u8> {
    let mut body = payload_elf();
    body.resize(131_072, 0);
    body.extend_from_slice(&repeated(4096, b"zrax synthetic sparse tail "));
    body
}

/// The 200-character name of `linked.exe`'s first hard link.
fn long_link(i: usize) -> String {
    format!("{}{i}", "L".repeat(200))
}

/// The recognized members of `ntfs.img`, in MFT record order, and the ISA
/// each classifies as.
fn ntfs_members() -> Vec<(String, Isa)> {
    let linked = format!("/bin/{}", long_link(1));
    vec![
        ("/payload.elf".to_string(), Isa::X86_64),
        ("/Program Files/Zrax/app.exe".to_string(), Isa::X86_64),
        ("/notes.txt:payload.macho".to_string(), Isa::AArch64),
        ("/compressed/zrax.macho".to_string(), Isa::AArch64),
        ("/sparse.elf".to_string(), Isa::X86_64),
        ("/bin/fragmented.elf".to_string(), Isa::X86_64),
        (linked.clone(), Isa::X86_64),
        (format!("{linked}:payload.elf"), Isa::X86_64),
    ]
}

/// The bytes each member of `ntfs.img` holds.
fn ntfs_member_bytes(label: &str) -> Vec<u8> {
    match label {
        "/payload.elf" => payload_elf(),
        "/Program Files/Zrax/app.exe" => app_exe(),
        "/notes.txt:payload.macho" => kernel_macho(),
        "/compressed/zrax.macho" => zrax_macho(),
        "/sparse.elf" => sparse_elf(),
        "/bin/fragmented.elf" => fragmented_elf(),
        label if label.ends_with(":payload.elf") => payload_elf(),
        label if label.starts_with("/bin/L") => app_exe(),
        other => panic!("unexpected member {other}"),
    }
}

// ---------------------------------------------------------------------------
// ntfs-3g fixtures
// ---------------------------------------------------------------------------

#[test]
fn ntfs_3g_volumes_are_detected_by_the_boot_sector_and_described() {
    for (name, image) in [
        ("ntfs.img", ntfs_img()),
        ("ntfs-4k.img", ntfs_4k_img()),
        ("ntfs-512.img", ntfs_512_img()),
    ] {
        assert_eq!(ntfs::detect(&image), Some(Layout::Ntfs), "{name}");
        let c = parse(&image);
        assert_eq!(c.format, FileFormat::Ntfs, "{name}");
        assert_eq!(c.variant, "NTFS", "{name}");
        assert!(c.target.is_none(), "{name}: the volume names no processor");
        assert_eq!(
            c.consumed,
            image.len(),
            "{name}: the backup boot sector belongs to it"
        );
        assert!(has_note(&c, "NTFS 3.1 volume"), "{name}: {:?}", c.notes);
        assert!(
            has_note(&c, "matches the boot sector"),
            "{name}: {:?}",
            c.notes
        );
        assert!(
            has_note(&c, "matches the first 4 MFT records"),
            "{name}: {:?}",
            c.notes
        );
        assert_eq!(metadata(&c, "ntfs_version"), "3.1", "{name}");
    }
    let image = ntfs_img();
    let c = parse(&image);
    assert_eq!(metadata(&c, "ntfs_volume_name"), "ZRAX");
    assert_eq!(metadata(&c, "ntfs_cluster_size"), "4096");
    assert_eq!(metadata(&c, "ntfs_mft_record_size"), "1024");
    assert_eq!(metadata(&c, "ntfs_total_sectors"), "8191");
    assert_eq!(metadata(&c, "ntfs_mft_cluster"), "4");
    assert!(metadata(&c, "ntfs_serial_number").starts_with("0x"));
    let image = ntfs_4k_img();
    let c = parse(&image);
    assert_eq!(metadata(&c, "ntfs_volume_name"), "ZRAX4K");
    assert_eq!(metadata(&c, "ntfs_bytes_per_sector"), "4096");
    assert_eq!(metadata(&c, "ntfs_mft_record_size"), "4096");
    let image = ntfs_512_img();
    let c = parse(&image);
    assert_eq!(metadata(&c, "ntfs_volume_name"), "ZRAX512");
    assert_eq!(metadata(&c, "ntfs_cluster_size"), "512");
}

#[test]
fn recognized_files_and_streams_are_listed_by_path_and_classified_on_their_own() {
    let image = ntfs_img();
    let c = parse(&image);
    let expected = ntfs_members();
    let expected_labels: Vec<String> = expected.iter().map(|(label, _)| label.clone()).collect();
    assert_eq!(labels(&c), expected_labels);
    let payload = classify(&image);
    assert_eq!(payload.format.format, FileFormat::Ntfs);
    assert_eq!(payload.format.variant_name.as_deref(), Some("NTFS"));
    assert_eq!(payload.primary.isa, Isa::X86_64, "the first member decides");
    assert!(
        payload
            .notes
            .iter()
            .any(|n| n.message.contains("Primary ISA selected from /payload.elf")),
        "{:?}",
        payload.notes
    );
    for (label, isa) in &expected {
        let slice = payload
            .slices
            .iter()
            .find(|slice| slice.label.as_deref() == Some(label.as_str()))
            .unwrap_or_else(|| panic!("{label} is a slice"));
        assert_eq!(slice.isa, *isa, "{label}");
    }
    assert!(c
        .children
        .iter()
        .all(|m| m.classify == zrax::formats::container::Classify::IfRecognized));
    // The boot sector lies in the first 4 KiB of a member, and the JSON ID.
    assert!(zrax::formats::container::is_recognized(&image[..4096]));
    assert_eq!(
        serde_json::to_string(&FileFormat::Ntfs).unwrap(),
        "\"ntfs\""
    );
}

#[test]
fn member_bytes_match_the_files_ntfs_3g_wrote() {
    let image = ntfs_img();
    let c = parse(&image);
    for member in &c.children {
        assert_eq!(
            &*member.data,
            ntfs_member_bytes(&member.label).as_slice(),
            "{}",
            member.label
        );
    }
    // Members stored as they are borrow the image at their offset; the
    // others name their transform and start with their first stored run.
    let transforms: Vec<(&str, Option<&str>)> = c
        .children
        .iter()
        .map(|member| (member.label.as_str(), member.transform))
        .collect();
    assert_eq!(
        transforms[0],
        ("/payload.elf", Some("NTFS update sequence"))
    );
    assert_eq!(transforms[1], ("/Program Files/Zrax/app.exe", None));
    assert_eq!(transforms[2], ("/notes.txt:payload.macho", None));
    assert_eq!(
        transforms[3],
        ("/compressed/zrax.macho", Some("NTFS LZNT1"))
    );
    assert_eq!(transforms[4], ("/sparse.elf", Some("NTFS runs")));
    assert_eq!(transforms[5], ("/bin/fragmented.elf", Some("NTFS runs")));
    for member in &c.children {
        let stored = &image[member.offset..member.offset + member.stored_size];
        match (member.transform, &member.data) {
            (None, Cow::Borrowed(bytes)) => assert_eq!(stored, *bytes, "{}", member.label),
            (Some("NTFS runs"), data) => {
                assert_eq!(stored, &data[..member.stored_size], "{}", member.label);
            }
            (Some("NTFS LZNT1"), _) => {
                // The first stored run starts with a compressed chunk header
                // (signature 3, bit 15 set).
                assert_eq!(le16(stored, 0) & 0xf000, 0xb000, "{}", member.label);
            }
            (Some("NTFS update sequence"), data) => {
                // The resident value crosses a stride end, whose stored
                // bytes are the update sequence number.
                assert_eq!(stored.len(), data.len());
                assert_ne!(stored, &data[..], "{}", member.label);
            }
            other => panic!("{}: {other:?}", member.label),
        }
    }
}

#[test]
fn links_streams_sparse_and_compressed_files_are_noted() {
    let image = ntfs_img();
    let c = parse(&image);
    for text in [
        "MFT walk: 218 base records in use after the 16 system records, 6 directories, 209 \
         regular files; members in a recognized format: 8",
        "2 files have more than one name (hard links)",
        "4 named data streams were examined",
        "2 members are resident: stored in their MFT records",
        "1 member has sparse runs, read as zeros",
        "1 member was decoded from LZNT1 compression units",
        "1 link with reparse tag 0xA000000C counted, not followed",
        "1 Interix symbolic link (IntxLNK) was counted, not followed",
        "No processor field",
    ] {
        assert!(has_note(&c, text), "{text}: {:?}", c.notes);
    }
    assert!(!has_note(&c, "Skipped"), "{:?}", c.notes);
    assert_eq!(metadata(&c, "ntfs_member_count"), "8");
    assert_eq!(metadata(&c, "ntfs_regular_file_count"), "209");
    // /links/hardlink.elf names the same record as /payload.elf, which is
    // listed once under its first name.
    assert!(!labels(&c).iter().any(|label| label.contains("hardlink")));
}

#[test]
fn sector_and_cluster_variants_decode_the_same_members() {
    let image = ntfs_4k_img();
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/payload.elf",
            "/Program Files/Zrax/app.exe",
            "/compressed/zrax.macho"
        ]
    );
    assert_eq!(&*child(&c, "/payload.elf").data, payload_elf().as_slice());
    assert_eq!(
        &*child(&c, "/Program Files/Zrax/app.exe").data,
        app_exe().as_slice()
    );
    assert_eq!(
        &*child(&c, "/compressed/zrax.macho").data,
        zrax_macho().as_slice()
    );
    let image = ntfs_512_img();
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/payload.elf",
            "/compressed/zrax.macho",
            "/bin/fragmented.elf"
        ]
    );
    assert_eq!(
        &*child(&c, "/compressed/zrax.macho").data,
        zrax_macho().as_slice()
    );
    let fragmented = child(&c, "/bin/fragmented.elf");
    assert_eq!(&*fragmented.data, &fragmented_elf()[..10240]);
    assert_eq!(fragmented.transform, Some("NTFS runs"));
    assert!(fragmented.stored_size < 10240, "the first of several runs");
    let payload = classify(&image);
    assert_eq!(payload.primary.isa, Isa::X86_64);
}

#[test]
fn the_mft_mirror_and_the_backup_boot_sector_are_compared() {
    let image = ntfs_img();
    // $MFTMirr at cluster 0x1FF: change a byte of its copy of record 1.
    let mut mirror = image.clone();
    mirror[0x1ff * 4096 + 1024 + 0x100] ^= 0xff;
    let c = parse(&mirror);
    assert!(has_note(&c, "differs from MFT records 1"), "{:?}", c.notes);
    // The backup boot sector: a changed serial number is noted, a missing
    // one is not, and other trailing data is an error.
    let size = image.len() - 512;
    let mut backup = image.clone();
    backup[size + 0x48] ^= 1;
    assert!(has_note(&parse(&backup), "differs from the boot sector"));
    let c = parse(&image[..size]);
    assert!(!has_note(&c, "Backup boot sector"));
    assert_eq!(c.consumed, size);
    let mut padded = image.clone();
    padded.extend_from_slice(&[0; 4096]);
    assert_eq!(parse(&padded).consumed, image.len());
    let mut trailing = image.clone();
    trailing.extend_from_slice(b"trailing data");
    assert_eq!(
        parse_error(&trailing),
        "NTFS volume parse error: Invalid trailing data: 525 B after the volume at 0x3FFE00 are \
         neither the backup boot sector nor padding"
    );
}

/// The prefixes the truncation sweeps parse.
fn sweep_ends(image: &[u8]) -> Vec<usize> {
    prefix_ends(image.len(), 4096, 9973, 4096)
}

#[test]
fn prefixes_are_truncated_volumes_that_list_only_members_inside_them() {
    for (name, image) in [
        ("ntfs.img", ntfs_img()),
        ("ntfs-4k.img", ntfs_4k_img()),
        ("ntfs-512.img", ntfs_512_img()),
    ] {
        let whole = parse(&image);
        // `number_of_sectors` times `bytes_per_sector`.
        let volume_size = (le64(&image, 0x28) * u64::from(le16(&image, 0x0b))) as usize;
        for end in sweep_ends(&image) {
            let prefix = &image[..end];
            if end < 512 {
                assert_eq!(ntfs::detect(prefix), None, "{name}: prefix {end}");
                continue;
            }
            match ntfs::parse_container(prefix, Layout::Ntfs) {
                // The volume and part of its backup boot sector.
                Ok(c) if end >= volume_size => {
                    assert!(!has_note(&c, "Volume truncated"), "{name}: prefix {end}");
                    assert_eq!(labels(&c), labels(&whole), "{name}: prefix {end}");
                    if end > volume_size && end < image.len() {
                        assert!(has_note(&c, "is cut short"), "{name}: prefix {end}");
                    }
                }
                Ok(c) => {
                    assert!(has_note(&c, "Volume truncated"), "{name}: prefix {end}");
                    assert_eq!(c.consumed, end, "{name}: prefix {end}");
                    assert_members_inside(name, &whole, &c, end);
                }
                Err(e) => assert!(
                    e.to_string()
                        .starts_with("NTFS volume parse error: Truncated volume"),
                    "{name}: prefix {end}: {e}"
                ),
            }
        }
    }
}

#[test]
fn a_cut_volume_lists_the_files_present_and_counts_the_others() {
    let image = ntfs_img();
    let c = parse(&image[..0xf0000]);
    assert_eq!(
        labels(&c),
        [
            "/payload.elf",
            "/Program Files/Zrax/app.exe",
            "/notes.txt:payload.macho"
        ]
    );
    assert!(has_note(
        &c,
        "Volume truncated: 960 KiB of 4193792 B present; files are listed only when all of \
         their data is present"
    ));
    assert!(has_note(
        &c,
        "$MFTMirr lies past the 960 KiB present and was not compared"
    ));
    assert!(
        has_note(&c, "5 data streams or files were not read"),
        "{:?}",
        c.notes
    );
    // The MFT continues past the cut: the records there are counted.
    let c = parse(&image[..0x10000]);
    assert!(
        has_note(&c, "MFT records lie past the 64 KiB present"),
        "{:?}",
        c.notes
    );
    // Without the root directory's record nothing can be listed.
    assert_eq!(
        parse_error(&image[..0x5000]),
        "NTFS volume parse error: Truncated volume: 8191 sectors of 512 B need 4193792 B, \
         20480 B present"
    );
}

// ---------------------------------------------------------------------------
// Synthetic volumes, built from the documented layout ([LAYOUT] ntfs-3g
// `include/ntfs-3g/layout.h`; docs/ntfs.md lists the fields)
// ---------------------------------------------------------------------------

/// Attribute types.
const AT_STANDARD_INFORMATION: u32 = 0x10;
const AT_ATTRIBUTE_LIST: u32 = 0x20;
const AT_FILE_NAME: u32 = 0x30;
const AT_VOLUME_NAME: u32 = 0x60;
const AT_VOLUME_INFORMATION: u32 = 0x70;
const AT_DATA: u32 = 0x80;
const AT_REPARSE_POINT: u32 = 0xc0;
const AT_LOGGED_UTILITY_STREAM: u32 = 0x100;
const AT_END: u32 = 0xffff_ffff;

/// Attribute flags.
const ATTR_IS_COMPRESSED: u16 = 0x0001;
const ATTR_IS_ENCRYPTED: u16 = 0x4000;
const ATTR_IS_SPARSE: u16 = 0x8000;

/// Record flags.
const RECORD_IN_USE: u16 = 0x0001;
const RECORD_IS_DIRECTORY: u16 = 0x0002;

/// `$STANDARD_INFORMATION` file attribute flags.
const FILE_ATTR_SYSTEM: u32 = 0x0004;
const FILE_ATTR_REPARSE_POINT: u32 = 0x0400;
const FILE_ATTR_ENCRYPTED: u32 = 0x4000;

/// `$FILE_NAME` namespaces.
const NAMESPACE_WIN32: u8 = 1;
const NAMESPACE_DOS: u8 = 2;

/// Records and update sequence strides.
const STRIDE: usize = 512;
const ROOT: u64 = 5;
const EXTEND: u64 = 11;

/// A run of clusters, or a sparse run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    /// First cluster; `None` for a sparse run.
    lcn: Option<u64>,
    clusters: u64,
}

fn stored(lcn: u64, clusters: u64) -> Run {
    Run {
        lcn: Some(lcn),
        clusters,
    }
}

fn sparse(clusters: u64) -> Run {
    Run {
        lcn: None,
        clusters,
    }
}

/// An attribute's value: in the record, or in runs.
#[derive(Debug, Clone)]
enum Value {
    Resident(Vec<u8>),
    NonResident(Extent),
}

/// One extent of a non-resident attribute.
#[derive(Debug, Clone)]
struct Extent {
    runs: Vec<Run>,
    lowest_vcn: u64,
    /// `allocated_size`, `data_size` and `initialized_size` in bytes.
    allocated: u64,
    size: u64,
    initialized: u64,
    compression_unit: u8,
}

/// An attribute record.
#[derive(Debug, Clone)]
struct Attr {
    kind: u32,
    name: String,
    flags: u16,
    instance: u16,
    value: Value,
}

/// An MFT record.
#[derive(Debug, Clone)]
struct RecordSpec {
    magic: [u8; 4],
    sequence: u16,
    flags: u16,
    /// `base_mft_record`: 0 for a base record.
    base: u64,
    attributes: Vec<Attr>,
}

/// An MFT reference: record number and sequence number.
fn reference(record: u64, sequence: u16) -> u64 {
    record | u64::from(sequence) << 48
}

/// The shortest little-endian two's complement bytes that sign-extend
/// back to `value` ([DOCS] `concepts/data_runs.html`).
fn signed_le(value: i64) -> Vec<u8> {
    let bytes = value.to_le_bytes();
    let mut len = 8;
    while len > 1 {
        let top = bytes[len - 1];
        let sign = bytes[len - 2] & 0x80;
        if (top == 0 && sign == 0) || (top == 0xff && sign != 0) {
            len -= 1;
        } else {
            break;
        }
    }
    bytes[..len].to_vec()
}

/// A mapping pairs array: a header byte (offset size << 4 | length size),
/// the run length, and the LCN delta from the previous stored run; no delta
/// for a sparse run; a zero byte at the end.
fn mapping_pairs(runs: &[Run]) -> Vec<u8> {
    let mut pairs = Vec::new();
    let mut previous = 0i64;
    for run in runs {
        let length = signed_le(run.clusters as i64);
        match run.lcn {
            Some(lcn) => {
                let delta = signed_le(lcn as i64 - previous);
                pairs.push((delta.len() << 4 | length.len()) as u8);
                pairs.extend_from_slice(&length);
                pairs.extend_from_slice(&delta);
                previous = lcn as i64;
            }
            None => {
                pairs.push(length.len() as u8);
                pairs.extend_from_slice(&length);
            }
        }
    }
    pairs.push(0);
    pairs
}

/// An attribute record. Resident: the 24-byte header, the name, the value
/// at an 8-aligned offset. Non-resident: the 64-byte header (72 when
/// compressed or sparse, with `compressed_size`), the name, the mapping
/// pairs at an 8-aligned offset.
fn encode_attribute(attr: &Attr, cluster: usize) -> Vec<u8> {
    let name = units(&attr.name);
    let mut out = vec![0u8; 24];
    put32(&mut out, 0, attr.kind);
    out[9] = attr.name.encode_utf16().count() as u8;
    put16(&mut out, 12, attr.flags);
    put16(&mut out, 14, attr.instance);
    match &attr.value {
        Value::Resident(value) => {
            let value_offset = align8(24 + name.len());
            put16(&mut out, 10, 24);
            out.extend_from_slice(&name);
            out.resize(value_offset, 0);
            out.extend_from_slice(value);
            out.resize(align8(out.len()), 0);
            put32(&mut out, 16, value.len() as u32);
            put16(&mut out, 20, value_offset as u16);
        }
        Value::NonResident(extent) => {
            let header = if attr.flags & (ATTR_IS_COMPRESSED | ATTR_IS_SPARSE) != 0 {
                72
            } else {
                64
            };
            out.resize(header, 0);
            out[8] = 1;
            put16(&mut out, 10, header as u16);
            let clusters: u64 = extent.runs.iter().map(|run| run.clusters).sum();
            put64(&mut out, 16, extent.lowest_vcn);
            put64(&mut out, 24, (extent.lowest_vcn + clusters).wrapping_sub(1));
            out[34] = extent.compression_unit;
            put64(&mut out, 40, extent.allocated);
            put64(&mut out, 48, extent.size);
            put64(&mut out, 56, extent.initialized);
            if header == 72 {
                let stored_clusters: u64 = extent
                    .runs
                    .iter()
                    .filter(|run| run.lcn.is_some())
                    .map(|run| run.clusters)
                    .sum();
                put64(&mut out, 64, stored_clusters * cluster as u64);
            }
            out.extend_from_slice(&name);
            let mapping_pairs_offset = align8(out.len());
            out.resize(mapping_pairs_offset, 0);
            put16(&mut out, 32, mapping_pairs_offset as u16);
            out.extend_from_slice(&mapping_pairs(&extent.runs));
            out.resize(align8(out.len()), 0);
        }
    }
    let length = out.len() as u32;
    put32(&mut out, 4, length);
    out
}

/// A record of `size` bytes: the NTFS 3.1 header (update sequence array at
/// 0x30), the attributes, the end marker, and the update sequence number
/// 0x0001 written over the last two bytes of each 512-byte stride, whose
/// bytes the array keeps.
fn encode_record(number: u64, spec: &RecordSpec, size: usize, cluster: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    let usa_count = 1 + size / STRIDE;
    let attributes_offset = align8(0x30 + 2 * usa_count);
    out[..4].copy_from_slice(&spec.magic);
    put16(&mut out, 4, 0x30);
    put16(&mut out, 6, usa_count as u16);
    put16(&mut out, 16, spec.sequence);
    put16(&mut out, 18, 1);
    put16(&mut out, 20, attributes_offset as u16);
    put16(&mut out, 22, spec.flags);
    put32(&mut out, 28, size as u32);
    put64(&mut out, 32, spec.base);
    put16(&mut out, 40, spec.attributes.len() as u16);
    put32(&mut out, 44, number as u32);
    let mut pos = attributes_offset;
    for attr in &spec.attributes {
        let bytes = encode_attribute(attr, cluster);
        out[pos..pos + bytes.len()].copy_from_slice(&bytes);
        pos += bytes.len();
    }
    put32(&mut out, pos, AT_END);
    put32(&mut out, 24, (pos + 8) as u32);
    let usn = [0x01, 0x00];
    out[0x30..0x32].copy_from_slice(&usn);
    for stride in 0..size / STRIDE {
        let tail = stride * STRIDE + STRIDE - 2;
        let entry = 0x30 + 2 * (stride + 1);
        out.copy_within(tail..tail + 2, entry);
        out[tail..tail + 2].copy_from_slice(&usn);
    }
    out
}

fn resident(kind: u32, name: &str, value: Vec<u8>) -> Attr {
    Attr {
        kind,
        name: name.to_string(),
        flags: 0,
        instance: 0,
        value: Value::Resident(value),
    }
}

/// `$STANDARD_INFORMATION`: four times (zero) and the file attributes at
/// 32, in the 72-byte NTFS 3.0 layout.
fn standard_information(file_attributes: u32) -> Attr {
    let mut value = vec![0u8; 72];
    put32(&mut value, 32, file_attributes);
    resident(AT_STANDARD_INFORMATION, "", value)
}

/// `$FILE_NAME`: the parent reference, four times, sizes, attributes, the
/// name length and namespace at 0x40, the UTF-16LE name at 0x42.
fn file_name(parent: u64, name: &str, namespace: u8) -> Attr {
    let mut value = vec![0u8; 0x42];
    put64(&mut value, 0, parent);
    value[0x40] = name.encode_utf16().count() as u8;
    value[0x41] = namespace;
    value.extend_from_slice(&units(name));
    resident(AT_FILE_NAME, "", value)
}

/// A `$DATA` attribute stored in `runs`, of `size` bytes.
fn data_runs(name: &str, runs: Vec<Run>, size: u64, cluster: usize) -> Attr {
    let clusters: u64 = runs.iter().map(|run| run.clusters).sum();
    Attr {
        kind: AT_DATA,
        name: name.to_string(),
        flags: if runs.iter().any(|run| run.lcn.is_none()) {
            ATTR_IS_SPARSE
        } else {
            0
        },
        instance: 0,
        value: Value::NonResident(Extent {
            runs,
            lowest_vcn: 0,
            allocated: clusters * cluster as u64,
            size,
            initialized: size,
            compression_unit: 0,
        }),
    }
}

/// Give a record's attributes distinct instance numbers in order.
fn numbered(mut attributes: Vec<Attr>) -> Vec<Attr> {
    for (i, attr) in attributes.iter_mut().enumerate() {
        attr.instance = i as u16;
    }
    attributes
}

/// Bytes written at a cluster.
#[derive(Debug, Clone)]
struct Write {
    lcn: u64,
    bytes: Vec<u8>,
}

/// Clusters of `cluster` bytes that hold `len` bytes.
fn clusters_for(len: usize, cluster: usize) -> u64 {
    (len / cluster + usize::from(len % cluster != 0)) as u64
}

/// A synthetic volume: boot sector, MFT records laid out through the
/// `$MFT` runs, the `$MFTMirr` copy of records 0-3, file data, and a backup
/// boot sector after the last cluster.
#[derive(Debug, Clone)]
struct Synth {
    sector: usize,
    cluster: usize,
    record: usize,
    clusters: u64,
    /// Where `$MFT`'s records are stored, in VCN order.
    mft_runs: Vec<Run>,
    mirror_lcn: u64,
    /// Extra attributes of record 0 after its `$DATA`, and a replacement
    /// for its generated `$DATA`.
    mft_data: Option<Vec<Attr>>,
    records: std::collections::BTreeMap<u64, RecordSpec>,
    writes: Vec<Write>,
    next_lcn: u64,
}

impl Synth {
    /// A volume with 512 B sectors and the given cluster and record sizes,
    /// `clusters` clusters, `$MFT` in `mft_runs` and the system records.
    fn with(cluster: usize, record: usize, clusters: u64, mft_runs: Vec<Run>) -> Self {
        let mut synth = Self {
            sector: 512,
            cluster,
            record,
            clusters,
            mft_runs,
            mirror_lcn: clusters / 2,
            mft_data: None,
            records: std::collections::BTreeMap::new(),
            writes: Vec::new(),
            next_lcn: 0,
        };
        synth.next_lcn = synth
            .mft_runs
            .iter()
            .map(|run| run.lcn.unwrap() + run.clusters)
            .max()
            .unwrap();
        let system = [
            "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", ".", "$Bitmap", "$Boot",
            "$BadClus", "$Secure", "$UpCase", "$Extend",
        ];
        for (number, name) in system.iter().enumerate() {
            let number = number as u64;
            let mut attributes = vec![
                standard_information(0x06),
                file_name(reference(ROOT, ROOT as u16), name, 3),
            ];
            if number == 3 {
                attributes.push(resident(AT_VOLUME_NAME, "", units("SYNTH")));
                attributes.push(resident(
                    AT_VOLUME_INFORMATION,
                    "",
                    vec![0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 0],
                ));
            }
            let directory = number == ROOT || number == EXTEND;
            // mkntfs gives $MFT sequence number 1 and the other system
            // files their record number.
            synth.records.insert(
                number,
                RecordSpec {
                    magic: *b"FILE",
                    sequence: if number == 0 { 1 } else { number as u16 },
                    flags: if directory {
                        RECORD_IN_USE | RECORD_IS_DIRECTORY
                    } else {
                        RECORD_IN_USE
                    },
                    base: 0,
                    attributes: numbered(attributes),
                },
            );
        }
        synth
    }

    /// 4 KiB clusters, 1 KiB records, 128 clusters, `$MFT` of 32 records at
    /// cluster 4.
    fn new() -> Self {
        Self::with(4096, 1024, 128, vec![stored(4, 8)])
    }

    /// Store `bytes` in fresh contiguous clusters.
    fn store(&mut self, bytes: &[u8]) -> Vec<Run> {
        let clusters = clusters_for(bytes.len(), self.cluster).max(1);
        let lcn = self.allocate(clusters);
        self.write(lcn, bytes);
        vec![stored(lcn, clusters)]
    }

    /// Write `bytes` at cluster `lcn` when the volume is built.
    fn write(&mut self, lcn: u64, bytes: &[u8]) {
        self.writes.push(Write {
            lcn,
            bytes: bytes.to_vec(),
        });
    }

    /// The next `clusters` free clusters, skipping the mirror's.
    fn allocate(&mut self, clusters: u64) -> u64 {
        let mirror_end = self.mirror_lcn + clusters_for(4 * self.record, self.cluster);
        if self.next_lcn < mirror_end && self.next_lcn + clusters > self.mirror_lcn {
            self.next_lcn = mirror_end;
        }
        let lcn = self.next_lcn;
        self.next_lcn += clusters;
        assert!(self.next_lcn <= self.clusters, "the volume is full");
        lcn
    }

    /// Store `bytes` one cluster at a time, leaving a free cluster between
    /// the clusters.
    fn store_fragmented(&mut self, bytes: &[u8]) -> Vec<Run> {
        bytes
            .chunks(self.cluster)
            .map(|chunk| {
                let lcn = self.allocate(1);
                self.allocate(1);
                self.write(lcn, chunk);
                stored(lcn, 1)
            })
            .collect()
    }

    /// Add a file record (sequence number 1) with its standard information,
    /// a Win32 name in `parent` and the given attributes, in type order.
    /// System records' sequence numbers are their record numbers.
    fn file(&mut self, number: u64, parent: u64, name: &str, streams: Vec<Attr>) {
        let parent_sequence = if parent < 16 { parent as u16 } else { 1 };
        let mut attributes = vec![
            standard_information(0),
            file_name(reference(parent, parent_sequence), name, NAMESPACE_WIN32),
        ];
        attributes.extend(streams);
        attributes.sort_by_key(|attr| attr.kind);
        self.records.insert(
            number,
            RecordSpec {
                magic: *b"FILE",
                sequence: 1,
                flags: RECORD_IN_USE,
                base: 0,
                attributes: numbered(attributes),
            },
        );
    }

    /// Add a directory record.
    fn directory(&mut self, number: u64, parent: u64, name: &str) {
        self.file(number, parent, name, Vec::new());
        self.records.get_mut(&number).unwrap().flags |= RECORD_IS_DIRECTORY;
    }

    /// A file holding `bytes` in fresh contiguous clusters.
    fn stored_file(&mut self, number: u64, parent: u64, name: &str, bytes: &[u8]) {
        let runs = self.store(bytes);
        let data = data_runs("", runs, bytes.len() as u64, self.cluster);
        self.file(number, parent, name, vec![data]);
    }

    fn record_count(&self) -> u64 {
        let clusters: u64 = self.mft_runs.iter().map(|run| run.clusters).sum();
        clusters * self.cluster as u64 / self.record as u64
    }

    /// The boot sector: jump, OEM ID, BIOS parameter block, sizes,
    /// `$MFT` and `$MFTMirr` clusters, record size encodings (negative:
    /// `1 << -value` bytes), serial number, end marker.
    fn boot_sector(&self) -> Vec<u8> {
        let mut sector = vec![0u8; self.sector.max(512)];
        sector[..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        sector[3..11].copy_from_slice(b"NTFS    ");
        put16(&mut sector, 0x0b, self.sector as u16);
        sector[0x0d] = (self.cluster / self.sector) as u8;
        sector[0x15] = 0xf8;
        put64(
            &mut sector,
            0x28,
            self.clusters * (self.cluster / self.sector) as u64,
        );
        put64(&mut sector, 0x30, self.mft_runs[0].lcn.unwrap());
        put64(&mut sector, 0x38, self.mirror_lcn);
        sector[0x40] = if self.record >= self.cluster {
            (self.record / self.cluster) as u8
        } else {
            (-(self.record.trailing_zeros() as i8)) as u8
        };
        sector[0x44] = (-12i8) as u8;
        put64(&mut sector, 0x48, 0x5a52_4158_4e54_4653);
        put16(&mut sector, 0x1fe, 0xaa55);
        sector
    }

    /// The file offset of `$MFT` byte `at`.
    fn mft_offset(&self, at: u64) -> usize {
        let cluster = self.cluster as u64;
        let mut vcn_start = 0;
        for run in &self.mft_runs {
            let end = vcn_start + run.clusters * cluster;
            if at < end {
                return (run.lcn.unwrap() * cluster + at - vcn_start) as usize;
            }
            vcn_start = end;
        }
        panic!("MFT byte 0x{at:X} is not mapped")
    }

    /// The encoded record `number` as the build writes it.
    fn encoded(&self, number: u64) -> Vec<u8> {
        let mut spec = self.records[&number].clone();
        if number == 0 {
            let size = self.record_count() * self.record as u64;
            let mut data = self
                .mft_data
                .clone()
                .unwrap_or_else(|| vec![data_runs("", self.mft_runs.clone(), size, self.cluster)]);
            spec.attributes.append(&mut data);
            spec.attributes.sort_by_key(|attr| attr.kind);
            spec.attributes = numbered(spec.attributes);
        }
        encode_record(number, &spec, self.record, self.cluster)
    }

    fn build(&self) -> Vec<u8> {
        let size = self.clusters as usize * self.cluster;
        let mut image = vec![0u8; size + self.sector];
        let boot = self.boot_sector();
        image[..boot.len()].copy_from_slice(&boot);
        image[size..size + boot.len().min(self.sector)].copy_from_slice(&boot[..self.sector]);
        for &number in self.records.keys() {
            let bytes = self.encoded(number);
            let start = number * self.record as u64;
            // Record bytes in MFT order, cluster by cluster, so that a
            // record may span runs.
            let step = self.cluster.min(self.record);
            for (i, chunk) in bytes.chunks(step).enumerate() {
                let at = self.mft_offset(start + (i * step) as u64);
                image[at..at + chunk.len()].copy_from_slice(chunk);
            }
            if number < 4 {
                let at = self.mirror_lcn as usize * self.cluster + number as usize * self.record;
                image[at..at + bytes.len()].copy_from_slice(&bytes);
            }
        }
        for write in &self.writes {
            let at = write.lcn as usize * self.cluster;
            image[at..at + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        image
    }

    /// The file offset of record `number`.
    fn record_offset(&self, number: u64) -> usize {
        self.mft_offset(number * self.record as u64)
    }
}

/// The displacement field width of an LZNT1 compressed word after
/// `written` bytes of a chunk: the largest value of 4 to 12 for which
/// 2^(value - 1) is less than `written`, or 4 ([MS-XCA] 2.5.1.4).
fn lznt1_displacement_bits(written: usize) -> u32 {
    (4..=12)
        .rev()
        .find(|&bits| 1usize << (bits - 1) < written)
        .unwrap_or(4)
}

/// An element of an LZNT1 flag group.
enum Element {
    Literal(u8),
    Word(u16),
}

/// One LZNT1 chunk for at most 4096 bytes ([MS-XCA] 2.5.1): compressed,
/// with literals and runs of three or more copies of the previous byte as
/// compressed words with displacement 1, or uncompressed when that is not
/// smaller.
fn lznt1_chunk(data: &[u8]) -> Vec<u8> {
    let mut elements: Vec<Element> = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let repeats = if pos == 0 {
            0
        } else {
            data[pos..]
                .iter()
                .take_while(|&&b| b == data[pos - 1])
                .count()
        };
        if repeats >= 3 {
            let length_bits = 16 - lznt1_displacement_bits(pos);
            let length = repeats.min((1 << length_bits) - 1 + 3);
            elements.push(Element::Word((length - 3) as u16));
            pos += length;
        } else {
            elements.push(Element::Literal(data[pos]));
            pos += 1;
        }
    }
    let mut body = Vec::new();
    for group in elements.chunks(8) {
        let flags = group.iter().enumerate().fold(0u8, |flags, (i, element)| {
            flags | (u8::from(matches!(element, Element::Word(_))) << i)
        });
        body.push(flags);
        for element in group {
            match element {
                Element::Word(word) => body.extend_from_slice(&word.to_le_bytes()),
                Element::Literal(literal) => body.push(*literal),
            }
        }
    }
    // Header: bit 15 compressed, signature 3, size with the header minus 3.
    let (header, body) = if body.len() < data.len() {
        (0xb000 | (body.len() + 2 - 3) as u16, body)
    } else {
        (0x3000 | (data.len() + 2 - 3) as u16, data.to_vec())
    };
    let mut chunk = header.to_le_bytes().to_vec();
    chunk.extend_from_slice(&body);
    chunk
}

impl Synth {
    /// Store `bytes` as an LZNT1-compressed attribute in units of 16
    /// clusters: an all-zero unit is sparse, a unit that compresses to
    /// fewer clusters is stored compressed and padded with a sparse run,
    /// others are stored as they are.
    fn store_compressed(&mut self, bytes: &[u8]) -> Vec<Run> {
        let unit = 16 * self.cluster;
        let mut runs = Vec::new();
        for chunk in bytes.chunks(unit) {
            if chunk.iter().all(|&b| b == 0) {
                runs.push(sparse(16));
                continue;
            }
            let compressed: Vec<u8> = chunk.chunks(4096).flat_map(lznt1_chunk).collect();
            let clusters = clusters_for(compressed.len(), self.cluster);
            if clusters < 16 {
                let lcn = self.allocate(clusters);
                self.write(lcn, &compressed);
                runs.push(stored(lcn, clusters));
                runs.push(sparse(16 - clusters));
            } else {
                let lcn = self.allocate(16);
                self.write(lcn, chunk);
                runs.push(stored(lcn, 16));
            }
        }
        runs
    }
}

/// A compressed `$DATA` attribute of `size` bytes in `runs`.
fn compressed_data(runs: Vec<Run>, size: u64, cluster: usize) -> Attr {
    let mut attr = data_runs("", runs, size, cluster);
    attr.flags = ATTR_IS_COMPRESSED;
    if let Value::NonResident(extent) = &mut attr.value {
        extent.compression_unit = 4;
    }
    attr
}

/// An ELF header followed by zeros and some text: compressible.
fn compressible_elf(size: usize) -> Vec<u8> {
    let mut body = payload_elf();
    body.resize(size / 2, 0);
    body.extend_from_slice(&repeated(
        size - size / 2,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
    ));
    body
}

/// The common synthetic volume: a resident ELF, a fragmented PE in `/bin`,
/// a sparse ELF, an LZNT1-compressed ELF, and a text file with a named
/// stream holding the Mach-O header.
fn synthetic() -> Synth {
    let mut v = Synth::new();
    v.file(
        16,
        ROOT,
        "payload.elf",
        vec![resident(AT_DATA, "", payload_elf())],
    );
    v.directory(17, ROOT, "bin");
    let runs = v.store_fragmented(&app_exe());
    let pe = data_runs("", runs, app_exe().len() as u64, v.cluster);
    v.file(18, 17, "app.exe", vec![pe]);
    let mut runs = v.store(&payload_elf());
    runs.push(sparse(3));
    let tail = v.store(&repeated(4096, b"tail "));
    runs.extend(tail);
    let size = 5 * 4096;
    v.file(
        19,
        ROOT,
        "sparse.elf",
        vec![data_runs("", runs, size, v.cluster)],
    );
    let zipped = compressible_elf(100_000);
    let runs = v.store_compressed(&zipped);
    let data = compressed_data(runs, zipped.len() as u64, v.cluster);
    v.file(20, ROOT, "zipped.elf", vec![data]);
    let stream_runs = v.store(&kernel_macho());
    let stream = data_runs("macho", stream_runs, kernel_macho().len() as u64, v.cluster);
    v.file(
        21,
        ROOT,
        "notes.txt",
        vec![
            resident(AT_DATA, "", b"not a recognized format".to_vec()),
            stream,
        ],
    );
    v
}

#[test]
fn a_synthetic_volume_lists_resident_fragmented_sparse_and_compressed_files() {
    let v = synthetic();
    let image = v.build();
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/payload.elf",
            "/bin/app.exe",
            "/sparse.elf",
            "/zipped.elf",
            "/notes.txt:macho"
        ]
    );
    assert_eq!(&*child(&c, "/payload.elf").data, payload_elf().as_slice());
    let pe = child(&c, "/bin/app.exe");
    assert_eq!(&*pe.data, app_exe().as_slice());
    assert_eq!(pe.transform, Some("NTFS runs"));
    assert_eq!(pe.stored_size, 4096, "the first one-cluster run");
    let mut sparse_bytes = payload_elf();
    sparse_bytes.resize(4 * 4096, 0);
    sparse_bytes.extend_from_slice(&repeated(4096, b"tail "));
    assert_eq!(&*child(&c, "/sparse.elf").data, sparse_bytes.as_slice());
    let zipped = child(&c, "/zipped.elf");
    assert_eq!(&*zipped.data, compressible_elf(100_000).as_slice());
    assert_eq!(zipped.transform, Some("NTFS LZNT1"));
    assert_eq!(
        &*child(&c, "/notes.txt:macho").data,
        kernel_macho().as_slice()
    );
    assert!(has_note(&c, "NTFS 3.1 volume: 128 clusters of 4 KiB"));
    assert!(has_note(&c, "matches the first 4 MFT records"));
    assert_eq!(metadata(&c, "ntfs_volume_name"), "SYNTH");
    let payload = classify(&image);
    assert_eq!(payload.primary.isa, Isa::X86_64);
    assert_eq!(payload.format.format, FileFormat::Ntfs);
}

#[test]
fn compression_units_may_be_sparse_stored_or_compressed() {
    let mut v = Synth::new();
    // Unit 0 compressed, unit 1 sparse (zeros), unit 2 stored as is
    // (random-looking bytes that do not compress), then a short tail.
    let mut bytes = compressible_elf(65536);
    bytes.resize(2 * 65536, 0);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..65536 + 1000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        bytes.push(x as u8);
    }
    let runs = v.store_compressed(&bytes);
    assert_eq!(runs[2], sparse(16), "unit 1 is sparse");
    let data = compressed_data(runs, bytes.len() as u64, v.cluster);
    v.file(16, ROOT, "units.elf", vec![data]);
    let image = v.build();
    let c = parse(&image);
    assert_eq!(&*child(&c, "/units.elf").data, bytes.as_slice());
    // A compression unit other than 16 clusters is not read.
    let mut v = Synth::new();
    let runs = v.store_compressed(&compressible_elf(65536));
    let mut data = compressed_data(runs, 65536, v.cluster);
    if let Value::NonResident(extent) = &mut data.value {
        extent.compression_unit = 3;
    }
    v.file(16, ROOT, "odd-unit.elf", vec![data]);
    let runs = v.store(&payload_elf());
    let mut method = data_runs("", runs, 256, v.cluster);
    method.flags = 0x0002;
    v.file(17, ROOT, "method-2.elf", vec![method]);
    let built = v.build();
    let c = parse(&built);
    assert_eq!(labels(&c), Vec::<String>::new());
    assert!(
        has_note(
            &c,
            "1 stream uses compression method 1 in units of 2^3 clusters of 4 KiB, which is not \
             implemented; not read"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "1 stream uses compression method 2 in units of 2^0 clusters"
    ));
}

#[test]
fn bytes_past_the_initialized_size_read_as_zeros_and_empty_files_are_skipped() {
    let mut v = Synth::new();
    let runs = v.store(&repeated(
        8192,
        b"\x7fELF\x02\x01\x01\x00garbage past init ",
    ));
    let mut data = data_runs("", runs, 8192, v.cluster);
    if let Value::NonResident(extent) = &mut data.value {
        extent.initialized = 256;
    }
    v.file(16, ROOT, "initialized.elf", vec![data]);
    // The ELF's own header in the first 256 bytes.
    v.writes.last_mut().unwrap().bytes[..256].copy_from_slice(&payload_elf());
    v.file(
        17,
        ROOT,
        "empty.bin",
        vec![resident(AT_DATA, "", Vec::new())],
    );
    let built = v.build();
    let c = parse(&built);
    let mut expected = payload_elf();
    expected.resize(8192, 0);
    let member = child(&c, "/initialized.elf");
    assert_eq!(&*member.data, expected.as_slice());
    assert_eq!(member.transform, Some("NTFS runs"));
    assert_eq!(labels(&c), ["/initialized.elf"]);
}

#[test]
fn data_extents_in_extension_records_are_joined_through_the_attribute_list() {
    let mut v = Synth::new();
    let pe = app_exe();
    let first = v.store(&pe[..8192]);
    let second = v.store(&pe[8192..]);
    // Record 22 is the base record; extents at VCN 0 and 2 are in
    // extension records 23 and 24, and the named stream in 23.
    let head = Attr {
        kind: AT_DATA,
        name: String::new(),
        flags: 0,
        instance: 0,
        value: Value::NonResident(Extent {
            runs: first,
            lowest_vcn: 0,
            allocated: 12288,
            size: pe.len() as u64,
            initialized: pe.len() as u64,
            compression_unit: 0,
        }),
    };
    let tail = Attr {
        value: Value::NonResident(Extent {
            runs: second,
            lowest_vcn: 2,
            allocated: 0,
            size: 0,
            initialized: 0,
            compression_unit: 0,
        }),
        ..head.clone()
    };
    let stream = Attr {
        name: "payload".to_string(),
        instance: 1,
        ..resident(AT_DATA, "", payload_elf())
    };
    /// One attribute list entry: type, length, name length and offset,
    /// lowest VCN, MFT reference, instance, name.
    fn entry(kind: u32, name: &str, lowest_vcn: u64, record: u64, instance: u16) -> Vec<u8> {
        let name = units(name);
        let mut out = vec![0u8; 26];
        put32(&mut out, 0, kind);
        out[6] = (name.len() / 2) as u8;
        out[7] = 26;
        put64(&mut out, 8, lowest_vcn);
        put64(&mut out, 16, reference(record, 1));
        put16(&mut out, 24, instance);
        out.extend_from_slice(&name);
        out.resize(align8(out.len()), 0);
        let length = out.len() as u16;
        put16(&mut out, 4, length);
        out
    }
    // In the base record: standard information (instance 0), the list
    // (1), the name (2).
    let list: Vec<u8> = [
        entry(AT_STANDARD_INFORMATION, "", 0, 22, 0),
        entry(AT_FILE_NAME, "", 0, 22, 2),
        entry(AT_DATA, "", 0, 23, 0),
        entry(AT_DATA, "", 2, 24, 0),
        entry(AT_DATA, "payload", 0, 23, 1),
    ]
    .concat();
    v.file(
        22,
        ROOT,
        "split.exe",
        vec![resident(AT_ATTRIBUTE_LIST, "", list)],
    );
    let extension = |attributes: Vec<Attr>| RecordSpec {
        magic: *b"FILE",
        sequence: 1,
        flags: RECORD_IN_USE,
        base: reference(22, 1),
        attributes,
    };
    v.records.insert(23, extension(vec![head, stream]));
    v.records.insert(24, extension(vec![tail]));
    let image = v.build();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/split.exe", "/split.exe:payload"]);
    let member = child(&c, "/split.exe");
    assert_eq!(&*member.data, pe.as_slice());
    assert_eq!(member.transform, Some("NTFS runs"));
    assert_eq!(
        &*child(&c, "/split.exe:payload").data,
        payload_elf().as_slice()
    );

    // An extension record that names another base record, and a listed
    // extent that is missing, are problems for that file only.
    let mut wrong_base = v.clone();
    wrong_base.records.get_mut(&24).unwrap().base = reference(16, 1);
    let built = wrong_base.build();
    let c = parse(&built);
    assert_eq!(labels(&c), Vec::<String>::new());
    assert!(
        has_note(
            &c,
            "Skipped MFT record 22: Invalid attribute list of MFT record 22: record 24 is not its \
         extension record in use"
        ),
        "{:?}",
        c.notes
    );
    let mut missing = v.clone();
    missing.records.get_mut(&24).unwrap().attributes.clear();
    let built = missing.build();
    let c = parse(&built);
    assert!(
        has_note(&c, "record 24 lacks attribute 0x80 (instance 0, VCN 0x2)"),
        "{:?}",
        c.notes
    );
}

#[test]
fn a_fragmented_mft_is_read_through_its_runlist() {
    // $MFT in two runs: records 0-7 at cluster 4, records 8-31 at cluster
    // 40 (the second run's delta is positive, then the files' data).
    let mut v = Synth::with(4096, 1024, 128, vec![stored(4, 2), stored(40, 6)]);
    v.next_lcn = 46;
    v.stored_file(30, ROOT, "late.elf", &payload_elf());
    let image = v.build();
    assert_eq!(v.record_offset(30), 40 * 4096 + 22 * 1024);
    let c = parse(&image);
    assert_eq!(labels(&c), ["/late.elf"]);
    assert!(has_note(&c, "$MFT at cluster 0x4 with 32 records"));
}

#[test]
fn the_mft_attribute_list_places_its_later_extents_in_extension_records() {
    // $MFT's $DATA in two extents: VCN 0-3 (records 0-15) in record 0 and
    // VCN 4-7 in extension record 15, which the first extent maps, as
    // ntfs-3g reads it.
    let mut v = Synth::with(4096, 1024, 128, vec![stored(4, 4), stored(40, 4)]);
    v.stored_file(30, ROOT, "late.elf", &payload_elf());
    let extent = |runs: Vec<Run>, lowest_vcn: u64| Attr {
        kind: AT_DATA,
        name: String::new(),
        flags: 0,
        instance: 0,
        value: Value::NonResident(Extent {
            runs,
            lowest_vcn,
            allocated: if lowest_vcn == 0 { 8 * 4096 } else { 0 },
            size: if lowest_vcn == 0 { 32 * 1024 } else { 0 },
            initialized: if lowest_vcn == 0 { 32 * 1024 } else { 0 },
            compression_unit: 0,
        }),
    };
    /// An attribute list entry: type, length 32, no name, lowest VCN,
    /// reference, instance.
    fn entry(kind: u32, lowest_vcn: u64, record: u64, instance: u16) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        put32(&mut out, 0, kind);
        put16(&mut out, 4, 32);
        out[7] = 26;
        put64(&mut out, 8, lowest_vcn);
        put64(&mut out, 16, reference(record, record as u16));
        put16(&mut out, 24, instance);
        out
    }
    // Record 0 after sorting: standard information (0), the list (1), the
    // name (2), the first extent (3).
    let list = [
        entry(AT_STANDARD_INFORMATION, 0, 0, 0),
        entry(AT_FILE_NAME, 0, 0, 2),
        entry(AT_DATA, 0, 0, 3),
        entry(AT_DATA, 4, 15, 0),
    ]
    .concat();
    v.mft_data = Some(vec![
        resident(AT_ATTRIBUTE_LIST, "", list),
        extent(vec![stored(4, 4)], 0),
    ]);
    v.records.insert(
        15,
        RecordSpec {
            magic: *b"FILE",
            sequence: 15,
            flags: RECORD_IN_USE,
            base: reference(0, 1),
            attributes: vec![extent(vec![stored(40, 4)], 4)],
        },
    );
    let built = v.build();
    let c = parse(&built);
    assert_eq!(labels(&c), ["/late.elf"]);
    // Without the extension record, the later records are not mapped.
    let mut broken = v.clone();
    broken.records.remove(&15);
    assert_eq!(
        parse_error(&broken.build()),
        "NTFS volume parse error: Invalid $MFT: its $DATA extension record 15 is empty"
    );
}

#[test]
fn records_split_across_runs_are_reassembled() {
    // 512 B clusters and 1 KiB records: the first $MFT run of 35 clusters
    // ends in the middle of record 17, whose second half is at cluster 200.
    let mut v = Synth::with(512, 1024, 1024, vec![stored(16, 35), stored(200, 29)]);
    v.next_lcn = 300;
    v.file(
        17,
        ROOT,
        "split.elf",
        vec![resident(AT_DATA, "", payload_elf())],
    );
    let image = v.build();
    let c = parse(&image);
    let member = child(&c, "/split.elf");
    assert_eq!(&*member.data, payload_elf().as_slice());
    assert_eq!(member.transform, Some("NTFS update sequence"));
    assert!(has_note(&c, "1024 clusters of 512 B"));
}

#[test]
fn paths_follow_parent_references_and_orphans_are_listed_apart() {
    let mut v = Synth::new();
    v.directory(16, ROOT, "a");
    v.directory(17, 16, "b");
    v.stored_file(18, 17, "deep.elf", &payload_elf());
    // A parent that does not exist, a parent cycle, and a stale sequence
    // number: orphans.
    v.stored_file(19, 25, "lost.elf", &payload_elf());
    v.directory(20, 21, "c");
    v.directory(21, 20, "d");
    v.stored_file(22, 20, "cycle.elf", &payload_elf());
    v.stored_file(23, 16, "stale.elf", &payload_elf());
    if let Value::Resident(name) = &mut v.records.get_mut(&23).unwrap().attributes[1].value {
        put64(name, 0, reference(16, 9));
    }
    // System files below $Extend are not read, and a DOS alias is not a
    // name of its own.
    v.stored_file(24, EXTEND, "$Secret.elf", &payload_elf());
    v.stored_file(26, ROOT, "Long File Name.elf", &payload_elf());
    let record = v.records.get_mut(&26).unwrap();
    let alias = file_name(reference(ROOT, 5), "LONGFI~1.ELF", NAMESPACE_DOS);
    record.attributes.insert(1, alias);
    record.attributes = numbered(std::mem::take(&mut record.attributes));
    let built = v.build();
    let c = parse(&built);
    assert_eq!(
        labels(&c),
        [
            "/a/b/deep.elf",
            "/$OrphanFiles/lost.elf",
            "/$OrphanFiles/cycle.elf",
            "/$OrphanFiles/stale.elf",
            "/Long File Name.elf"
        ]
    );
    assert!(has_note(
        &c,
        "3 files or directories are not reachable from the root directory; recognized ones are \
         listed under /$OrphanFiles"
    ), "{:?}", c.notes);
    assert!(!has_note(&c, "hard links"), "a DOS alias is not a link");
    assert!(!labels(&c).iter().any(|label| label.contains("Secret")));
    assert_eq!(metadata(&c, "ntfs_directory_count"), "4");
}

#[test]
fn paths_deeper_than_the_limit_are_counted() {
    let mut v = Synth::with(4096, 1024, 256, vec![stored(4, 24)]);
    let mut parent = ROOT;
    for level in 0..70u64 {
        v.directory(16 + level, parent, &format!("d{level}"));
        parent = 16 + level;
    }
    v.stored_file(16 + 70, parent, "deep.elf", &payload_elf());
    v.stored_file(16 + 71, 16 + 10, "shallow.elf", &payload_elf());
    let built = v.build();
    let c = parse(&built);
    let shallow: String = (0..=10).map(|level| format!("/d{level}")).collect();
    assert_eq!(labels(&c), [format!("{shallow}/shallow.elf")]);
    assert!(
        has_note(&c, "1 file deeper than 64 directory levels was not read"),
        "{:?}",
        c.notes
    );
}

#[test]
fn encrypted_files_links_and_wof_files_are_counted_and_other_reparse_points_read() {
    let mut v = Synth::new();
    v.stored_file(16, ROOT, "efs-flag.elf", &payload_elf());
    if let Value::Resident(info) = &mut v.records.get_mut(&16).unwrap().attributes[0].value {
        put32(info, 32, FILE_ATTR_ENCRYPTED);
    }
    v.stored_file(17, ROOT, "efs-stream.elf", &payload_elf());
    v.records.get_mut(&17).unwrap().attributes.push(Attr {
        instance: 9,
        ..resident(AT_LOGGED_UTILITY_STREAM, "$EFS", vec![0; 0x60])
    });
    v.stored_file(18, ROOT, "encrypted-attribute.elf", &payload_elf());
    if let Some(attr) = v.records.get_mut(&18).unwrap().attributes.last_mut() {
        attr.flags |= ATTR_IS_ENCRYPTED;
    }
    let reparse = |tag: u32| {
        let mut value = vec![0u8; 8];
        put32(&mut value, 0, tag);
        resident(AT_REPARSE_POINT, "", value)
    };
    for (number, name, tag) in [
        (19, "symlink.elf", 0xa000_000c),
        (20, "junction", 0xa000_0003),
        (21, "wof.elf", 0x8000_0017),
        (22, "dedup.elf", 0x8000_0013),
    ] {
        v.stored_file(number, ROOT, name, &payload_elf());
        let record = v.records.get_mut(&number).unwrap();
        if let Value::Resident(info) = &mut record.attributes[0].value {
            put32(info, 32, FILE_ATTR_REPARSE_POINT);
        }
        record.attributes.push(Attr {
            instance: 9,
            ..reparse(tag)
        });
    }
    // An Interix symbolic link: a system file starting with `IntxLNK\1`.
    let mut interix = b"IntxLNK\x01".to_vec();
    interix.extend_from_slice(&units("payload.elf"));
    v.file(23, ROOT, "interix", vec![resident(AT_DATA, "", interix)]);
    if let Value::Resident(info) = &mut v.records.get_mut(&23).unwrap().attributes[0].value {
        put32(info, 32, FILE_ATTR_SYSTEM);
    }
    let built = v.build();
    let c = parse(&built);
    assert_eq!(labels(&c), ["/dedup.elf"]);
    for text in [
        "3 encrypted files were not read: EFS-encrypted data is opaque",
        "1 link with reparse tag 0xA0000003 counted, not followed",
        "1 link with reparse tag 0xA000000C counted, not followed",
        "1 WOF-compressed file was not read",
        "1 file carries reparse tag 0x80000013; their data streams were examined as stored",
        "1 Interix symbolic link (IntxLNK) was counted, not followed",
    ] {
        assert!(has_note(&c, text), "{text}: {:?}", c.notes);
    }
}

#[test]
fn damaged_records_are_skipped_with_notes() {
    let mut v = synthetic();
    let clean = v.build();
    // A torn write in record 18, BAAD in 19, an unknown magic in 20, a
    // runlist past the volume in 21.
    let mut image = clean.clone();
    let torn = v.record_offset(18) + 1022;
    image[torn] ^= 0xff;
    image[v.record_offset(19)..v.record_offset(19) + 4].copy_from_slice(b"BAAD");
    image[v.record_offset(20)..v.record_offset(20) + 4].copy_from_slice(b"XYZW");
    let c = parse(&image);
    assert_eq!(labels(&c), ["/payload.elf", "/notes.txt:macho"]);
    for text in [
        "Skipped MFT record 18: Invalid MFT record 18: stride 1 does not end with the update \
         sequence number (incomplete multi-sector transfer)",
        "Skipped MFT record 19: Invalid MFT record 19: BAAD magic",
        "Skipped MFT record 20: Invalid MFT record 20: magic 0x575A5958 instead of FILE",
    ] {
        assert!(has_note(&c, text), "{text}: {:?}", c.notes);
    }
    let runs = vec![stored(120, 20)];
    v.file(22, ROOT, "far.elf", vec![data_runs("", runs, 4096, 4096)]);
    let built = v.build();
    let c = parse(&built);
    assert!(has_note(
        &c,
        "Skipped MFT record 22: Invalid runlist of attribute 0x80 in MFT record 22: the run at \
         0x0 maps clusters 0x78 + 20 beyond the 128 clusters of the volume"
    ), "{:?}", c.notes);
    // Attributes out of order.
    let mut v = synthetic();
    v.records.get_mut(&16).unwrap().attributes.swap(0, 1);
    let built = v.build();
    let c = parse(&built);
    assert!(
        has_note(
            &c,
            "Skipped MFT record 16: Invalid MFT record 16: attribute 0x10"
        ),
        "{:?}",
        c.notes
    );
}

#[test]
fn damage_to_the_mft_or_the_root_is_a_parse_error() {
    let v = synthetic();
    let image = v.build();
    let error_of = |mutate: &dyn Fn(&mut Vec<u8>)| {
        let mut damaged = image.clone();
        mutate(&mut damaged);
        parse_error(&damaged)
    };
    let mft = v.record_offset(0);
    assert_eq!(
        error_of(&|d| d[mft + 510] ^= 1),
        "NTFS volume parse error: Invalid MFT record 0: stride 0 does not end with the update \
         sequence number (incomplete multi-sector transfer)"
    );
    assert_eq!(
        error_of(&|d| d[mft..mft + 4].copy_from_slice(&[0; 4])),
        "NTFS volume parse error: Invalid $MFT: MFT record 0 is empty"
    );
    let root = v.record_offset(ROOT);
    assert_eq!(
        error_of(&|d| put16(d, root + 22, RECORD_IN_USE)),
        "NTFS volume parse error: Missing root directory: MFT record 5 is not a directory in use"
    );
    // The boot sector names another $MFT cluster than the runlist.
    assert!(error_of(&|d| put64(d, 0x30, 5)).starts_with("NTFS volume parse error: Invalid"));

    let mut resident_mft = v.clone();
    resident_mft.mft_data = Some(vec![resident(AT_DATA, "", vec![0; 64])]);
    assert_eq!(
        parse_error(&resident_mft.build()),
        "NTFS volume parse error: Invalid $MFT: its $DATA is resident"
    );
    let mut overlapping = Synth::with(4096, 1024, 128, vec![stored(4, 4), stored(6, 4)]);
    overlapping.next_lcn = 16;
    assert_eq!(
        parse_error(&overlapping.build()),
        "NTFS volume parse error: Invalid $MFT: its runs overlap"
    );
    let mut small = Synth::with(4096, 1024, 128, vec![stored(4, 3)]);
    small.next_lcn = 16;
    assert_eq!(
        parse_error(&small.build()),
        "NTFS volume parse error: Invalid $MFT: 12 records, fewer than the 16 system records"
    );
    let mut sparse_mft = v.clone();
    sparse_mft.mft_data = Some(vec![data_runs(
        "",
        vec![stored(4, 8), sparse(8)],
        64 * 1024,
        4096,
    )]);
    assert_eq!(
        parse_error(&sparse_mft.build()),
        "NTFS volume parse error: Invalid $MFT: its runlist has a sparse run"
    );
}

#[test]
fn detection_requires_a_consistent_boot_sector() {
    let image = synthetic().build();
    assert_eq!(ntfs::detect(&image), Some(Layout::Ntfs));
    assert_eq!(ntfs::detect(&image[..511]), None);
    let rejected = |at: usize, bytes: &[u8]| {
        let mut changed = image.clone();
        changed[at..at + bytes.len()].copy_from_slice(bytes);
        ntfs::detect(&changed).is_none()
    };
    // OEM ID, end marker, sector sizes, cluster encodings and sizes, the
    // zero FAT fields, record size encodings, the sector count and the MFT
    // locations.
    assert!(rejected(3, b"NTFS   X"));
    assert!(rejected(0x1fe, &[0x55, 0xab]));
    for sector in [128u16, 384, 8192, 0] {
        assert!(
            rejected(0x0b, &sector.to_le_bytes()),
            "sector size {sector}"
        );
    }
    for spc in [0u8, 3, 129, 239, 254, 255] {
        assert!(rejected(0x0d, &[spc]), "sectors per cluster 0x{spc:02X}");
    }
    assert!(
        rejected(0x0d, &[0xf3]),
        "8192 sectors of 512 B: 4 MiB clusters"
    );
    for at in [0x0e, 0x10, 0x11, 0x13, 0x16, 0x20] {
        assert!(rejected(at, &[1]), "FAT field at 0x{at:X}");
    }
    for value in [0u8, 3, 0x80, 0xe0, 0xf8, 0xf9] {
        assert!(
            rejected(0x40, &[value]),
            "clusters per MFT record 0x{value:02X}"
        );
        assert!(
            rejected(0x44, &[value]),
            "clusters per index record 0x{value:02X}"
        );
    }
    assert!(rejected(0x40, &[0x20]), "128 KiB MFT records");
    assert!(rejected(0x28, &0u64.to_le_bytes()));
    assert!(rejected(0x28, &(-1i64).to_le_bytes()));
    assert!(
        rejected(0x28, &(1u64 << 62).to_le_bytes()),
        "a size past 64 bits"
    );
    assert!(rejected(0x30, &0u64.to_le_bytes()));
    assert!(
        rejected(0x30, &128u64.to_le_bytes()),
        "past the last cluster"
    );
    assert!(rejected(0x38, &4u64.to_le_bytes()), "the mirror on the MFT");
    // Large-cluster encodings ntfs-3g accepts: 0xF4 is 4096 sectors.
    let mut large = image.clone();
    large[0x0d] = 0xf4;
    put64(&mut large, 0x28, 1 << 20);
    assert_eq!(ntfs::detect(&large), Some(Layout::Ntfs));
    // The MBR check refuses an NTFS boot sector, and so does every other
    // detector: the format is NTFS.
    assert_eq!(classify(&image).format.format, FileFormat::Ntfs);
    assert_eq!(
        ntfs::parse_container(&image[..300], Layout::Ntfs)
            .unwrap_err()
            .to_string(),
        "NTFS volume parse error: Truncated boot sector: 512 B needed, 300 B present"
    );
}

#[test]
fn volume_flags_are_noted() {
    let mut v = synthetic();
    if let Value::Resident(info) = &mut v.records.get_mut(&3).unwrap().attributes[3].value {
        put16(info, 10, 0x8001);
    }
    let built = v.build();
    let c = parse(&built);
    assert!(
        has_note(&c, "The volume is marked dirty (VOLUME_IS_DIRTY)"),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "The volume flags record a chkdsk run"));
}

#[test]
fn record_sizes_match_their_sector_size_variants() {
    // 4096-byte sectors and records: eight strides per record.
    let mut v = Synth::with(4096, 4096, 128, vec![stored(4, 32)]);
    v.sector = 4096;
    v.next_lcn = 40;
    // The ELF header's first 128 bytes end before the first stride end.
    let head = payload_elf()[..128].to_vec();
    v.file(
        16,
        ROOT,
        "payload.elf",
        vec![resident(AT_DATA, "", head.clone())],
    );
    let image = v.build();
    let c = parse(&image);
    assert_eq!(labels(&c), ["/payload.elf"]);
    assert_eq!(metadata(&c, "ntfs_bytes_per_sector"), "4096");
    assert_eq!(&*child(&c, "/payload.elf").data, head.as_slice());
    // A resident value clear of the stride ends is borrowed as stored.
    let member = child(&c, "/payload.elf");
    assert_eq!(member.transform, None);
    assert!(matches!(member.data, Cow::Borrowed(_)));
}

/// Set byte `at` of `image` three ways (0x00, 0xFF, its low bit flipped)
/// and parse each time, which may fail but must not panic; then restore it.
fn mutate_and_parse(image: &mut [u8], at: usize) {
    let original = image[at];
    for change in [0x00, 0xff, original ^ 0x01] {
        image[at] = change;
        if let Some(layout) = ntfs::detect(image) {
            let _ = ntfs::parse_container(image, layout);
        }
    }
    image[at] = original;
}

#[test]
fn byte_mutations_of_the_metadata_never_panic() {
    let v = synthetic();
    let mut image = v.build();
    // The boot sector, records 0-5 and every 3rd byte of the other records.
    let mft = v.record_offset(0);
    for at in (0..512)
        .chain(mft..mft + 6 * 1024)
        .chain((mft + 6 * 1024..mft + 32 * 1024).step_by(3))
    {
        mutate_and_parse(&mut image, at);
    }
    // The 512 B cluster fixture's boot sector, every 11th byte of its system
    // records and every 23rd byte of its user records.
    let mut image = ntfs_512_img();
    for at in (0..512)
        .chain((0x4000..0x8000).step_by(11))
        .chain((0x14000..0x1a000).step_by(23))
    {
        mutate_and_parse(&mut image, at);
    }
    // Every 7th byte of the main fixture's records 0-5 and every 61st of
    // its user records.
    let mut image = ntfs_img();
    for at in (0x4000..0x5800)
        .step_by(7)
        .chain((0x14000..0x20000).step_by(61))
    {
        mutate_and_parse(&mut image, at);
    }
}

#[test]
fn byte_mutations_of_the_whole_image_never_panic_the_classifier() {
    let mut image = ntfs_512_img();
    for at in (0..image.len()).step_by(997) {
        image[at] ^= 0xff;
        let _ = detect_payload(&image, &ClassifierOptions::new());
        image[at] ^= 0xff;
    }
}

#[test]
fn attribute_lists_that_share_clusters_stop_at_the_metadata_read_limit() {
    // 79 files whose non-resident attribute lists all name the same 256 KiB
    // of clusters: each load parses 256 KiB, so the first pass reaches 16
    // times the 1 MiB floor after about 64 loads, and the walk stops before
    // it examines the files it indexed.
    let mut v = Synth::with(4096, 1024, 256, vec![stored(4, 24)]);
    let shared = vec![stored(160, 64)];
    v.stored_file(16, ROOT, "first.elf", &payload_elf());
    for number in 17..96 {
        let list = Attr {
            kind: AT_ATTRIBUTE_LIST,
            ..data_runs("", shared.clone(), 64 * 4096, 4096)
        };
        v.file(number, ROOT, &format!("file{number}.bin"), vec![list]);
    }
    let built = v.build();
    let c = parse(&built);
    assert_eq!(labels(&c), Vec::<String>::new());
    assert!(
        has_note(
            &c,
            "The walk stopped at the metadata read limit (16 times the 1 MiB present, at least \
             1 MiB)"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "files not examined"));
    // Without the shared lists, the same volume lists its file.
    let mut plain = Synth::with(4096, 1024, 256, vec![stored(4, 24)]);
    plain.stored_file(16, ROOT, "first.elf", &payload_elf());
    let built = plain.build();
    assert_eq!(labels(&parse(&built)), ["/first.elf"]);
    let problems = c.notes.iter().filter(|n| n.starts_with("Skipped")).count();
    assert!(problems <= 16, "{:?}", c.notes);
}

#[test]
fn synthetic_prefixes_list_only_members_inside_them() {
    let image = synthetic().build();
    let whole = parse(&image);
    let volume_size = image.len() - 512;
    for end in prefix_ends(image.len(), 4096, 997, 4096) {
        let prefix = &image[..end];
        match ntfs::detect(prefix).map(|layout| ntfs::parse_container(prefix, layout)) {
            None => assert!(end < 512, "prefix {end}"),
            Some(Ok(c)) => {
                assert_eq!(
                    has_note(&c, "Volume truncated"),
                    end < volume_size,
                    "prefix {end}"
                );
                assert_members_inside("synthetic", &whole, &c, end);
            }
            Some(Err(e)) => assert!(
                e.to_string().contains("Truncated volume"),
                "prefix {end}: {e}"
            ),
        }
    }
    // A prefix with the MFT and the first files lists those files.
    let c = parse(&image[..0x1d000]);
    assert!(labels(&c).contains(&"/payload.elf".to_string()));
}

#[test]
fn ida_inputs_hold_no_ntfs_volume_or_parse_without_panicking() {
    // IDA Pro's test inputs cannot be committed; IDA_INPUT_DIR names them.
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR is not set; skipped");
        return;
    };
    let mut volumes = 0;
    let mut pending = vec![std::path::PathBuf::from(dir)];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in std::fs::read_dir(&path)
                .expect("readable directory")
                .flatten()
            {
                pending.push(entry.path());
            }
            continue;
        }
        // The boot sector decides; only volumes are read whole.
        let mut head = [0u8; 512];
        let read = std::fs::File::open(&path)
            .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut head));
        if read.is_err() || ntfs::detect(&head).is_none() {
            continue;
        }
        volumes += 1;
        let data = std::fs::read(&path).expect("readable volume");
        match ntfs::parse_container(&data, Layout::Ntfs) {
            Ok(c) => eprintln!("{}: {} members", path.display(), c.children.len()),
            Err(e) => eprintln!("{}: {e}", path.display()),
        }
        let _ = classify(&data);
    }
    eprintln!("{volumes} NTFS volumes in IDA_INPUT_DIR");
}

#[test]
fn a_local_ntfs_image_parses_without_panicking() {
    // NTFS images from this machine cannot be committed; ZRAX_NTFS_IMAGE
    // names one.
    let Some(path) = std::env::var_os("ZRAX_NTFS_IMAGE") else {
        eprintln!("ZRAX_NTFS_IMAGE is not set; skipped");
        return;
    };
    let data = std::fs::read(&path).expect("ZRAX_NTFS_IMAGE is readable");
    let c = parse(&data);
    eprintln!("{} members: {:?}", c.children.len(), labels(&c));
    for note in &c.notes {
        eprintln!("note: {note}");
    }
    let payload = classify(&data);
    assert_eq!(payload.format.format, FileFormat::Ntfs);
}
