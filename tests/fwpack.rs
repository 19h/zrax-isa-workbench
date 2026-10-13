//! Firmware package wrappers: synthetic MikroTik NPK packages, Ubiquiti
//! firmware images and ChromeOS kernel partitions built from the documented
//! layouts (tenable/routeros `ls_npk`, MikroTikPatch `npk.py`, `OpenWrt`
//! firmware-utils `fw.h`, vboot `2struct.h` and futility), covering
//! children with stored and decoded ranges, verified CRCs and digests,
//! corrupted fields, and truncation and mutation sweeps.

use sha2::{Digest, Sha512};
use zrax::formats::checksum::{crc32, Sha1};
use zrax::formats::container::{self, Container, Kind};
use zrax::formats::fwpack::Layout;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// A 256-byte x86-64 ELF header and filler (see
/// `tests/fixtures/compressed/README.md`).
const PAYLOAD_ELF: &[u8] = include_bytes!("fixtures/compressed/payload.elf");

/// `payload.elf` compressed with `gzip -n -9`.
const PAYLOAD_ELF_GZ: &[u8] = include_bytes!("fixtures/compressed/payload.elf.gz");

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    container::parse(data, Kind::FwPack(layout)).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    container::parse(data, Kind::FwPack(layout))
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

fn metadata_text(p: &DetectionPayload, key: &str) -> String {
    p.metadata
        .iter()
        .find(|m| m.key == zrax::MetadataKey::Custom(key.into()))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
        .to_string()
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put_le16(data: &mut [u8], at: usize, value: u16) {
    put(data, at, &value.to_le_bytes());
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_le_bytes());
}

fn put_le64(data: &mut [u8], at: usize, value: u64) {
    put(data, at, &value.to_le_bytes());
}

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_be_bytes());
}

fn size32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).expect("fixture fits in 32 bits")
}

/// `value` rounded up to a multiple of `alignment`.
fn align(value: usize, alignment: usize) -> usize {
    match value % alignment {
        0 => value,
        rest => value + alignment - rest,
    }
}

/// Every prefix shorter than `end` must fail to parse as `layout`.
fn parse_truncation_sweep(data: &[u8], layout: Layout, end: usize) {
    for cut in 0..end {
        assert!(
            container::parse(&data[..cut], Kind::FwPack(layout)).is_err(),
            "prefix of {cut} B parses as {layout:?}"
        );
    }
}

/// Every `step`-th prefix and the prefixes within 2 bytes of each boundary
/// must not be classified as `format`.
fn truncation_sweep(data: &[u8], format: FileFormat, step: usize, boundaries: &[usize]) {
    let near = boundaries
        .iter()
        .flat_map(|b| b.saturating_sub(2)..b.saturating_add(3));
    for end in (0..data.len()).step_by(step).chain(near) {
        if end >= data.len() {
            continue;
        }
        let claimed = detect_payload(&data[..end], &ClassifierOptions::new())
            .is_ok_and(|p| p.format.format == format);
        assert!(!claimed, "prefix of {end} B still classifies as {format}");
    }
}

/// Single-byte mutations (0x00, 0xFF, bit flip) of every byte in `header`
/// and of every `step`-th byte, parsed and classified without panicking.
fn mutation_sweep(data: &[u8], layout: Layout, header: std::ops::Range<usize>, step: usize) {
    let positions = header.chain((0..data.len()).step_by(step));
    for i in positions.filter(|i| *i < data.len()) {
        for value in [0x00, 0xff, data[i] ^ 0x01] {
            let mut mutated = data.to_vec();
            mutated[i] = value;
            let _ = container::parse(&mutated, Kind::FwPack(layout));
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

// --- Shared payloads --------------------------------------------------------

/// A 52-byte ELF32 little-endian header: `e_type` 2, `e_machine` 40 (Arm),
/// `e_version` 1, `e_ehsize` 52, `e_phentsize` 32, `e_shentsize` 40.
fn arm_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 52];
    put(&mut elf, 0, b"\x7fELF\x01\x01\x01");
    put_le16(&mut elf, 16, 2);
    put_le16(&mut elf, 18, 40);
    put_le32(&mut elf, 20, 1);
    put_le16(&mut elf, 40, 52);
    put_le16(&mut elf, 42, 32);
    put_le16(&mut elf, 46, 40);
    elf
}

/// SquashFS metadata block header flag: the block is stored uncompressed.
const METADATA_UNCOMPRESSED: u16 = 0x8000;

/// An empty SquashFS 4.0 image. Superblock: magic `hsqs`, 1 inode, mkfs
/// time 0, block size 128 KiB, 0 fragments, compressor 1 (gzip), block log
/// 17, flags 0, 1 id, version 4.0, root inode reference 0, bytes used, id
/// table index start, no xattr table, inode table at 96, directory table at
/// 130, no fragment or export table. The inode table is one uncompressed
/// metadata block (size | 0x8000) holding the root directory (basic
/// directory, type 1: mode 0755, uid and gid index 0, mtime 0, inode number
/// 1, start block 0, link count 2, file size 3 for an empty listing, offset
/// 0, parent inode 2). The directory table is empty; the id table is one
/// metadata block with id 0, then its index. Zero padding to 4 KiB.
fn empty_squashfs() -> Vec<u8> {
    const NO_TABLE: u64 = u64::MAX;
    let mut image = vec![0u8; 96];
    let mut inode = Vec::new();
    inode.extend_from_slice(&1u16.to_le_bytes());
    inode.extend_from_slice(&0o755u16.to_le_bytes());
    inode.extend_from_slice(&[0; 4]);
    inode.extend_from_slice(&0u32.to_le_bytes());
    inode.extend_from_slice(&1u32.to_le_bytes());
    inode.extend_from_slice(&0u32.to_le_bytes());
    inode.extend_from_slice(&2u32.to_le_bytes());
    inode.extend_from_slice(&3u16.to_le_bytes());
    inode.extend_from_slice(&0u16.to_le_bytes());
    inode.extend_from_slice(&2u32.to_le_bytes());
    let inode_table = image.len() as u64;
    image.extend_from_slice(&(inode.len() as u16 | METADATA_UNCOMPRESSED).to_le_bytes());
    image.extend_from_slice(&inode);
    let directory_table = image.len() as u64;
    let id_block = image.len() as u64;
    image.extend_from_slice(&(4u16 | METADATA_UNCOMPRESSED).to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes());
    let id_index = image.len() as u64;
    image.extend_from_slice(&id_block.to_le_bytes());
    let bytes_used = image.len() as u64;
    put(&mut image, 0, b"hsqs");
    put_le32(&mut image, 4, 1);
    put_le32(&mut image, 12, 128 << 10);
    put_le16(&mut image, 20, 1);
    put_le16(&mut image, 22, 17);
    put_le16(&mut image, 26, 1);
    put_le16(&mut image, 28, 4);
    put_le64(&mut image, 32, 0);
    put_le64(&mut image, 40, bytes_used);
    put_le64(&mut image, 48, id_index);
    put_le64(&mut image, 56, NO_TABLE);
    put_le64(&mut image, 64, inode_table);
    put_le64(&mut image, 72, directory_table);
    put_le64(&mut image, 80, NO_TABLE);
    put_le64(&mut image, 88, NO_TABLE);
    image.resize(4096, 0);
    image
}

#[test]
fn the_empty_squashfs_fixture_is_a_squashfs_image() {
    let p = classify(&empty_squashfs());
    assert_eq!(p.format.format, FileFormat::Squashfs);
}

// --- MikroTik NPK -----------------------------------------------------------

const NPK_MAGIC: u32 = 0xbad0_f11e;
const NAME_INFO: u16 = 0x01;
const DESCRIPTION: u16 = 0x02;
const FILE_CONTAINER: u16 = 0x04;
const SIGNATURE: u16 = 0x09;
const ARCHITECTURE: u16 = 0x10;
const PKG_INFO: u16 = 0x12;
const PKG_FEATURES: u16 = 0x14;
const SQUASHFS: u16 = 0x15;
const NULL_BLOCK: u16 = 0x16;

/// `st_mode` values: directory 0755, regular file 0755, symbolic link 0777.
const MODE_DIRECTORY: u16 = 0x41ed;
const MODE_FILE: u16 = 0x81ed;
const MODE_SYMLINK: u16 = 0xa1ff;

/// Version bytes revision, build code (102: final), minor, major: 7.15.1.
const VERSION_7_15_1: [u8; 4] = [1, 102, 15, 7];

/// A part: type (2), payload size (4), payload.
fn npk_part(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut part = kind.to_le_bytes().to_vec();
    part.extend_from_slice(&size32(payload).to_le_bytes());
    part.extend_from_slice(payload);
    part
}

/// `NAME_INFO` or `PKG_INFO` payload: name NUL-padded to 16, version bytes,
/// build time, then 12 zero bytes (`NpkNameInfo`, 36 B).
fn info(name: &str, version: [u8; 4], build_time: u32) -> Vec<u8> {
    let mut payload = vec![0u8; 16];
    put(&mut payload, 0, name.as_bytes());
    payload.extend_from_slice(&version);
    payload.extend_from_slice(&build_time.to_le_bytes());
    payload.extend_from_slice(&[0; 12]);
    payload
}

/// A file container entry: `st_mode` (low byte permissions, high byte file
/// type), user and group (6, zero), modification time, version bytes,
/// creation time, an unknown word, data size, name size, name, data.
fn file_entry(mode: u16, name: &str, contents: &[u8]) -> Vec<u8> {
    let mut entry = mode.to_le_bytes().to_vec();
    entry.extend_from_slice(&[0; 6]);
    entry.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    entry.extend_from_slice(&VERSION_7_15_1);
    entry.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    entry.extend_from_slice(&0u32.to_le_bytes());
    entry.extend_from_slice(&size32(contents).to_le_bytes());
    entry.extend_from_slice(&u16::try_from(name.len()).expect("short name").to_le_bytes());
    entry.extend_from_slice(name.as_bytes());
    entry.extend_from_slice(contents);
    entry
}

/// The file container of the test package, zlib-compressed: directory
/// `bin`, `bin/payload.elf` (x86-64 ELF), the symbolic link `bin/link`
/// and the text file `etc/readme`.
fn file_container() -> Vec<u8> {
    let mut entries = file_entry(MODE_DIRECTORY, "bin", b"");
    entries.extend_from_slice(&file_entry(MODE_FILE, "bin/payload.elf", PAYLOAD_ELF));
    entries.extend_from_slice(&file_entry(MODE_SYMLINK, "bin/link", b"payload.elf"));
    entries.extend_from_slice(&file_entry(0x81a4, "etc/readme", b"zrax npk fixture\n"));
    miniz_oxide::deflate::compress_to_vec_zlib(&entries, 6)
}

/// A signature part for the parts before it: the SHA-1 of their headers and
/// payloads and of the signature part's own header, a zero KCDSA signature
/// (48 B) and a zero EdDSA signature (64 B).
fn signature_part(signed: &[Vec<u8>]) -> Vec<u8> {
    let size: u32 = 20 + 48 + 64;
    let mut header = SIGNATURE.to_le_bytes().to_vec();
    header.extend_from_slice(&size.to_le_bytes());
    let mut sha1 = Sha1::new();
    for part in signed {
        sha1.update(part);
    }
    sha1.update(&header);
    let mut part = header;
    part.extend_from_slice(&sha1.finish());
    part.extend_from_slice(&[0; 48 + 64]);
    part
}

/// Magic, the size of everything after the size field, the parts.
fn npk(parts: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = parts.concat();
    let mut package = NPK_MAGIC.to_le_bytes().to_vec();
    package.extend_from_slice(&size32(&body).to_le_bytes());
    package.extend_from_slice(&body);
    package
}

/// The parts of the test package before its signature: name and version,
/// description, architecture, file container, zero padding and SquashFS
/// image.
fn package_parts() -> Vec<Vec<u8>> {
    vec![
        npk_part(NAME_INFO, &info("zrax-test", VERSION_7_15_1, 1_700_000_000)),
        npk_part(DESCRIPTION, b"zrax synthetic package\0"),
        npk_part(ARCHITECTURE, b"x86\0"),
        npk_part(FILE_CONTAINER, &file_container()),
        npk_part(NULL_BLOCK, &[0; 10]),
        npk_part(SQUASHFS, &empty_squashfs()),
    ]
}

/// The test package with its signature part.
fn signed_package() -> Vec<u8> {
    let mut parts = package_parts();
    parts.push(signature_part(&parts));
    npk(&parts)
}

/// File offset of the payload of part `index` in `npk(parts)`.
fn part_payload_offset(parts: &[Vec<u8>], index: usize) -> usize {
    8 + parts[..index].iter().map(Vec::len).sum::<usize>() + 6
}

#[test]
fn npk_packages_list_files_and_the_squashfs_image_with_stored_and_decoded_ranges() {
    let parts = package_parts();
    let package = signed_package();
    assert_eq!(
        detected_format(&package),
        Some(FileFormat::MikrotikNpk),
        "detected"
    );
    let c = parse(&package, Layout::MikrotikNpk);
    assert_eq!(labels(&c), ["bin/payload.elf", "SquashFS image"]);
    assert_eq!(c.target, None, "the architecture part is not ISA evidence");
    assert!(has_note(
        &c,
        "MikroTik NPK: 7 parts; package: zrax-test 7.15.1"
    ));
    assert!(has_note(
        &c,
        "Package zrax-test: SHA-1 digest verified; KCDSA (48 B) and EdDSA (64 B) signatures present, not verified"
    ));
    assert!(has_note(
        &c,
        "4 entries: 2 files, 1 directory, 1 symbolic link"
    ));
    assert!(has_note(
        &c,
        "1 of 2 files are in a recognized format and listed"
    ));
    assert!(has_note(&c, "Architecture part names x86"));

    let p = classify(&package);
    assert_eq!(p.format.format, FileFormat::MikrotikNpk);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("MikroTik NPK package")
    );
    assert_eq!(p.primary.isa, Isa::X86_64);
    let file = slice(&p, "bin/payload.elf");
    let container_offset = part_payload_offset(&parts, 3);
    assert_eq!(file.isa, Isa::X86_64);
    assert_eq!(
        (file.offset, file.size),
        (container_offset as u64, parts[3].len() as u64 - 6)
    );
    let decoded = file.decoded.as_ref().expect("decoded range");
    assert_eq!(
        (decoded.transform.as_str(), decoded.offset, decoded.size),
        ("zlib", 0, 256)
    );
    let squashfs = slice(&p, "SquashFS image");
    assert_eq!(squashfs.offset, part_payload_offset(&parts, 5) as u64);
    assert_eq!(squashfs.size, 4096);
    assert!(squashfs.decoded.is_none());
    assert_eq!(metadata_text(&p, "npk_package_name"), "zrax-test");
    assert_eq!(metadata_text(&p, "npk_version"), "7.15.1");
    assert_eq!(metadata_text(&p, "npk_architecture"), "x86");
    assert_eq!(
        metadata_text(&p, "npk_description"),
        "zrax synthetic package"
    );
}

#[test]
fn npk_bundles_prefix_member_labels_and_digest_each_package_from_its_name_part() {
    let mut parts = vec![
        npk_part(PKG_INFO, &info("routeros", VERSION_7_15_1, 1)),
        npk_part(PKG_FEATURES, b""),
    ];
    for name in ["system", "extra"] {
        let member = vec![
            npk_part(NAME_INFO, &info(name, VERSION_7_15_1, 1)),
            npk_part(FILE_CONTAINER, &file_container()),
        ];
        let signature = signature_part(&member);
        parts.extend(member);
        parts.push(signature);
    }
    let package = npk(&parts);
    let c = parse(&package, Layout::MikrotikNpk);
    assert_eq!(
        labels(&c),
        ["system/bin/payload.elf", "extra/bin/payload.elf"]
    );
    assert!(has_note(
        &c,
        "bundle routeros 7.15.1; packages: system 7.15.1, extra 7.15.1"
    ));
    assert!(has_note(&c, "Package system: SHA-1 digest verified"));
    assert!(has_note(&c, "Package extra: SHA-1 digest verified"));
    let p = classify(&package);
    assert_eq!(metadata_text(&p, "npk_package_name"), "routeros");
    assert_eq!(slice(&p, "extra/bin/payload.elf").isa, Isa::X86_64);
}

#[test]
fn npk_digest_mismatches_are_noted_and_signatures_never_verified() {
    let mut parts = package_parts();
    let mut signature = signature_part(&parts);
    signature[6] ^= 1;
    parts.push(signature);
    let package = npk(&parts);
    let c = parse(&package, Layout::MikrotikNpk);
    assert!(has_note(
        &c,
        "SHA-1 digest does not match the parts before it"
    ));
    let mut short = package_parts();
    short.push(npk_part(SIGNATURE, &[0; 8]));
    let package = npk(&short);
    let c = parse(&package, Layout::MikrotikNpk);
    assert!(has_note(&c, "too few for a SHA-1 digest; not verified"));
}

#[test]
fn npk_undecodable_containers_and_non_squashfs_parts_are_opaque() {
    let mut container = file_container();
    let last = container.len() - 1;
    container[last] ^= 0xff;
    let parts = vec![
        npk_part(NAME_INFO, &info("zrax-test", VERSION_7_15_1, 1)),
        npk_part(FILE_CONTAINER, &container),
        npk_part(SQUASHFS, PAYLOAD_ELF),
    ];
    let package = npk(&parts);
    let c = parse(&package, Layout::MikrotikNpk);
    assert_eq!(labels(&c), ["File container", "SquashFS image"]);
    assert!(c.children.iter().all(|child| child.opaque));
    assert!(has_note(&c, "does not decode as zlib"));
    assert!(has_note(&c, "does not start with a SquashFS magic"));
    let p = classify(&package);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{:?}", p.primary);
}

#[test]
fn npk_structure_errors_name_the_field() {
    let package = signed_package();
    let mut short = package.clone();
    put_le32(&mut short, 4, size32(&package));
    assert!(parse_error(&short, Layout::MikrotikNpk).contains("Truncated NPK package"));

    let mut overrun = npk(&[npk_part(NAME_INFO, &info("a", VERSION_7_15_1, 1))]);
    put_le32(&mut overrun, 10, 37);
    assert_eq!(
        parse_error(&overrun, Layout::MikrotikNpk),
        "Firmware package parse error: Truncated NPK part 0x01 at 0x8: 37 B declared, 36 B left in the package"
    );

    let mut trailing = package.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing, Layout::MikrotikNpk)
        .contains("Unexpected 4 B after the NPK package"));
    let mut padded = package.clone();
    padded.extend_from_slice(&[0xff; 64]);
    parse(&padded, Layout::MikrotikNpk);

    let mut cut_header = npk(&[npk_part(NAME_INFO, &info("a", VERSION_7_15_1, 1))]);
    cut_header.extend_from_slice(&[0; 3]);
    let declared = size32(&cut_header) - 8;
    put_le32(&mut cut_header, 4, declared);
    assert!(parse_error(&cut_header, Layout::MikrotikNpk).contains("Truncated NPK part header"));
}

#[test]
fn npk_detection_needs_a_documented_first_part_that_fits() {
    let package = signed_package();
    let mut undocumented = package.clone();
    put_le16(&mut undocumented, 8, 0x0b);
    assert_ne!(
        detected_format(&undocumented),
        Some(FileFormat::MikrotikNpk)
    );
    let mut oversized = package.clone();
    put_le32(&mut oversized, 10, size32(&package));
    assert_ne!(detected_format(&oversized), Some(FileFormat::MikrotikNpk));
}

#[test]
fn npk_prefixes_and_mutations_do_not_claim_the_package() {
    let package = signed_package();
    parse_truncation_sweep(&package, Layout::MikrotikNpk, package.len());
    truncation_sweep(&package, FileFormat::MikrotikNpk, 97, &[8, 14, 50]);
    mutation_sweep(&package, Layout::MikrotikNpk, 0..64, 41);
}

// --- Ubiquiti ---------------------------------------------------------------

/// A Ubiquiti header: magic, version NUL-padded to 256, the CRC-32 of the
/// magic and version (big-endian), a zero pad.
fn ubnt_header(magic: &[u8; 4], version: &str) -> Vec<u8> {
    let mut header = vec![0u8; 268];
    put(&mut header, 0, magic);
    put(&mut header, 4, version.as_bytes());
    let crc = crc32(&header[..260]);
    put_be32(&mut header, 260, crc);
    header
}

/// One `PART` or `EXEC` record's fields.
struct UbntRecord<'a> {
    magic: &'a [u8; 4],
    name: &'a str,
    index: u32,
    memory_address: u32,
    base_address: u32,
    entry_address: u32,
    partition_size: u32,
    data: &'a [u8],
}

/// A record: magic, name NUL-padded to 16, 12 pad bytes, memory address,
/// index, flash base address, entry address, data size, partition size
/// (big-endian), the data, the CRC-32 of the 56-byte header and data, a
/// zero pad.
fn ubnt_record(record: &UbntRecord<'_>) -> Vec<u8> {
    let mut bytes = vec![0u8; 56];
    put(&mut bytes, 0, record.magic);
    put(&mut bytes, 4, record.name.as_bytes());
    put_be32(&mut bytes, 32, record.memory_address);
    put_be32(&mut bytes, 36, record.index);
    put_be32(&mut bytes, 40, record.base_address);
    put_be32(&mut bytes, 44, record.entry_address);
    put_be32(&mut bytes, 48, size32(record.data));
    put_be32(&mut bytes, 52, record.partition_size);
    bytes.extend_from_slice(record.data);
    let crc = crc32(&bytes);
    bytes.extend_from_slice(&crc.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

/// The kernel record of `mkfwimage -B XM`: index 1, flash base
/// 0x9F050000, load and entry address 0x80002000.
fn kernel_record(data: &[u8]) -> UbntRecord<'_> {
    UbntRecord {
        magic: b"PART",
        name: "kernel",
        index: 1,
        memory_address: 0x8000_2000,
        base_address: 0x9f05_0000,
        entry_address: 0x8000_2000,
        partition_size: 0x10_0000,
        data,
    }
}

/// The rootfs record: index 2, after the kernel's flash space.
fn rootfs_record(data: &[u8]) -> UbntRecord<'_> {
    UbntRecord {
        magic: b"PART",
        name: "rootfs",
        index: 2,
        memory_address: 0,
        base_address: 0x9f15_0000,
        entry_address: 0,
        partition_size: 0x66_0000,
        data,
    }
}

/// Header, records, then `END.` with the CRC-32 of everything before it and
/// a zero pad.
fn ubnt_image(magic: &[u8; 4], records: &[UbntRecord<'_>]) -> Vec<u8> {
    let mut image = ubnt_header(magic, "XM.ar7240.v6.0.0-zrax");
    for record in records {
        image.extend_from_slice(&ubnt_record(record));
    }
    let crc = crc32(&image);
    image.extend_from_slice(b"END.");
    image.extend_from_slice(&crc.to_be_bytes());
    image.extend_from_slice(&[0; 4]);
    image
}

/// Header, records, then `ENDS`, a 256-byte RSA signature (zero here, as
/// `mkfwimage` writes it) and a zero pad.
fn signed_ubnt_image(magic: &[u8; 4], records: &[UbntRecord<'_>]) -> Vec<u8> {
    let mut image = ubnt_header(magic, "WA.ar934x.v8.7.4-zrax");
    for record in records {
        image.extend_from_slice(&ubnt_record(record));
    }
    image.extend_from_slice(b"ENDS");
    image.extend_from_slice(&[0; 256 + 4]);
    image
}

#[test]
fn ubiquiti_images_list_partitions_with_verified_crcs() {
    let squashfs = empty_squashfs();
    let image = ubnt_image(
        b"UBNT",
        &[kernel_record(PAYLOAD_ELF), rootfs_record(&squashfs)],
    );
    assert_eq!(detected_format(&image), Some(FileFormat::UbiquitiFw));
    let c = parse(&image, Layout::UbiquitiFirmware);
    assert_eq!(labels(&c), ["kernel", "rootfs"]);
    assert_eq!(c.target, None);
    assert!(has_note(
        &c,
        "Ubiquiti firmware image: header magic UBNT; version XM.ar7240.v6.0.0-zrax; header CRC-32 verified"
    ));
    assert!(has_note(
        &c,
        "kernel: partition 1, 256 B of a 1 MiB partition at flash base 0x9F050000; load address 0x80002000; entry 0x80002000; CRC-32 verified"
    ));
    assert!(has_note(&c, "2 records; end record at 0x"));
    assert!(has_note(&c, "image CRC-32 verified"));

    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::UbiquitiFw);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let kernel = slice(&p, "kernel");
    assert_eq!((kernel.offset, kernel.size), (268 + 56, 256));
    let rootfs = slice(&p, "rootfs");
    assert_eq!(rootfs.offset, (268 + 56 + 256 + 8 + 56) as u64);
    assert_eq!(rootfs.size, 4096);
    assert_eq!(metadata_text(&p, "ubnt_magic"), "UBNT");
    assert_eq!(metadata_text(&p, "ubnt_version"), "XM.ar7240.v6.0.0-zrax");
}

#[test]
fn ubiquiti_signed_images_and_exec_records_are_listed_without_verification() {
    let arm = arm_elf();
    let exec = UbntRecord {
        magic: b"EXEC",
        name: "script",
        index: 3,
        memory_address: 0,
        base_address: 0,
        entry_address: 0,
        partition_size: 0x1000,
        data: PAYLOAD_ELF,
    };
    let image = signed_ubnt_image(b"OPEN", &[kernel_record(&arm), exec]);
    let c = parse(&image, Layout::UbiquitiFirmware);
    assert_eq!(labels(&c), ["kernel", "script"]);
    assert!(!c.children[0].opaque);
    assert!(c.children[1].opaque, "EXEC data has no documented meaning");
    assert!(has_note(&c, "script: additional data 3"));
    assert!(has_note(
        &c,
        "RSA signature (256 B) present, not verified; the image has no overall CRC-32"
    ));
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::Arm);
}

#[test]
fn ubiquiti_crc_and_structure_errors_name_the_field() {
    let image = ubnt_image(b"UBNT", &[kernel_record(PAYLOAD_ELF)]);
    let mut header = image.clone();
    header[10] ^= 1;
    assert!(
        parse_error(&header, Layout::UbiquitiFirmware).contains("Invalid Ubiquiti header CRC-32")
    );
    let mut part = image.clone();
    part[268 + 56 + 100] ^= 1;
    assert!(parse_error(&part, Layout::UbiquitiFirmware)
        .contains("Invalid CRC-32 of Ubiquiti partition kernel at 0x10C"));
    let mut end = image.clone();
    let end_crc = image.len() - 8;
    end[end_crc] ^= 1;
    assert!(parse_error(&end, Layout::UbiquitiFirmware).contains("Invalid Ubiquiti image CRC-32"));
    let mut pad = image.clone();
    let end_pad = image.len() - 1;
    pad[end_pad] = 1;
    assert!(parse_error(&pad, Layout::UbiquitiFirmware).contains("end record pad"));
    let mut unknown = image.clone();
    let end_magic = image.len() - 12;
    put(&mut unknown, end_magic, b"XYZW");
    assert_eq!(
        parse_error(&unknown, Layout::UbiquitiFirmware),
        "Firmware package parse error: Unknown Ubiquiti record magic XYZW at 0x24C"
    );
    let missing_end = &image[..image.len() - 12];
    assert!(parse_error(missing_end, Layout::UbiquitiFirmware)
        .contains("Truncated Ubiquiti record magic at 0x24C"));
    let mut trailing = image.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing, Layout::UbiquitiFirmware).contains("Unexpected 4 B"));
    let mut magic = image.clone();
    put(&mut magic, 0, b"OPEX");
    assert_ne!(detected_format(&magic), Some(FileFormat::UbiquitiFw));
}

#[test]
fn ubiquiti_prefixes_and_mutations_do_not_claim_the_image() {
    let squashfs = empty_squashfs();
    let image = ubnt_image(
        b"GEOS",
        &[kernel_record(PAYLOAD_ELF), rootfs_record(&squashfs)],
    );
    parse_truncation_sweep(&image, Layout::UbiquitiFirmware, image.len());
    truncation_sweep(&image, FileFormat::UbiquitiFw, 101, &[268, 324, 580, 588]);
    mutation_sweep(&image, Layout::UbiquitiFirmware, 0..8, 37);
    mutation_sweep(&image, Layout::UbiquitiFirmware, 256..340, 997);
}

// --- ChromeOS kernel partitions ----------------------------------------------

/// `VB2_KEYBLOCK_FLAG_DEVELOPER_0 | VB2_KEYBLOCK_FLAG_RECOVERY_0`.
const FLAGS_NORMAL: u32 = 0x5;

/// `VB2_ALG_RSA2048_SHA256`.
const ALG_RSA2048_SHA256: u32 = 4;

/// Data key bytes (real keys are RSA moduli; any bytes do here).
const DATA_KEY: [u8; 16] = *b"zrax-data-key-16";

/// RSA-2048 signatures are 256 B.
const RSA2048_SIGNATURE: usize = 256;

/// A `vb2_signature` at `at`: data offset from the structure, reserved,
/// data size, reserved, signed size, reserved.
fn put_signature(data: &mut [u8], at: usize, data_at: usize, size: usize, signed: usize) {
    put_le32(data, at, u32::try_from(data_at - at).expect("small"));
    put_le32(data, at + 8, u32::try_from(size).expect("small"));
    put_le32(data, at + 16, u32::try_from(signed).expect("small"));
}

/// A keyblock as `vb2_create_keyblock` lays it out: the 112-byte header
/// (`CHROMEOS`, version 2.1, keyblock size, the signature at 24, the hash
/// at 48, flags at 72, the data key at 80: key offset from the key
/// structure, size, algorithm, version 1), the key data, the SHA-512 of the
/// header and key, then a zero RSA-2048 signature over the same bytes.
fn keyblock(flags: u32) -> Vec<u8> {
    let key_at = 112;
    let hash_at = key_at + DATA_KEY.len();
    let signature_at = hash_at + 64;
    let size = signature_at + RSA2048_SIGNATURE;
    let mut block = vec![0u8; size];
    put(&mut block, 0, b"CHROMEOS");
    put_le32(&mut block, 8, 2);
    put_le32(&mut block, 12, 1);
    put_le32(&mut block, 16, u32::try_from(size).expect("small"));
    put_signature(&mut block, 24, signature_at, RSA2048_SIGNATURE, hash_at);
    put_signature(&mut block, 48, hash_at, 64, hash_at);
    put_le32(&mut block, 72, flags);
    put_le32(&mut block, 80, u32::try_from(key_at - 80).expect("small"));
    put_le32(&mut block, 88, DATA_KEY.len() as u32);
    put_le32(&mut block, 96, ALG_RSA2048_SHA256);
    put_le32(&mut block, 104, 1);
    put(&mut block, key_at, &DATA_KEY);
    let digest = Sha512::digest(&block[..hash_at]);
    put(&mut block, hash_at, digest.as_slice());
    block
}

/// Kernel preamble fields.
struct PreambleFields {
    minor: u32,
    kernel_version: u32,
    body_load_address: u64,
    bootloader_address: u64,
    bootloader_size: u32,
    body_size: usize,
    vmlinuz_header_address: u64,
    vmlinuz_header_size: u32,
    flags: u32,
    /// Size the preamble is padded to (futility pads the vblock to 64 KiB).
    padded_size: usize,
}

/// A kernel preamble as `vb2_create_kernel_preamble` lays it out: the
/// 116-byte header (preamble size, the preamble signature at 8, version
/// 2.minor at 32, kernel version, body load address, bootloader address
/// and size, the body signature at 72, vmlinuz header address and size,
/// flags), the body signature data, the preamble signature data over the
/// header and body signature, then zero padding.
fn preamble(fields: &PreambleFields) -> Vec<u8> {
    let body_signature_at = 116;
    let signature_at = body_signature_at + RSA2048_SIGNATURE;
    let mut block = vec![0u8; fields.padded_size];
    put_le32(
        &mut block,
        0,
        u32::try_from(fields.padded_size).expect("small"),
    );
    put_signature(&mut block, 8, signature_at, RSA2048_SIGNATURE, signature_at);
    put_le32(&mut block, 32, 2);
    put_le32(&mut block, 36, fields.minor);
    put_le32(&mut block, 40, fields.kernel_version);
    put_le64(&mut block, 48, fields.body_load_address);
    put_le64(&mut block, 56, fields.bootloader_address);
    put_le32(&mut block, 64, fields.bootloader_size);
    put_signature(
        &mut block,
        72,
        body_signature_at,
        RSA2048_SIGNATURE,
        fields.body_size,
    );
    put_le64(&mut block, 96, fields.vmlinuz_header_address);
    put_le32(&mut block, 104, fields.vmlinuz_header_size);
    put_le32(&mut block, 112, fields.flags);
    block
}

/// `futility`'s page size (`CROS_ALIGN`).
const PAGE: usize = 4096;

/// The default body load address (`CROS_32BIT_ENTRY_ADDR`).
const BODY_LOAD_ADDRESS: u64 = 0x10_0000;

/// A kernel blob in `CreateKernelBlob` order and where its parts lie.
struct Blob {
    bytes: Vec<u8>,
    bootloader_offset: usize,
    bootloader_size: usize,
    vmlinuz_header_offset: usize,
    vmlinuz_header_size: usize,
}

/// The kernel rounded up to 4 KiB, the command line page, the boot
/// parameter page, the bootloader rounded up to 4 KiB, then the vmlinuz
/// header; the whole blob rounded up to 4 KiB.
fn kernel_blob(
    kernel: &[u8],
    command_line: &str,
    bootloader: &[u8],
    vmlinuz_header: &[u8],
) -> Blob {
    let mut bytes = kernel.to_vec();
    bytes.resize(align(kernel.len(), PAGE), 0);
    let config = bytes.len();
    bytes.resize(config + 2 * PAGE, 0);
    put(&mut bytes, config, command_line.as_bytes());
    let bootloader_offset = bytes.len();
    bytes.extend_from_slice(bootloader);
    bytes.resize(align(bytes.len(), PAGE), 0);
    let bootloader_size = bytes.len() - bootloader_offset;
    let vmlinuz_header_offset = bytes.len();
    bytes.extend_from_slice(vmlinuz_header);
    bytes.resize(align(bytes.len(), PAGE), 0);
    Blob {
        bytes,
        bootloader_offset,
        bootloader_size: if bootloader.is_empty() {
            0
        } else {
            bootloader_size
        },
        vmlinuz_header_offset,
        vmlinuz_header_size: vmlinuz_header.len(),
    }
}

/// Preamble fields for `blob` with version 2.2 and a 64 KiB vblock.
fn fields_for(blob: &Blob, keyblock_size: usize) -> PreambleFields {
    let address = |offset: usize| BODY_LOAD_ADDRESS + offset as u64;
    PreambleFields {
        minor: 2,
        kernel_version: 1,
        body_load_address: BODY_LOAD_ADDRESS,
        bootloader_address: address(blob.bootloader_offset),
        bootloader_size: u32::try_from(blob.bootloader_size).expect("small"),
        body_size: blob.bytes.len(),
        vmlinuz_header_address: if blob.vmlinuz_header_size == 0 {
            0
        } else {
            address(blob.vmlinuz_header_offset)
        },
        vmlinuz_header_size: u32::try_from(blob.vmlinuz_header_size).expect("small"),
        flags: 0,
        padded_size: (64 << 10) - keyblock_size,
    }
}

/// Keyblock, preamble and blob.
fn kernel_partition(blob: &Blob, fields: &PreambleFields) -> Vec<u8> {
    let mut partition = keyblock(FLAGS_NORMAL);
    partition.extend_from_slice(&preamble(fields));
    partition.extend_from_slice(&blob.bytes);
    partition
}

/// An x86 `bzImage`: one setup sector after the boot sector (setup code
/// ends at 0x400), boot flag 0xAA55, `HdrS`, protocol 2.15, loadflags 1,
/// `XLF_KERNEL_64`, and the payload 0x100 B into the protected-mode code:
/// the gzip-compressed x86-64 ELF.
fn bzimage() -> Vec<u8> {
    let mut image = vec![0u8; 0x500];
    image[0x1f1] = 1;
    put_le16(&mut image, 0x1fe, 0xaa55);
    put(&mut image, 0x202, b"HdrS");
    put_le16(&mut image, 0x206, 0x020f);
    image[0x211] = 1;
    put_le16(&mut image, 0x236, 1);
    put_le32(&mut image, 0x248, 0x100);
    put_le32(&mut image, 0x24c, size32(PAYLOAD_ELF_GZ));
    image.extend_from_slice(PAYLOAD_ELF_GZ);
    image
}

/// The setup code `futility` strips from a `bzImage`: `(setup_sects + 1)
/// * 512` bytes.
const SETUP_SIZE: usize = 0x400;

/// A kernel partition and the blob it holds.
struct Partition {
    bytes: Vec<u8>,
    blob: Blob,
}

/// The x86 partition `vbutil_kernel --pack --arch x86` builds from
/// `bzimage()`: the protected-mode part in the kernel slot, the setup code
/// as the vmlinuz header, a PE stub as the bootloader.
fn x86_partition() -> Partition {
    let vmlinuz = bzimage();
    let blob = kernel_blob(
        &vmlinuz[SETUP_SIZE..],
        "console= loglevel=7 cros_secure",
        b"MZ bootstub",
        &vmlinuz[..SETUP_SIZE],
    );
    let partition = kernel_partition(&blob, &fields_for(&blob, keyblock(FLAGS_NORMAL).len()));
    Partition {
        bytes: partition,
        blob,
    }
}

/// A 64-byte AArch64 `Image` header (magic `ARM\x64` at 0x38) and 192 zero
/// bytes.
fn arm64_image() -> Vec<u8> {
    let mut image = vec![0u8; 256];
    put(&mut image, 0x38, b"ARM\x64");
    image
}

/// An Arm partition: an AArch64 `Image` in the kernel slot, no vmlinuz
/// header, and an ARM32 ELF as the bootloader.
fn arm64_partition() -> Partition {
    let blob = kernel_blob(&arm64_image(), "console=ttyS0", &arm_elf(), b"");
    let partition = kernel_partition(&blob, &fields_for(&blob, keyblock(FLAGS_NORMAL).len()));
    Partition {
        bytes: partition,
        blob,
    }
}

const BODY_OFFSET: usize = 64 << 10;

#[test]
fn chromeos_x86_kernels_are_rebuilt_into_vmlinuz_as_futility_does() {
    let Partition {
        bytes: partition,
        blob,
    } = x86_partition();
    assert_eq!(
        detected_format(&partition),
        Some(FileFormat::ChromeOsKernel)
    );
    let c = parse(&partition, Layout::ChromeOsKernel);
    assert_eq!(labels(&c), ["Kernel", "Bootloader"]);
    assert_eq!(c.target, None);
    assert_eq!(c.children[0].transform, Some("vmlinuz reassembly"));
    assert_eq!(c.children[0].data.len(), SETUP_SIZE + blob.bytes.len());
    assert_eq!(
        &c.children[0].data[..SETUP_SIZE + 0x100],
        &bzimage()[..SETUP_SIZE + 0x100]
    );
    assert!(has_note(
        &c,
        "ChromeOS kernel partition: keyblock 2.1 (448 B), kernel preamble 2.2 (65088 B), kernel body 20 KiB at 0x10000"
    ));
    assert!(has_note(
        &c,
        "Keyblock flags 0x5 (developer mode off, normal boot); data key RSA2048 SHA256, version 1; keyblock SHA-512 hash verified; keyblock signature (256 B) present, not verified"
    ));
    assert!(has_note(
        &c,
        "Preamble signature (256 B) and kernel body signature (256 B) present, not verified"
    ));
    assert!(has_note(
        &c,
        "Kernel version 1; body load address 0x100000; kernel type ChromeOS"
    ));
    assert!(has_note(
        &c,
        "Kernel command line (futility layout, 8 KiB before the bootloader): console= loglevel=7 cros_secure"
    ));

    let p = classify(&partition);
    assert_eq!(p.format.format, FileFormat::ChromeOsKernel);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let kernel = slice(&p, "Kernel");
    assert_eq!(kernel.isa, Isa::X86_64);
    assert_eq!(
        (kernel.offset, kernel.size),
        (BODY_OFFSET as u64, blob.bytes.len() as u64)
    );
    let decoded = kernel.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "vmlinuz reassembly");
    assert_eq!(decoded.size, (SETUP_SIZE + blob.bytes.len()) as u64);
    let bootloader = slice(&p, "Bootloader");
    assert_eq!(
        (bootloader.offset, bootloader.size),
        (
            (BODY_OFFSET + blob.bootloader_offset) as u64,
            blob.bootloader_size as u64
        )
    );
    assert!(payload_has_note(&p, "Kernel: x86_64 (contained zImage)"));
    assert_eq!(
        metadata_text(&p, "chromeos_command_line"),
        "console= loglevel=7 cros_secure"
    );
    assert_eq!(
        metadata_text(&p, "chromeos_data_key_algorithm"),
        "RSA2048 SHA256"
    );
}

#[test]
fn chromeos_arm_kernels_decide_the_isa_before_the_bootloader() {
    let Partition {
        bytes: partition,
        blob,
    } = arm64_partition();
    let c = parse(&partition, Layout::ChromeOsKernel);
    assert_eq!(labels(&c), ["Kernel", "Bootloader"]);
    assert_eq!(c.children[0].transform, None);
    assert_eq!(
        c.children[0].data.len(),
        PAGE,
        "the kernel slot ends at the command line"
    );
    let p = classify(&partition);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(slice(&p, "Kernel").offset, BODY_OFFSET as u64);
    assert_eq!(slice(&p, "Bootloader").isa, Isa::Arm);
    assert_eq!(
        slice(&p, "Bootloader").offset,
        (BODY_OFFSET + blob.bootloader_offset) as u64
    );
}

#[test]
fn chromeos_older_preambles_and_kernel_types_are_reported() {
    let blob = kernel_blob(&arm64_image(), "", b"", b"");
    let keyblock_size = keyblock(FLAGS_NORMAL).len();
    let mut fields = fields_for(&blob, keyblock_size);
    fields.minor = 0;
    let partition = kernel_partition(&blob, &fields);
    let c = parse(&partition, Layout::ChromeOsKernel);
    assert!(has_note(&c, "kernel preamble 2.0"));
    assert!(has_note(&c, "kernel type ChromeOS"));
    assert!(has_note(
        &c,
        "Kernel command line page (futility layout) is empty"
    ));
    assert_eq!(labels(&c), ["Kernel"]);

    let mut bootimg = fields_for(&blob, keyblock_size);
    bootimg.flags = 1;
    let partition = kernel_partition(&blob, &bootimg);
    let c = parse(&partition, Layout::ChromeOsKernel);
    assert!(has_note(&c, "kernel type Android boot image"));
}

#[test]
fn chromeos_unused_partition_space_is_noted() {
    let mut partition = arm64_partition().bytes;
    let body_end = partition.len();
    partition.extend_from_slice(&[0; 4096]);
    let c = parse(&partition, Layout::ChromeOsKernel);
    assert_eq!(c.consumed, body_end);
    assert!(has_note(
        &c,
        "4 KiB of unused partition space after the kernel body"
    ));
    assert!(has_note(&c, ": padding"));
    partition.extend_from_slice(b"stale kernel bytes");
    let c = parse(&partition, Layout::ChromeOsKernel);
    assert!(has_note(&c, "outside the signed body and not analyzed"));
}

#[test]
fn chromeos_structure_errors_name_the_field() {
    let Partition {
        bytes: partition,
        blob,
    } = x86_partition();
    let keyblock_size = keyblock(FLAGS_NORMAL).len();

    let mut hash = partition.clone();
    hash[112] ^= 1;
    assert_eq!(
        parse_error(&hash, Layout::ChromeOsKernel),
        "Firmware package parse error: Invalid ChromeOS keyblock SHA-512 hash"
    );
    let mut size = partition.clone();
    put_le32(&mut size, 16, size32(&partition) + 1);
    assert!(
        parse_error(&size, Layout::ChromeOsKernel).contains("Truncated ChromeOS keyblock at 0x0")
    );
    let mut hash_size = partition.clone();
    put_le32(&mut hash_size, 48 + 8, 32);
    assert!(parse_error(&hash_size, Layout::ChromeOsKernel)
        .contains("Invalid ChromeOS keyblock hash size 32 B"));
    let mut version = partition.clone();
    put_le32(&mut version, 8, 3);
    assert_ne!(detected_format(&version), Some(FileFormat::ChromeOsKernel));
    assert!(parse_error(&version, Layout::ChromeOsKernel)
        .contains("Unsupported ChromeOS keyblock header version 3.1"));

    let mut preamble_version = partition.clone();
    put_le32(&mut preamble_version, keyblock_size + 32, 3);
    assert!(parse_error(&preamble_version, Layout::ChromeOsKernel)
        .contains("Unsupported ChromeOS kernel preamble version 3.2"));
    let mut preamble_size = partition.clone();
    put_le32(&mut preamble_size, keyblock_size, 100);
    assert!(parse_error(&preamble_size, Layout::ChromeOsKernel)
        .contains("Invalid ChromeOS kernel preamble size 100 B: version 2.2 needs 116 B"));

    let mut fields = fields_for(&blob, keyblock_size);
    fields.bootloader_address = BODY_LOAD_ADDRESS + blob.bytes.len() as u64;
    assert!(
        parse_error(&kernel_partition(&blob, &fields), Layout::ChromeOsKernel)
            .contains("Invalid ChromeOS bootloader: outside the signed kernel body")
    );
    let mut fields = fields_for(&blob, keyblock_size);
    fields.vmlinuz_header_address = BODY_LOAD_ADDRESS - 1;
    assert!(
        parse_error(&kernel_partition(&blob, &fields), Layout::ChromeOsKernel)
            .contains("Invalid ChromeOS vmlinuz header")
    );
    let mut fields = fields_for(&blob, keyblock_size);
    fields.body_size = 0;
    assert!(
        parse_error(&kernel_partition(&blob, &fields), Layout::ChromeOsKernel)
            .contains("signs 0 B")
    );
    let mut fields = fields_for(&blob, keyblock_size);
    fields.body_size += 1;
    assert!(
        parse_error(&kernel_partition(&blob, &fields), Layout::ChromeOsKernel)
            .contains("Truncated ChromeOS kernel body at 0x10000")
    );
}

#[test]
fn chromeos_bodies_beyond_what_vboot_reads_are_noted() {
    let blob = kernel_blob(&arm64_image(), "", b"", b"");
    let mut fields = fields_for(&blob, keyblock(FLAGS_NORMAL).len());
    fields.padded_size += PAGE;
    let partition = kernel_partition(&blob, &fields);
    let c = parse(&partition, Layout::ChromeOsKernel);
    assert!(has_note(&c, "beyond the 64 KiB that vboot reads before it"));
}

#[test]
fn chromeos_prefixes_and_mutations_do_not_claim_the_partition() {
    let partition = arm64_partition().bytes;
    parse_truncation_sweep(&partition, Layout::ChromeOsKernel, partition.len());
    truncation_sweep(
        &partition,
        FileFormat::ChromeOsKernel,
        4099,
        &[112, 624, 740, BODY_OFFSET],
    );
    mutation_sweep(&partition, Layout::ChromeOsKernel, 0..740, 997);
}
