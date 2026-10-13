//! Virtual disk images: qemu-img-made QCOW2 (v2, v3, deflate, zstd,
//! extended L2, backing overlay), VMDK (monolithic sparse,
//! stream-optimized), VHD (dynamic, fixed), VHDX (dynamic, fixed) and VDI
//! (dynamic, static) images of one MBR/FAT12 disk, synthetic differencing
//! VHD and VHDX disks and an oversized QCOW2 built from the documented
//! layouts, corrupted fields and checksums, and truncation and mutation
//! sweeps.

use zrax::formats::checksum::crc32c_update;
use zrax::formats::container::{Child, Container};
use zrax::formats::vdisk::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat, MAX_PAYLOAD};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vdisk");

/// Bytes of a 512-byte sector.
const SECTOR: usize = 512;

/// The raw disk of the fixtures (README.md there): 340 sectors, an MBR
/// whose one FAT12 partition starts at sector 64.
const DISK_SIZE: usize = 340 * SECTOR;

/// The contents of a gzip file written by `gzip -n` (RFC 1952): a 10-byte
/// header without optional fields, a DEFLATE stream and an 8-byte trailer.
fn gunzip(file: &[u8]) -> Vec<u8> {
    assert_eq!(&file[..4], &[0x1f, 0x8b, 8, 0], "gzip -n header");
    miniz_oxide::inflate::decompress_to_vec(&file[10..file.len() - 8]).expect("inflates")
}

/// A fixture from `tests/fixtures/vdisk`, without its `.gz`.
fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}/{name}.gz");
    gunzip(&std::fs::read(path).expect("fixture is committed"))
}

fn raw_disk() -> Vec<u8> {
    fixture("disk.img")
}

/// A fixture converted from the raw disk.
struct Image {
    /// File name without `.gz`.
    name: &'static str,
    layout: Layout,
    /// The container variant the parser reports.
    variant: &'static str,
}

const fn image(name: &'static str, layout: Layout, variant: &'static str) -> Image {
    Image {
        name,
        layout,
        variant,
    }
}

/// Every image converted from the raw disk.
const IMAGES: &[Image] = &[
    image("qcow2-v3.qcow2", Layout::Qcow2, "QCOW2 v3"),
    image("qcow2-v2.qcow2", Layout::Qcow2, "QCOW2 v2"),
    image("qcow2-deflate.qcow2", Layout::Qcow2, "QCOW2 v3"),
    image("qcow2-zstd.qcow2", Layout::Qcow2, "QCOW2 v3"),
    image("qcow2-extl2.qcow2", Layout::Qcow2, "QCOW2 v3"),
    image("vmdk-sparse.vmdk", Layout::Vmdk, "VMDK monolithicSparse"),
    image("vmdk-stream.vmdk", Layout::Vmdk, "VMDK streamOptimized"),
    image("vhd-dynamic.vhd", Layout::Vhd, "VHD dynamic"),
    image("vhd-fixed.vhd", Layout::Vhd, "VHD fixed"),
    image("vhdx-dynamic.vhdx", Layout::Vhdx, "VHDX dynamic"),
    image("vhdx-fixed.vhdx", Layout::Vhdx, "VHDX fixed"),
    image("vdi-dynamic.vdi", Layout::Vdi, "VDI dynamic"),
    image("vdi-static.vdi", Layout::Vdi, "VDI fixed"),
];

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse an image that must be valid.
fn parse(data: &[u8]) -> Container<'_> {
    let layout = vdisk::detect(data).expect("detected as a virtual disk");
    vdisk::parse_container(data, layout).expect("parses")
}

/// The error text of an image that does not parse as `layout`.
fn parse_error(data: &[u8], layout: Layout) -> String {
    vdisk::parse_container(data, layout)
        .expect_err("does not parse")
        .to_string()
}

fn guest<'c>(c: &'c Container<'_>) -> &'c Child<'c> {
    assert_eq!(c.children.len(), 1, "one guest disk: {:?}", c.notes);
    &c.children[0]
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|note| note.contains(text))
}

fn payload_has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|note| note.message.contains(text))
}

fn metadata(c: &Container<'_>, key: &str) -> String {
    c.metadata()
        .into_iter()
        .find(|entry| format!("{:?}", entry.key).contains(&format!("\"{key}\"")))
        .map(|entry| entry.value.to_string())
        .unwrap_or_else(|| panic!("metadata {key}"))
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put16_le(data: &mut [u8], at: usize, value: u16) {
    put(data, at, &value.to_le_bytes());
}

fn put32_le(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_le_bytes());
}

fn put64_le(data: &mut [u8], at: usize, value: u64) {
    put(data, at, &value.to_le_bytes());
}

fn put32_be(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_be_bytes());
}

fn put64_be(data: &mut [u8], at: usize, value: u64) {
    put(data, at, &value.to_be_bytes());
}

fn be_u64(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

fn le_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn le_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

/// UTF-16 code units of `text`, little- or big-endian.
fn utf16(text: &str, little_endian: bool) -> Vec<u8> {
    text.encode_utf16()
        .flat_map(|unit| {
            if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            }
        })
        .collect()
}

/// A GUID in binary form ([MS-VHDX]): `Data1`, `Data2` and `Data3`
/// little-endian, `Data4` in text order.
fn guid(text: &str) -> [u8; 16] {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    let byte = |i: usize| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        // Reverse the first three groups (4, 2 and 2 bytes).
        let source = match i {
            0..=3 => 3 - i,
            4 | 5 => 9 - i,
            6 | 7 => 13 - i,
            _ => i,
        };
        *slot = byte(source);
    }
    out
}

// ---------------------------------------------------------------------
// QEMU images of the raw disk
// ---------------------------------------------------------------------

#[test]
fn qemu_images_hold_the_raw_disk_and_report_the_contained_isa() {
    let raw = raw_disk();
    assert_eq!(raw.len(), DISK_SIZE);
    for &Image {
        name,
        layout,
        variant,
    } in IMAGES
    {
        let data = fixture(name);
        assert_eq!(vdisk::detect(&data), Some(layout), "{name}");
        let c = parse(&data);
        assert_eq!(c.variant, variant, "{name}");
        assert_eq!(c.format, layout.format(), "{name}");
        assert!(c.target.is_none(), "{name}: virtual disks name no ISA");
        assert_eq!(
            &guest(&c).data[..],
            &raw[..],
            "{name}: guest disk is the raw disk"
        );
        assert_eq!(
            metadata(&c, "vdisk_virtual_size"),
            DISK_SIZE.to_string(),
            "{name}"
        );

        let p = classify(&data);
        assert_eq!(p.format.format, layout.format(), "{name}");
        assert_eq!(
            p.primary.isa,
            Isa::X86_64,
            "{name}: from the ELF in the FAT partition"
        );
        let slice = p
            .slices
            .iter()
            .find(|s| s.label.as_deref() == Some("Guest disk"))
            .unwrap_or_else(|| panic!("{name}: guest disk slice"));
        assert_eq!(slice.isa, Isa::X86_64, "{name}");
        assert!(
            payload_has_note(&p, "Primary ISA selected from Guest disk"),
            "{name}"
        );
    }
}

#[test]
fn json_format_ids_are_the_lowercase_variant_names() {
    for (format, id) in [
        (FileFormat::Qcow2, "qcow2"),
        (FileFormat::Vmdk, "vmdk"),
        (FileFormat::Vhd, "vhd"),
        (FileFormat::Vhdx, "vhdx"),
        (FileFormat::Vdi, "vdi"),
    ] {
        assert_eq!(serde_json::to_value(format).unwrap(), id);
    }
}

#[test]
fn stored_runs_are_slices_and_sparse_images_are_assembled() {
    for (name, offset, transform) in [
        ("vhd-fixed.vhd", Some(0), None),
        ("vhd-dynamic.vhd", Some(0xA00), None),
        ("vhdx-dynamic.vhdx", Some(0x80_0000), None),
        ("vhdx-fixed.vhdx", Some(0x90_0000), None),
        ("vdi-dynamic.vdi", Some(0x400), None),
        ("vdi-static.vdi", Some(0x400), None),
        ("qcow2-v3.qcow2", None, Some("QCOW2 clusters")),
        ("vmdk-sparse.vmdk", None, Some("VMDK grains")),
    ] {
        let data = fixture(name);
        let c = parse(&data);
        let child = guest(&c);
        assert_eq!(child.transform, transform, "{name}");
        match offset {
            Some(offset) => {
                assert_eq!(child.offset, offset, "{name}");
                assert_eq!(child.stored_size, DISK_SIZE, "{name}");
                assert!(has_note(
                    &c,
                    &format!("170 KiB stored contiguously at 0x{offset:X}")
                ));
            }
            None => {
                assert_eq!((child.offset, child.stored_size), (0, data.len()), "{name}");
                assert!(has_note(&c, "Guest disk assembled from"), "{name}");
            }
        }
    }
    let p = classify(&fixture("qcow2-v3.qcow2"));
    let slice = &p.slices[0];
    let decoded = slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "QCOW2 clusters");
    assert_eq!(decoded.size, DISK_SIZE as u64);
}

#[test]
fn fixed_vhd_is_detected_by_its_footer_before_the_guest_mbr() {
    let data = fixture("vhd-fixed.vhd");
    assert!(matches!(
        detect_format(&raw_disk()),
        DetectedFormat::Container { kind } if kind.format() == FileFormat::Mbr
    ));
    assert!(matches!(
        detect_format(&data),
        DetectedFormat::Container { kind } if kind.format() == FileFormat::Vhd
    ));
    let c = parse(&data);
    assert!(has_note(
        &c,
        "VHD fixed disk; 170 KiB current size; created by qemu"
    ));
    assert_eq!(metadata(&c, "vdisk_vhd_creator"), "qemu");
    let p = classify(&data);
    assert_eq!(p.slices[0].offset, 0);
    assert_eq!(p.slices[0].size, DISK_SIZE as u64);
}

#[test]
fn compressed_qcow2_clusters_decode_with_deflate_and_zstd() {
    let raw = raw_disk();
    for name in ["qcow2-deflate.qcow2", "qcow2-zstd.qcow2"] {
        let data = fixture(name);
        let c = parse(&data);
        assert_eq!(&guest(&c).data[..], &raw[..], "{name}");
        assert!(
            has_note(&c, "0 B stored, 16384 B from compressed blocks"),
            "{name}"
        );
        assert_eq!(metadata(&c, "vdisk_compressed_size"), "16384", "{name}");
    }
    assert!(has_note(
        &parse(&fixture("qcow2-zstd.qcow2")),
        "zstd compression"
    ));
}

#[test]
fn streamoptimized_vmdk_grains_are_zlib_streams_behind_markers() {
    let data = fixture("vmdk-stream.vmdk");
    let c = parse(&data);
    assert!(has_note(&c, "deflate-compressed grains; markers"));
    assert_eq!(metadata(&c, "vdisk_vmdk_create_type"), "streamOptimized");
    // The first grain marker (grain table entry for grain 0) names LBA 0.
    let marker = grain_entry(&data, 0) as usize * SECTOR;
    assert_eq!(le_u64(&data, marker), 0);
    assert_eq!(
        &data[marker + 12..marker + 14],
        &[0x78, 0x9c],
        "zlib header"
    );
}

/// The grain table entry of `grain` in a hosted sparse extent: the grain
/// directory at `gdOffset` (sector, u64 at 56) holds the sector of each
/// grain table (512 u32 entries).
fn grain_entry_offset(data: &[u8], grain: usize) -> usize {
    let gd = le_u64(data, 56) as usize * SECTOR;
    let gt = le_u32(data, gd + grain / 512 * 4) as usize * SECTOR;
    gt + grain % 512 * 4
}

fn grain_entry(data: &[u8], grain: usize) -> u32 {
    le_u32(data, grain_entry_offset(data, grain))
}

// ---------------------------------------------------------------------
// QCOW2 fields
// ---------------------------------------------------------------------

/// QCOW2 header field offsets (qcow2.rst "Header").
const QCOW2_VERSION: usize = 4;
const QCOW2_CLUSTER_BITS: usize = 20;
const QCOW2_CRYPT_METHOD: usize = 32;
const QCOW2_L1_SIZE: usize = 36;
const QCOW2_L1_TABLE_OFFSET: usize = 40;
const QCOW2_INCOMPATIBLE: usize = 72;

/// The file offset of guest cluster 0's L2 entry: L1 entry 0 points to
/// the L2 table, whose first entry describes cluster 0.
fn qcow2_l2_entry0(data: &[u8]) -> usize {
    let l1 = be_u64(data, QCOW2_L1_TABLE_OFFSET) as usize;
    (be_u64(data, l1) & 0x00ff_ffff_ffff_fe00) as usize
}

#[test]
fn qcow2_v2_maps_six_l2_tables_of_512_byte_clusters() {
    let data = fixture("qcow2-v2.qcow2");
    let c = parse(&data);
    assert!(has_note(
        &c,
        "QCOW2 version 2; 512 B clusters; 170 KiB virtual disk; 6 L1 entries"
    ));
    assert_eq!(metadata(&c, "vdisk_qcow2_cluster_size"), "512");
}

#[test]
fn extended_l2_subclusters_follow_their_allocation_and_zero_bits() {
    let raw = raw_disk();
    let mut data = fixture("qcow2-extl2.qcow2");
    assert!(has_note(
        &parse(&data),
        "extended L2 entries (32 subclusters)"
    ));
    // Cluster 0 (16 KiB) is 32 subclusters of 512 B. Its bitmap (the second
    // u64 of the 128-bit entry) has allocation bits 0-31 and zero bits
    // 32-63; make subcluster 0 read as zeros.
    let bitmap_at = qcow2_l2_entry0(&data) + 8;
    let bitmap = be_u64(&data, bitmap_at);
    assert_eq!(bitmap & 1, 1, "subcluster 0 is allocated");
    put64_be(&mut data, bitmap_at, (bitmap & !1) | (1 << 32));
    let c = parse(&data);
    let disk = &guest(&c).data;
    assert_eq!(&disk[..SECTOR], &[0u8; SECTOR][..]);
    assert_eq!(&disk[SECTOR..], &raw[SECTOR..]);

    put64_be(&mut data, bitmap_at, bitmap | (1 << 32));
    assert!(parse_error(&data, Layout::Qcow2).contains("subclusters both allocated and zero"));
}

#[test]
fn qcow2_backing_overlay_leaves_unallocated_clusters_to_the_backing_file() {
    let data = fixture("qcow2-overlay.qcow2");
    let c = parse(&data);
    assert!(has_note(&c, "Backing file: qcow2-v3.qcow2 (format qcow2)"));
    assert_eq!(metadata(&c, "vdisk_qcow2_backing_file"), "qcow2-v3.qcow2");
    assert!(has_note(
        &c,
        "169984 B of the guest disk are not in this file: the backing file qcow2-v3.qcow2 holds \
         them, so they read as zeros here"
    ));
    let disk = &guest(&c).data;
    assert_eq!(
        &disk[8 * SECTOR..9 * SECTOR],
        &[0x5a; SECTOR][..],
        "the written sector"
    );
    assert!(disk[..8 * SECTOR].iter().all(|&b| b == 0));
    assert!(has_note(&c, "does not start with a recognized format"));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Qcow2);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(
        p.slices.is_empty(),
        "an unrecognized guest disk is not listed"
    );
}

#[test]
fn encrypted_qcow2_guest_data_is_opaque() {
    let mut data = fixture("qcow2-v3.qcow2");
    put32_be(&mut data, QCOW2_CRYPT_METHOD, 2);
    let c = parse(&data);
    assert!(c.opaque);
    assert!(c.children.is_empty());
    assert!(has_note(
        &c,
        "Guest data is encrypted (LUKS); the guest disk is not assembled"
    ));
    let p = classify(&data);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(payload_has_note(
        &p,
        "Payload is encrypted or metadata-only"
    ));
    put32_be(&mut data, QCOW2_CRYPT_METHOD, 3);
    assert_eq!(
        parse_error(&data, Layout::Qcow2),
        "Virtual disk parse error: Unknown QCOW2 crypt_method 3"
    );
}

#[test]
fn qcow2_external_data_file_is_noted_and_not_assembled() {
    let mut data = fixture("qcow2-v3.qcow2");
    let incompatible = be_u64(&data, QCOW2_INCOMPATIBLE);
    put64_be(&mut data, QCOW2_INCOMPATIBLE, incompatible | 1 << 2);
    let c = parse(&data);
    assert!(c.children.is_empty());
    assert!(has_note(&c, "external data file (not named)"));
}

#[test]
fn qcow2_header_and_table_errors_name_the_field() {
    let data = fixture("qcow2-v3.qcow2");
    let with = |at: usize, value: u64, width: usize| {
        let mut copy = data.clone();
        put(&mut copy, at, &value.to_be_bytes()[8 - width..]);
        parse_error(&copy, Layout::Qcow2)
    };
    assert_eq!(
        with(QCOW2_INCOMPATIBLE, 1 << 5, 8),
        "Virtual disk parse error: Unsupported QCOW2 incompatible features 0x20"
    );
    assert_eq!(
        with(QCOW2_CLUSTER_BITS, 8, 4),
        "Virtual disk parse error: Unsupported QCOW2 cluster_bits 8"
    );
    assert_eq!(
        with(QCOW2_VERSION, 4, 4),
        "Virtual disk parse error: Unsupported QCOW2 version 4"
    );
    assert!(with(QCOW2_L1_SIZE, 0, 4).contains("Invalid QCOW2 L1 table: 0 entries cover less"));
    assert!(with(QCOW2_L1_TABLE_OFFSET, 0x1001, 8).contains("not cluster-aligned"));
    assert!(with(QCOW2_L1_TABLE_OFFSET, 1 << 40, 8).contains("Truncated QCOW2 L1 table"));

    let mut reserved = data.clone();
    let l2 = qcow2_l2_entry0(&reserved);
    let entry = be_u64(&reserved, l2);
    put64_be(&mut reserved, l2, entry | 1 << 1);
    assert!(parse_error(&reserved, Layout::Qcow2)
        .contains("Invalid QCOW2 L2 entry for cluster 0: reserved bits set"));
    put64_be(
        &mut reserved,
        l2,
        (entry & !0x00ff_ffff_ffff_fe00) | 0x00ff_ffff_ffff_0000,
    );
    assert!(parse_error(&reserved, Layout::Qcow2).contains("Truncated QCOW2 data cluster"));
}

#[test]
fn qcow2_version_1_and_other_magics_are_not_virtual_disks() {
    let mut data = fixture("qcow2-v3.qcow2");
    put32_be(&mut data, QCOW2_VERSION, 1);
    assert_eq!(vdisk::detect(&data), None);
    assert_eq!(vdisk::detect(&raw_disk()), None);
    assert_eq!(vdisk::detect(b"QFI\xfb"), None);
    assert_eq!(vdisk::detect(&[0u8; 4096]), None);
}

/// QCOW2 v3 header (qcow2.rst "Header"), big-endian: magic, version 3, no
/// backing file, `cluster_bits`, virtual `size`, no encryption, `l1_size`
/// entries at cluster 1, a one-cluster refcount table at cluster 2, no
/// snapshots, no features, refcount order 4 and a 112-byte header. The L1
/// and refcount tables are all zeros: every guest cluster is unallocated.
fn empty_qcow2(cluster_bits: u32, size: u64, l1_size: u32) -> Vec<u8> {
    let cluster = 1usize << cluster_bits;
    let mut data = vec![0u8; 3 * cluster];
    put(&mut data, 0, b"QFI\xfb");
    put32_be(&mut data, QCOW2_VERSION, 3);
    put32_be(&mut data, QCOW2_CLUSTER_BITS, cluster_bits);
    put64_be(&mut data, 24, size);
    put32_be(&mut data, QCOW2_L1_SIZE, l1_size);
    put64_be(&mut data, QCOW2_L1_TABLE_OFFSET, cluster as u64);
    put64_be(&mut data, 48, 2 * cluster as u64);
    put32_be(&mut data, 56, 1);
    put32_be(&mut data, 96, 4);
    put32_be(&mut data, 100, 112);
    data
}

#[test]
fn virtual_disks_larger_than_the_extraction_limit_are_cut_with_a_note() {
    // 1 GiB with 64 KiB clusters: 8192 L2 entries per table, so each L1
    // entry covers 512 MiB.
    let data = empty_qcow2(16, 1 << 30, 2);
    let c = parse(&data);
    let disk = &guest(&c).data;
    assert_eq!(disk.len(), MAX_PAYLOAD);
    assert!(has_note(
        &c,
        "Virtual disk is 1 GiB; only the first 64 MiB were assembled and analyzed"
    ));
    assert_eq!(metadata(&c, "vdisk_guest_size"), MAX_PAYLOAD.to_string());
    assert_eq!(metadata(&c, "vdisk_virtual_size"), (1u64 << 30).to_string());

    let empty = empty_qcow2(16, 0, 0);
    let c = parse(&empty);
    assert!(c.children.is_empty());
    assert!(has_note(&c, "Virtual disk size is 0 B"));
}

// ---------------------------------------------------------------------
// VMDK fields
// ---------------------------------------------------------------------

/// VMDK header fields (technote "Hosted Sparse Extent Header").
const VMDK_VERSION: usize = 4;
const VMDK_FLAGS: usize = 8;
const VMDK_GD_OFFSET: usize = 56;
const VMDK_FLAG_ZEROED_GRAINS: u32 = 1 << 2;
const VMDK_GD_AT_END: u64 = u64::MAX;
const VMDK_MARKER_FOOTER: u32 = 3;
const GRAIN: usize = 64 << 10;

#[test]
fn streamoptimized_footer_supplies_the_grain_directory() {
    let raw = raw_disk();
    let mut data = fixture("vmdk-stream.vmdk");
    let header: Vec<u8> = data[..SECTOR].to_vec();
    let end = data.len();
    // The last three sectors (zeros in qemu-img's file): footer marker
    // (value 1 sector, size 0, type 3), the footer (the header with the
    // real grain directory offset), and the end-of-stream marker (zeros).
    assert!(data[end - 3 * SECTOR..].iter().all(|&b| b == 0));
    let marker = end - 3 * SECTOR;
    put64_le(&mut data, marker, 1);
    put32_le(&mut data, marker + 12, VMDK_MARKER_FOOTER);
    put(&mut data, end - 2 * SECTOR, &header);
    put64_le(&mut data, VMDK_GD_OFFSET, VMDK_GD_AT_END);
    let c = parse(&data);
    assert_eq!(&guest(&c).data[..], &raw[..]);
    assert!(has_note(
        &c,
        &format!("Stream-optimized footer at 0x{:X}", end - 2 * SECTOR)
    ));

    put32_le(&mut data, end - SECTOR + 12, 7);
    assert!(parse_error(&data, Layout::Vmdk).contains("missing footer or end-of-stream marker"));
}

#[test]
fn vmdk_grain_markers_must_name_their_own_lba() {
    let mut data = fixture("vmdk-stream.vmdk");
    let marker = grain_entry(&data, 0) as usize * SECTOR;
    put64_le(&mut data, marker, 1);
    assert_eq!(
        parse_error(&data, Layout::Vmdk),
        format!("Virtual disk parse error: Invalid VMDK grain marker at 0x{marker:X}: LBA 1, expected 0")
    );
    put64_le(&mut data, marker, 0);
    put32_le(&mut data, marker + 8, 0);
    assert!(parse_error(&data, Layout::Vmdk).contains("a metadata marker where grain 0 should be"));
    put32_le(&mut data, marker + 8, 3 * GRAIN as u32);
    assert!(parse_error(&data, Layout::Vmdk).contains("B of compressed data"));
}

#[test]
fn vmdk_zeroed_grain_entries_read_as_zeros() {
    let raw = raw_disk();
    let mut data = fixture("vmdk-sparse.vmdk");
    let flags = le_u32(&data, VMDK_FLAGS);
    put32_le(&mut data, VMDK_VERSION, 2);
    put32_le(&mut data, VMDK_FLAGS, flags | VMDK_FLAG_ZEROED_GRAINS);
    let entry = grain_entry_offset(&data, 0);
    put32_le(&mut data, entry, 1);
    let c = parse(&data);
    let disk = &guest(&c).data;
    assert!(disk[..GRAIN].iter().all(|&b| b == 0));
    assert_eq!(&disk[GRAIN..], &raw[GRAIN..]);
}

#[test]
fn vmdk_delta_link_names_its_parent_and_leaves_it_unallocated_grains() {
    let mut data = fixture("vmdk-sparse.vmdk");
    // The embedded descriptor: sector 1, 20 sectors.
    let text = "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=12345678\n\
                createType=\"monolithicSparse\"\nparentFileNameHint=\"base.vmdk\"\n\
                RW 340 SPARSE \"delta.vmdk\"\n";
    put(&mut data, SECTOR, &vec![0u8; 20 * SECTOR]);
    put(&mut data, SECTOR, text.as_bytes());
    let c = parse(&data);
    assert!(has_note(
        &c,
        "Delta link of the parent base.vmdk (parent CID 12345678)"
    ));
    assert!(has_note(
        &c,
        "the parent link base.vmdk (parent CID 12345678) holds them"
    ));
    // Grain 0 is stored; grains 1 and 2 were all zeros and are not
    // allocated, so the parent holds them.
    assert_eq!(
        metadata(&c, "vdisk_parent_size"),
        (DISK_SIZE - GRAIN).to_string()
    );
    assert_eq!(&guest(&c).data[..GRAIN], &raw_disk()[..GRAIN]);
}

#[test]
fn vmdk_header_checks_follow_the_technote() {
    let data = fixture("vmdk-sparse.vmdk");
    let mut newline = data.clone();
    newline[75] = b'\n';
    assert!(parse_error(&newline, Layout::Vmdk).contains("altered by a text-mode transfer"));
    let mut grain = data.clone();
    put64_le(&mut grain, 20, 100);
    assert!(parse_error(&grain, Layout::Vmdk).contains("Unsupported VMDK grain size 100 sectors"));
    let mut version = data.clone();
    put32_le(&mut version, VMDK_VERSION, 4);
    assert_eq!(vdisk::detect(&version), None);
    assert!(parse_error(&version, Layout::Vmdk).contains("Unsupported VMDK version 4"));
    let mut directory = data.clone();
    put64_le(&mut directory, VMDK_GD_OFFSET, 1 << 40);
    assert!(parse_error(&directory, Layout::Vmdk).contains("Truncated VMDK grain directory"));
}

// ---------------------------------------------------------------------
// VHD fields and a differencing disk
// ---------------------------------------------------------------------

/// VHD footer and dynamic header fields (the VHD specification's "Hard
/// Disk Footer Format" and "Dynamic Disk Header Format"), big-endian.
const VHD_FOOTER: usize = 512;
const VHD_CHECKSUM: usize = 64;
const VHD_DYNAMIC_CHECKSUM: usize = 36;
const VHD_DISK_DIFFERENCING: u32 = 4;
const VHD_BAT_UNUSED: u32 = 0xffff_ffff;

/// One's complement of the byte sum with the checksum field counted as 0.
fn vhd_checksum(bytes: &[u8], checksum_at: usize) -> u32 {
    let sum = bytes
        .iter()
        .enumerate()
        .filter(|&(i, _)| !(checksum_at..checksum_at + 4).contains(&i))
        .fold(0u32, |sum, (_, &b)| sum.wrapping_add(u32::from(b)));
    !sum
}

fn seal_vhd(bytes: &mut [u8], checksum_at: usize) {
    let checksum = vhd_checksum(bytes, checksum_at);
    put32_be(bytes, checksum_at, checksum);
}

/// A VHD footer: cookie, features 2 (the reserved bit), version 1.0, data
/// offset, time stamp 0, creator `zrax` 1.0 on `Wi2k`, original and current
/// size, geometry 0, `disk_type`, checksum, unique ID and saved state 0.
fn vhd_footer(data_offset: u64, size: u64, disk_type: u32) -> Vec<u8> {
    let mut footer = vec![0u8; VHD_FOOTER];
    put(&mut footer, 0, b"conectix");
    put32_be(&mut footer, 8, 2);
    put32_be(&mut footer, 12, 0x0001_0000);
    put64_be(&mut footer, 16, data_offset);
    put(&mut footer, 28, b"zrax");
    put32_be(&mut footer, 32, 0x0001_0000);
    put(&mut footer, 36, b"Wi2k");
    put64_be(&mut footer, 40, size);
    put64_be(&mut footer, 48, size);
    put32_be(&mut footer, 60, disk_type);
    put(&mut footer, 68, &[0x11; 16]);
    seal_vhd(&mut footer, VHD_CHECKSUM);
    footer
}

/// A differencing VHD of two 4 KiB blocks (8 sectors each): the footer
/// copy at 0, the dynamic header at 512 (cookie, data offset all ones, BAT
/// at 1536, version 1.0, 2 entries, 4 KiB blocks, checksum, parent unique
/// ID, parent time stamp, parent name `base.vhd` in UTF-16BE), the BAT
/// (block 0 at sector 4, block 1 unused) and block 0: a one-sector bitmap
/// with sectors 0 and 2 present (bits 7 and 5 of byte 0), then 4 KiB of
/// data whose sector 1 holds bytes that the bitmap marks absent. The
/// footer follows.
fn differencing_vhd() -> Vec<u8> {
    let block_size = 4096usize;
    let size = 2 * block_size as u64;
    let mut data = vhd_footer(512, size, VHD_DISK_DIFFERENCING);
    let mut header = vec![0u8; 1024];
    put(&mut header, 0, b"cxsparse");
    put64_be(&mut header, 8, u64::MAX);
    put64_be(&mut header, 16, 1536);
    put32_be(&mut header, 24, 0x0001_0000);
    put32_be(&mut header, 28, 2);
    put32_be(&mut header, 32, block_size as u32);
    put(&mut header, 40, &[0x22; 16]);
    put(&mut header, 64, &utf16("base.vhd", false));
    seal_vhd(&mut header, VHD_DYNAMIC_CHECKSUM);
    data.extend_from_slice(&header);
    let mut bat = vec![0xffu8; SECTOR];
    put32_be(&mut bat, 0, 4);
    put32_be(&mut bat, 4, VHD_BAT_UNUSED);
    data.extend_from_slice(&bat);
    let mut bitmap = vec![0u8; SECTOR];
    bitmap[0] = 0b1010_0000;
    data.extend_from_slice(&bitmap);
    let mut block = vec![0u8; block_size];
    block[..SECTOR].fill(0x41);
    block[SECTOR..2 * SECTOR].fill(0xee);
    block[2 * SECTOR..3 * SECTOR].fill(0x43);
    data.extend_from_slice(&block);
    let footer = vhd_footer(512, size, VHD_DISK_DIFFERENCING);
    data.extend_from_slice(&footer);
    data
}

#[test]
fn differencing_vhd_reads_present_sectors_and_leaves_the_rest_to_the_parent() {
    let data = differencing_vhd();
    let c = parse(&data);
    assert_eq!(c.variant, "VHD differencing");
    let disk = &guest(&c).data;
    assert_eq!(disk.len(), 8192);
    assert_eq!(&disk[..SECTOR], &[0x41; SECTOR][..]);
    assert_eq!(
        &disk[SECTOR..2 * SECTOR],
        &[0u8; SECTOR][..],
        "held by the parent"
    );
    assert_eq!(&disk[2 * SECTOR..3 * SECTOR], &[0x43; SECTOR][..]);
    assert!(disk[3 * SECTOR..].iter().all(|&b| b == 0));
    assert!(has_note(
        &c,
        "Differencing disk of the parent base.vhd (unique ID 22222222-2222-2222-2222-222222222222)"
    ));
    assert_eq!(
        metadata(&c, "vdisk_parent_size"),
        (8192 - 2 * SECTOR).to_string()
    );
}

#[test]
fn dynamic_vhd_uses_the_footer_copy_when_the_footer_is_cut_or_damaged() {
    let raw = raw_disk();
    let data = fixture("vhd-dynamic.vhd");
    let cut = &data[..data.len() - 100];
    let c = parse(cut);
    assert!(has_note(
        &c,
        "footer at the end of the file is missing or damaged; the copy at 0x0 is used"
    ));
    assert_eq!(&guest(&c).data[..], &raw[..]);

    let mut copy = data.clone();
    copy[100] ^= 1;
    assert!(has_note(
        &parse(&copy),
        "footer copy at 0x0 is missing or damaged"
    ));
}

#[test]
fn vhd_checksums_and_tables_are_verified() {
    let data = fixture("vhd-dynamic.vhd");
    let mut header = data.clone();
    header[0x200 + 40] ^= 1;
    assert_eq!(
        parse_error(&header, Layout::Vhd),
        "Virtual disk parse error: Invalid VHD dynamic disk header checksum at 0x200"
    );
    let mut both = data.clone();
    both[100] ^= 1;
    let end = both.len() - VHD_FOOTER + 100;
    both[end] ^= 1;
    assert_eq!(
        parse_error(&both, Layout::Vhd),
        "Virtual disk parse error: Invalid VHD footer checksum at 0x0"
    );
    // A BAT too small for the disk: one 2 MiB entry is enough for 170 KiB,
    // zero entries are not.
    let mut table = data.clone();
    let header = 0x200;
    put32_be(&mut table, header + 28, 0);
    seal_vhd(&mut table[header..header + 1024], VHD_DYNAMIC_CHECKSUM);
    assert!(parse_error(&table, Layout::Vhd).contains("0 entries of 2 MiB cover less"));
}

#[test]
fn old_511_byte_vhd_footer_is_found_at_the_end() {
    let raw = raw_disk();
    let mut data = fixture("vhd-fixed.vhd");
    // The last footer byte is reserved and zero, so the 511-byte footer
    // keeps its checksum.
    assert_eq!(data.pop(), Some(0));
    let c = parse(&data);
    assert!(has_note(&c, "511-byte footer (before Virtual PC 2004)"));
    assert_eq!(&guest(&c).data[..], &raw[..]);
}

#[test]
fn a_footer_at_the_end_must_describe_the_file_to_be_detected() {
    // A fixed footer whose current size is not the bytes before it (a VHD
    // stored as the last member of another file) is not detected; parsed
    // as a VHD anyway, the mismatch is noted.
    let mut data = fixture("vhd-fixed.vhd");
    let footer = data.len() - VHD_FOOTER;
    put64_be(&mut data, footer + 48, 1 << 20);
    seal_vhd(&mut data[footer..], VHD_CHECKSUM);
    assert_eq!(vdisk::detect(&data), None);
    let c = vdisk::parse_container(&data, Layout::Vhd).expect("parses");
    assert!(has_note(
        &c,
        "current size is 1048576 B, but 174080 B are stored before the footer"
    ));
    assert_eq!(guest(&c).data.len(), DISK_SIZE);

    // A dynamic disk whose footer copy is gone is detected by its footer
    // when the data offset locates the dynamic header.
    let mut dynamic = fixture("vhd-dynamic.vhd");
    dynamic[..8].copy_from_slice(b"notconec");
    assert_eq!(vdisk::detect(&dynamic), Some(Layout::Vhd));
    assert!(has_note(
        &parse(&dynamic),
        "footer copy at 0x0 is missing or damaged"
    ));
    let mut header = dynamic.clone();
    header[0x200] = b'X';
    assert_eq!(vdisk::detect(&header), None);
}

// ---------------------------------------------------------------------
// VHDX fields and a differencing disk
// ---------------------------------------------------------------------

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;

/// [MS-VHDX] 2.2: headers at 64 and 128 KiB, region tables at 192 and
/// 256 KiB; the checksum is the second 32-bit word of each.
const VHDX_HEADERS: [usize; 2] = [64 * KIB, 128 * KIB];
const VHDX_REGION_TABLES: [usize; 2] = [192 * KIB, 256 * KIB];
const VHDX_HEADER_SIZE: usize = 4 * KIB;
const VHDX_REGION_TABLE_SIZE: usize = 64 * KIB;
const VHDX_CHECKSUM: usize = 4;

/// Write the CRC-32C of `bytes` (checksum field counted as 0) into it.
fn seal_vhdx(bytes: &mut [u8]) {
    put32_le(bytes, VHDX_CHECKSUM, 0);
    let crc = !crc32c_update(!0, bytes);
    put32_le(bytes, VHDX_CHECKSUM, crc);
}

/// A VHDX header (2.2.2): `head`, checksum, `sequence`, file write and
/// data write GUIDs, log GUID `log_guid`, log version 0, version 1, a
/// 1 MiB log at 1 MiB.
fn vhdx_header(sequence: u64, log_guid: [u8; 16]) -> Vec<u8> {
    let mut header = vec![0u8; VHDX_HEADER_SIZE];
    put(&mut header, 0, b"head");
    put64_le(&mut header, 8, sequence);
    put(&mut header, 16, &[0x31; 16]);
    put(&mut header, 32, &[0x32; 16]);
    put(&mut header, 48, &log_guid);
    put16_le(&mut header, 66, 1);
    put32_le(&mut header, 68, MIB as u32);
    put64_le(&mut header, 72, MIB as u64);
    seal_vhdx(&mut header);
    header
}

/// One metadata table entry (2.6.1.2): item ID, offset from the region
/// start, length and flags (`IsRequired` = 4, `IsVirtualDisk` = 2).
struct MetadataItem {
    id: &'static str,
    flags: u32,
    value: Vec<u8>,
}

/// One key-value pair of a parent locator.
struct LocatorPair {
    key: &'static str,
    value: &'static str,
}

/// A parent locator item (2.6.2.6): the VHDX locator type, reserved, the
/// key-value count, then entries of key offset, value offset, key length
/// and value length, then the UTF-16LE strings.
fn parent_locator(pairs: &[LocatorPair]) -> Vec<u8> {
    let mut item = vec![0u8; 20 + 12 * pairs.len()];
    put(&mut item, 0, &guid("B04AEFB7-D19E-4A81-B789-25B8E9445913"));
    put16_le(&mut item, 18, pairs.len() as u16);
    for (i, pair) in pairs.iter().enumerate() {
        let key = utf16(pair.key, true);
        let value = utf16(pair.value, true);
        let entry = 20 + 12 * i;
        let key_offset = item.len() as u32;
        put32_le(&mut item, entry, key_offset);
        put16_le(&mut item, entry + 8, key.len() as u16);
        item.extend_from_slice(&key);
        let value_offset = item.len() as u32;
        put32_le(&mut item, entry + 4, value_offset);
        put16_le(&mut item, entry + 10, value.len() as u16);
        item.extend_from_slice(&value);
    }
    item
}

/// A 6 MiB differencing VHDX of a 1 MiB disk with 1 MiB blocks and
/// 512-byte sectors: identifier with creator `zrax`, headers with
/// sequence numbers 1 and 2, both region tables (BAT at 3 MiB, metadata at
/// 2 MiB), the metadata table with file parameters (`HasParent`), virtual
/// size, disk ID, sector sizes and a parent locator, a BAT whose entry 0
/// is a partially present block at 4 MiB and whose entry 4096 (the chunk's
/// sector bitmap) is present at 5 MiB, the block (sector 1 holds bytes the
/// bitmap marks absent) and the bitmap with sectors 0 and 2 set.
fn differencing_vhdx() -> Vec<u8> {
    let mut data = vec![0u8; 6 * MIB];
    put(&mut data, 0, b"vhdxfile");
    put(&mut data, 8, &utf16("zrax", true));
    put(&mut data, VHDX_HEADERS[0], &vhdx_header(1, [0; 16]));
    put(&mut data, VHDX_HEADERS[1], &vhdx_header(2, [0; 16]));
    let mut table = vec![0u8; VHDX_REGION_TABLE_SIZE];
    put(&mut table, 0, b"regi");
    put32_le(&mut table, 8, 2);
    for (i, (id, offset)) in [
        ("2DC27766-F623-4200-9D64-115E9BFD4A08", 3 * MIB),
        ("8B7CA206-4790-4B9A-B8FE-575F050F886E", 2 * MIB),
    ]
    .into_iter()
    .enumerate()
    {
        let entry = 16 + 32 * i;
        put(&mut table, entry, &guid(id));
        put64_le(&mut table, entry + 16, offset as u64);
        put32_le(&mut table, entry + 24, MIB as u32);
        put32_le(&mut table, entry + 28, 1);
    }
    seal_vhdx(&mut table);
    for at in VHDX_REGION_TABLES {
        put(&mut data, at, &table);
    }
    let mut file_parameters = Vec::new();
    file_parameters.extend_from_slice(&(MIB as u32).to_le_bytes());
    file_parameters.extend_from_slice(&2u32.to_le_bytes());
    let items = [
        MetadataItem {
            id: "CAA16737-FA36-4D43-B3B6-33F0AA44E76B",
            flags: 4,
            value: file_parameters,
        },
        MetadataItem {
            id: "2FA54224-CD1B-4876-B211-5DBED83BF4B8",
            flags: 6,
            value: (MIB as u64).to_le_bytes().to_vec(),
        },
        MetadataItem {
            id: "BECA12AB-B2E6-4523-93EF-C309E000C746",
            flags: 6,
            value: vec![0x44; 16],
        },
        MetadataItem {
            id: "8141BF1D-A96F-4709-BA47-F233A8FAAB5F",
            flags: 6,
            value: 512u32.to_le_bytes().to_vec(),
        },
        MetadataItem {
            id: "CDA348C7-445D-4471-9CC9-E9885251C556",
            flags: 6,
            value: 512u32.to_le_bytes().to_vec(),
        },
        MetadataItem {
            id: "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C",
            flags: 4,
            value: parent_locator(&[
                LocatorPair {
                    key: "parent_linkage",
                    value: "{83ed0ec3-24c8-49a6-a959-5e4bf1288bfb}",
                },
                LocatorPair {
                    key: "relative_path",
                    value: "base.vhdx",
                },
            ]),
        },
    ];
    let region = 2 * MIB;
    put(&mut data, region, b"metadata");
    put16_le(&mut data, region + 10, items.len() as u16);
    let mut item_offset = 64 * KIB;
    for (i, item) in items.iter().enumerate() {
        let entry = region + 32 * (i + 1);
        put(&mut data, entry, &guid(item.id));
        put32_le(&mut data, entry + 16, item_offset as u32);
        put32_le(&mut data, entry + 20, item.value.len() as u32);
        put32_le(&mut data, entry + 24, item.flags);
        put(&mut data, region + item_offset, &item.value);
        item_offset += item.value.len();
    }
    // BAT entries: state in bits 0-2, offset in MiB from bit 20.
    let bat = 3 * MIB;
    put64_le(&mut data, bat, (4 * MIB as u64) | 7);
    put64_le(&mut data, bat + 4096 * 8, (5 * MIB as u64) | 6);
    let block = 4 * MIB;
    data[block..block + SECTOR].fill(0x41);
    data[block + SECTOR..block + 2 * SECTOR].fill(0xee);
    data[block + 2 * SECTOR..block + 3 * SECTOR].fill(0x43);
    data[5 * MIB] = 0b0000_0101;
    data
}

#[test]
fn differencing_vhdx_maps_partial_blocks_through_the_sector_bitmap() {
    let data = differencing_vhdx();
    let c = parse(&data);
    assert_eq!(c.variant, "VHDX differencing");
    let disk = &guest(&c).data;
    assert_eq!(disk.len(), MIB);
    assert_eq!(&disk[..SECTOR], &[0x41; SECTOR][..]);
    assert_eq!(
        &disk[SECTOR..2 * SECTOR],
        &[0u8; SECTOR][..],
        "held by the parent"
    );
    assert_eq!(&disk[2 * SECTOR..3 * SECTOR], &[0x43; SECTOR][..]);
    assert!(disk[3 * SECTOR..].iter().all(|&b| b == 0));
    assert!(has_note(
        &c,
        "Differencing disk of the parent (parent_linkage {83ed0ec3-24c8-49a6-a959-5e4bf1288bfb}; \
         relative_path base.vhdx)"
    ));
    assert!(has_note(
        &c,
        "current header at 0x20000 (sequence number 2)"
    ));
    assert!(has_note(&c, "Creator: zrax"));
    assert_eq!(
        metadata(&c, "vdisk_vhdx_disk_id"),
        "44444444-4444-4444-4444-444444444444"
    );

    let mut bitmap_absent = data.clone();
    put64_le(&mut bitmap_absent, 3 * MIB + 4096 * 8, 0);
    assert!(parse_error(&bitmap_absent, Layout::Vhdx)
        .contains("the sector bitmap of a partially present block is not present"));
}

#[test]
fn vhdx_header_choice_follows_sequence_numbers_and_checksums() {
    let data = differencing_vhdx();
    let mut second_bad = data.clone();
    second_bad[VHDX_HEADERS[1] + 100] ^= 1;
    assert!(has_note(
        &parse(&second_bad),
        "current header at 0x10000 (sequence number 1)"
    ));
    let mut both_bad = second_bad.clone();
    both_bad[VHDX_HEADERS[0] + 100] ^= 1;
    assert!(parse_error(&both_bad, Layout::Vhdx).contains("neither header"));
    let mut equal = data.clone();
    put(&mut equal, VHDX_HEADERS[1], &vhdx_header(1, [0x55; 16]));
    assert!(parse_error(&equal, Layout::Vhdx).contains("both have sequence number 1 but differ"));
}

#[test]
fn vhdx_second_region_table_and_non_empty_log() {
    let mut data = differencing_vhdx();
    data[VHDX_REGION_TABLES[0] + 40] ^= 1;
    assert!(has_note(&parse(&data), "region table at 0x40000"));
    put(&mut data, VHDX_HEADERS[1], &vhdx_header(2, [0x66; 16]));
    assert!(has_note(
        &parse(&data),
        "may hold updates that were not replayed"
    ));
    data[VHDX_REGION_TABLES[1] + 40] ^= 1;
    assert!(parse_error(&data, Layout::Vhdx).contains("neither copy at 0x30000 or 0x40000"));
}

#[test]
fn vhdx_unknown_required_metadata_and_reserved_block_states_are_errors() {
    let data = fixture("vhdx-dynamic.vhdx");
    // The third metadata entry is the virtual disk ID (flags 6, required).
    let mut unknown = data.clone();
    let entry = 3 * MIB + 32 * 3;
    put(&mut unknown, entry, &[0x77; 16]);
    assert!(parse_error(&unknown, Layout::Vhdx).contains(
        "Unsupported VHDX metadata item 77777777-7777-7777-7777-777777777777 marked required"
    ));
    let mut state = data.clone();
    let bat = 2 * MIB;
    let entry = le_u64(&state, bat);
    put64_le(&mut state, bat, (entry & !7) | 4);
    assert!(parse_error(&state, Layout::Vhdx).contains("reserved payload block state 4"));
    put64_le(&mut state, bat, (entry & !7) | 7);
    assert!(parse_error(&state, Layout::Vhdx)
        .contains("partially present block in a disk without a parent"));
    put64_le(&mut state, bat, 0);
    let c = parse(&state);
    assert!(
        guest(&c).data.iter().all(|&b| b == 0),
        "a block that is not present reads as zeros"
    );
}

// ---------------------------------------------------------------------
// VDI fields
// ---------------------------------------------------------------------

/// VDI header fields (`VDIHEADER1` after the 72-byte pre-header),
/// little-endian.
const VDI_VERSION: usize = 68;
const VDI_TYPE: usize = 76;
const VDI_CREATE_UUID: usize = 392;
const VDI_LINKAGE_UUID: usize = 424;
const VDI_BLOCK_MAP: usize = 0x200;
const VDI_TYPE_DIFF: u32 = 4;
const VDI_BLOCK_FREE: u32 = 0xffff_ffff;

#[test]
fn vdi_differencing_image_leaves_free_blocks_to_its_parent() {
    let mut data = fixture("vdi-dynamic.vdi");
    put32_le(&mut data, VDI_TYPE, VDI_TYPE_DIFF);
    put(
        &mut data,
        VDI_LINKAGE_UUID,
        &guid("01234567-89AB-CDEF-0123-456789ABCDEF"),
    );
    put32_le(&mut data, VDI_BLOCK_MAP, VDI_BLOCK_FREE);
    let c = parse(&data);
    assert_eq!(c.variant, "VDI differencing");
    assert!(has_note(
        &c,
        "Differencing image of the parent with UUID 01234567-89AB-CDEF-0123-456789ABCDEF"
    ));
    assert_eq!(metadata(&c, "vdisk_parent_size"), DISK_SIZE.to_string());
}

#[test]
fn vdi_header_checks_follow_virtualbox() {
    let data = fixture("vdi-dynamic.vdi");
    let mut pointer = data.clone();
    put32_le(&mut pointer, VDI_BLOCK_MAP, 5);
    assert!(parse_error(&pointer, Layout::Vdi).contains("Invalid VDI block pointer 5 for block 0"));
    let mut uuid = data.clone();
    put(&mut uuid, VDI_CREATE_UUID, &[0; 16]);
    assert!(parse_error(&uuid, Layout::Vdi).contains("null creation or modification UUID"));
    let mut kind = data.clone();
    put32_le(&mut kind, VDI_TYPE, 9);
    assert!(parse_error(&kind, Layout::Vdi).contains("Invalid VDI image type 9"));
    let mut old = data.clone();
    put32_le(&mut old, VDI_VERSION, 2);
    assert_eq!(vdisk::detect(&old), Some(Layout::Vdi));
    assert!(parse_error(&old, Layout::Vdi).contains("Unsupported VDI header version 0.2"));
    let mut zero = data.clone();
    put32_le(&mut zero, VDI_BLOCK_MAP, 0xffff_fffe);
    assert!(guest(&parse(&zero)).data.iter().all(|&b| b == 0));
}

// ---------------------------------------------------------------------
// Nesting, sweeps and real inputs
// ---------------------------------------------------------------------

#[test]
fn gzip_compressed_qcow2_is_classified_through_every_layer() {
    let gz = std::fs::read(format!("{FIXTURES}/qcow2-v3.qcow2.gz")).expect("fixture");
    let p = classify(&gz);
    assert_eq!(p.format.format, FileFormat::Gzip);
    assert_eq!(p.primary.isa, Isa::X86_64);
}

/// Prefix lengths for a truncation sweep: every length up to 4 KiB, then
/// at most 2048 lengths spread over the rest (every 509 bytes in a small
/// file), then every length in the last 2 KiB.
fn truncation_points(len: usize) -> Vec<usize> {
    let mut points: Vec<usize> = (0..len.min(4096)).collect();
    points.extend((4096..len).step_by(509.max(len / 2048)));
    points.extend(len.saturating_sub(2048).max(4096)..len);
    points
}

#[test]
fn truncated_images_fail_or_assemble_the_same_guest_disk() {
    for &Image { name, layout, .. } in IMAGES {
        let data = fixture(name);
        let full = parse(&data);
        let expected = &guest(&full).data;
        for end in truncation_points(data.len()) {
            let prefix = &data[..end];
            if let Ok(c) = vdisk::parse_container(prefix, layout) {
                assert_eq!(&guest(&c).data, expected, "{name}: prefix {end}");
            }
            let _ = vdisk::detect(prefix);
        }
    }
    for data in [differencing_vhd(), differencing_vhdx()] {
        let layout = vdisk::detect(&data).expect("detected");
        let full = parse(&data);
        let expected = &guest(&full).data;
        for end in truncation_points(data.len()) {
            if let Ok(c) = vdisk::parse_container(&data[..end], layout) {
                assert_eq!(&guest(&c).data, expected, "{layout:?}: prefix {end}");
            }
        }
    }
}

/// Positions to mutate: every byte of the first 512 bytes (the headers),
/// every second byte of the last 512 (VHD and VMDK footers), and at most
/// 256 positions spread over the rest (every 97th byte in a small file).
/// VHDX images add their headers, region tables, metadata table and BAT.
fn mutation_points(data: &[u8]) -> Vec<usize> {
    let len = data.len();
    let mut points: Vec<usize> = (0..len.min(512)).collect();
    points.extend((512..len).step_by(97.max(len / 256)));
    points.extend((len.saturating_sub(512).max(512)..len).step_by(2));
    if data.starts_with(b"vhdxfile") {
        // The metadata table and the BAT are at 2 and 3 MiB, either way
        // round.
        for start in VHDX_HEADERS.into_iter().chain(VHDX_REGION_TABLES) {
            points.extend(start..start + 64);
        }
        for start in [2 * MIB, 3 * MIB] {
            points.extend((start..start + 224).step_by(2));
        }
    }
    points.retain(|&at| at < len);
    points
}

#[test]
fn byte_mutations_never_panic() {
    let mut images: Vec<Vec<u8>> = IMAGES.iter().map(|image| fixture(image.name)).collect();
    images.push(fixture("qcow2-overlay.qcow2"));
    images.push(differencing_vhd());
    images.push(differencing_vhdx());
    let mutations: [fn(u8) -> u8; 3] = [|_| 0x00, |_| 0xff, |b| b ^ 0x01];
    for data in &mut images {
        for at in mutation_points(data) {
            let original = data[at];
            for mutate in mutations {
                data[at] = mutate(original);
                if let Some(layout) = vdisk::detect(data) {
                    let _ = vdisk::parse_container(data, layout);
                }
            }
            data[at] = original;
        }
        // The full classification on a sample of header mutations.
        for at in (0..data.len().min(512)).step_by(16) {
            data[at] ^= 0x80;
            let _ = detect_payload(data, &ClassifierOptions::new());
            data[at] ^= 0x80;
        }
    }
}

#[test]
fn deterministic_noise_is_not_a_virtual_disk() {
    let mut x: u32 = 0x9e37_79b9;
    let noise: Vec<u8> = (0..65536)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    for end in [0, 7, 512, 1536, 4096, noise.len()] {
        assert_eq!(vdisk::detect(&noise[..end]), None);
    }
    // A `conectix` footer without a valid checksum is not a VHD.
    let mut fake = noise.clone();
    let footer = fake.len() - VHD_FOOTER;
    put(&mut fake, footer, b"conectix");
    assert_eq!(vdisk::detect(&fake), None);
}

/// Every input in `IDA_INPUT_DIR` (read-only) that is detected as a virtual
/// disk parses or fails with an error, without panicking. Skips without
/// the variable.
#[test]
fn ida_inputs_detected_as_virtual_disks_parse_without_panicking() {
    let Ok(dir) = std::env::var("IDA_INPUT_DIR") else {
        eprintln!("skipped: IDA_INPUT_DIR is not set");
        return;
    };
    let mut detected = 0usize;
    let mut scanned = 0usize;
    for entry in std::fs::read_dir(&dir).expect("IDA_INPUT_DIR is a directory") {
        let path = entry.expect("directory entry").path();
        if !path.is_file() {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        scanned += 1;
        if let Some(layout) = vdisk::detect(&data) {
            detected += 1;
            let outcome = vdisk::parse_container(&data, layout).map(|c| c.variant);
            eprintln!("{}: {layout:?}: {outcome:?}", path.display());
        }
    }
    eprintln!("{scanned} inputs scanned, {detected} detected as virtual disks");
}
