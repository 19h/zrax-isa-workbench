//! Android dynamic-partition `super` images (full and `super_empty`), DTB/
//! DTBO table images and AVB vbmeta images: partitions listed by name with
//! linear, multi-extent and zero extents, device trees classified as
//! device trees, vbmeta descriptors summarized with the hash checked,
//! checksums, corrupted fields, a sparse image of a super image of an
//! EROFS partition, and truncation and mutation sweeps. Every fixture is
//! built here from the documented layouts (liblp `metadata_format.h`,
//! libufdt `dt_table.h`, libavb `avb_vbmeta_image.h` and descriptor
//! headers); the EROFS partition is the committed mkfs.erofs fixture.

use sha2::{Digest, Sha256};
use zrax::formats::android::{self, Layout};
use zrax::formats::container::{self, Container, Kind};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> zrax::Result<Container<'_>> {
    container::parse(data, Kind::Android(layout))
}

fn error_text(data: &[u8], layout: Layout) -> String {
    parse(data, layout)
        .expect_err("is a parse error")
        .to_string()
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|n| n.contains(text))
}

fn notes(c: &Container<'_>) -> String {
    c.notes.join("\n")
}

fn payload_notes(p: &DetectionPayload) -> String {
    p.notes
        .iter()
        .map(|n| n.message.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
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

fn be32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn be64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

/// Zero bytes up to the next multiple of `size`.
fn pad_to(data: &mut Vec<u8>, size: usize) {
    let remainder = data.len() % size;
    if remainder != 0 {
        data.resize(data.len() + size - remainder, 0);
    }
}

/// Machine code for AArch64 (`transforms/aarch64.text.bin`).
fn aarch64_code() -> Vec<u8> {
    fixture("transforms/aarch64.text.bin")
}

/// Linux arm64 `Image`: `text_offset` 0x80000 (u64 at 0x08), `image_size`
/// (u64 at 0x10), magic `ARM\x64` at 0x38; then AArch64 code.
fn arm64_image(code: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 64];
    put64(&mut image, 0x08, 0x8_0000);
    put64(&mut image, 0x10, (64 + code.len()) as u64);
    image[0x38..0x3c].copy_from_slice(b"ARM\x64");
    image.extend_from_slice(code);
    image
}

// ---------------------------------------------------------------------------
// Logical partition metadata (liblp metadata_format.h, little-endian)
// ---------------------------------------------------------------------------

const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616c_4467;
const LP_METADATA_HEADER_MAGIC: u32 = 0x414c_5030;
const SECTOR: u64 = 512;

/// One `LpMetadataExtent`.
#[derive(Clone, Copy)]
enum Extent {
    /// `LP_TARGET_TYPE_LINEAR`: `sectors` at `physical` on block device
    /// `device`.
    Linear {
        sectors: u64,
        physical: u64,
        device: u32,
    },
    /// `LP_TARGET_TYPE_ZERO`.
    Zero { sectors: u64 },
}

/// One `LpMetadataPartition` with its extents, in logical order.
struct Partition<'a> {
    name: &'a str,
    attributes: u32,
    group: u32,
    extents: Vec<Extent>,
}

/// One `LpMetadataBlockDevice`: name, size in bytes, first logical sector.
struct Device<'a> {
    name: &'a str,
    size: u64,
    first_logical_sector: u64,
}

/// The metadata of a test super image.
struct Lp<'a> {
    minor: u16,
    metadata_max_size: u32,
    slots: u32,
    partitions: Vec<Partition<'a>>,
    /// `(name, maximum size)` for each `LpMetadataPartitionGroup`.
    groups: Vec<(&'a str, u64)>,
    devices: Vec<Device<'a>>,
}

/// A NUL-padded 36-byte name field.
fn name36(name: &str) -> [u8; 36] {
    let mut field = [0u8; 36];
    field[..name.len()].copy_from_slice(name.as_bytes());
    field
}

/// `LpMetadataGeometry` in its 4096-byte block: magic, `struct_size` 52,
/// SHA-256 of the 52 bytes with the checksum zeroed (8), `metadata_max_size`
/// (40), `metadata_slot_count` (44), `logical_block_size` 4096 (48).
fn geometry(max_size: u32, slots: u32) -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    put32(&mut block, 0, LP_METADATA_GEOMETRY_MAGIC);
    put32(&mut block, 4, 52);
    put32(&mut block, 40, max_size);
    put32(&mut block, 44, slots);
    put32(&mut block, 48, 4096);
    let digest = Sha256::digest(&block[..52]);
    block[8..40].copy_from_slice(&digest);
    block
}

/// `LpMetadataHeader` (128 B for v10.0/10.1, 256 B for v10.2): magic, major
/// 10, minor, `header_size`, SHA-256 of the header with the field zeroed
/// (12), `tables_size` (44), SHA-256 of the tables (48), then the
/// partition, extent, group and block device table descriptors (80, 92,
/// 104, 116: offset, count, entry size). The tables follow in that order:
/// partitions (52 B: name, attributes, first extent, extent count, group),
/// extents (24 B: sectors, target type, target data, target source),
/// groups (48 B: name, flags, maximum size) and block devices (64 B: first
/// logical sector, alignment, alignment offset, size, name, flags).
fn metadata(lp: &Lp<'_>) -> Vec<u8> {
    let mut partitions = Vec::new();
    let mut extents = Vec::new();
    for p in &lp.partitions {
        let mut entry = vec![0u8; 52];
        entry[..36].copy_from_slice(&name36(p.name));
        put32(&mut entry, 36, p.attributes);
        put32(&mut entry, 40, u32::try_from(extents.len() / 24).unwrap());
        put32(&mut entry, 44, u32::try_from(p.extents.len()).unwrap());
        put32(&mut entry, 48, p.group);
        partitions.extend_from_slice(&entry);
        for extent in &p.extents {
            let mut record = vec![0u8; 24];
            match *extent {
                Extent::Linear {
                    sectors,
                    physical,
                    device,
                } => {
                    put64(&mut record, 0, sectors);
                    put64(&mut record, 12, physical);
                    put32(&mut record, 20, device);
                }
                Extent::Zero { sectors } => {
                    put64(&mut record, 0, sectors);
                    put32(&mut record, 8, 1);
                }
            }
            extents.extend_from_slice(&record);
        }
    }
    let mut groups = Vec::new();
    for (name, maximum) in &lp.groups {
        let mut entry = vec![0u8; 48];
        entry[..36].copy_from_slice(&name36(name));
        put64(&mut entry, 40, *maximum);
        groups.extend_from_slice(&entry);
    }
    let mut devices = Vec::new();
    for d in &lp.devices {
        let mut entry = vec![0u8; 64];
        put64(&mut entry, 0, d.first_logical_sector);
        put32(&mut entry, 8, 1 << 20);
        put64(&mut entry, 16, d.size);
        entry[24..60].copy_from_slice(&name36(d.name));
        devices.extend_from_slice(&entry);
    }
    let header_size = if lp.minor >= 2 { 256 } else { 128 };
    let mut header = vec![0u8; header_size];
    put32(&mut header, 0, LP_METADATA_HEADER_MAGIC);
    put16(&mut header, 4, 10);
    put16(&mut header, 6, lp.minor);
    put32(&mut header, 8, u32::try_from(header_size).unwrap());
    let tables = [&partitions, &extents, &groups, &devices];
    let sizes = [52u32, 24, 48, 64];
    let mut offset = 0u32;
    for (k, (table, size)) in tables.iter().zip(sizes).enumerate() {
        let at = 80 + 12 * k;
        put32(&mut header, at, offset);
        put32(
            &mut header,
            at + 4,
            u32::try_from(table.len()).unwrap() / size,
        );
        put32(&mut header, at + 8, size);
        offset += u32::try_from(table.len()).unwrap();
    }
    put32(&mut header, 44, offset);
    let body: Vec<u8> = tables
        .iter()
        .flat_map(|table| table.iter().copied())
        .collect();
    header[48..80].copy_from_slice(&Sha256::digest(&body));
    let digest = Sha256::digest(&header);
    header[12..44].copy_from_slice(&digest);
    header.extend_from_slice(&body);
    header
}

/// A full super image (`ImageBuilder::Build`): 4096 reserved zero bytes,
/// the geometry twice, `slots * 2` metadata copies of `metadata_max_size`
/// bytes, then `contents` at their byte offsets; the file is the size of
/// block device 0.
fn super_image(lp: &Lp<'_>, contents: &[(u64, &[u8])]) -> Vec<u8> {
    let mut image = vec![0u8; 4096];
    let geometry = geometry(lp.metadata_max_size, lp.slots);
    image.extend_from_slice(&geometry);
    image.extend_from_slice(&geometry);
    let mut copy = metadata(lp);
    copy.resize(lp.metadata_max_size as usize, 0);
    for _ in 0..lp.slots * 2 {
        image.extend_from_slice(&copy);
    }
    // Without block devices (an invalid table) the image is 64 KiB.
    let size = lp.devices.first().map_or(64 << 10, |device| device.size);
    image.resize(usize::try_from(size).unwrap(), 0);
    for (offset, bytes) in contents {
        let at = usize::try_from(*offset).unwrap();
        image[at..at + bytes.len()].copy_from_slice(bytes);
    }
    image
}

/// Offset of the first metadata copy in a full image.
const METADATA_AT: usize = 4096 + 2 * 4096;

/// A two-slot layout: 4 KiB metadata copies, partitions from sector 64
/// (32 KiB) on a 64 KiB `super` device, plus a retrofit second device.
/// `system` is one linear extent at sector 64; `vendor` is two linear
/// extents, the second stored before the first, and a zero extent;
/// `product` has no extents; `odm` lies on block device 1.
fn sample_lp<'a>() -> Lp<'a> {
    Lp {
        minor: 2,
        metadata_max_size: 4096,
        slots: 2,
        partitions: vec![
            Partition {
                name: "system",
                attributes: 1,
                group: 1,
                extents: vec![Extent::Linear {
                    sectors: 8,
                    physical: 64,
                    device: 0,
                }],
            },
            Partition {
                name: "vendor",
                attributes: 1,
                group: 1,
                extents: vec![
                    Extent::Linear {
                        sectors: 8,
                        physical: 88,
                        device: 0,
                    },
                    Extent::Linear {
                        sectors: 8,
                        physical: 72,
                        device: 0,
                    },
                    Extent::Zero { sectors: 8 },
                ],
            },
            Partition {
                name: "product",
                attributes: 0,
                group: 0,
                extents: Vec::new(),
            },
            Partition {
                name: "odm",
                attributes: 0,
                group: 0,
                extents: vec![Extent::Linear {
                    sectors: 8,
                    physical: 2048,
                    device: 1,
                }],
            },
        ],
        groups: vec![("default", 0), ("main", 8 << 20)],
        devices: vec![
            Device {
                name: "super",
                size: 64 << 10,
                first_logical_sector: 64,
            },
            Device {
                name: "system_b",
                size: 4 << 20,
                first_logical_sector: 2048,
            },
        ],
    }
}

/// The sample image: an x86-64 ELF header in `system`, an arm64 `Image`
/// split across `vendor`'s two linear extents.
fn sample_super() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let elf = fixture("compressed/payload.elf");
    let mut vendor = arm64_image(&aarch64_code());
    vendor.resize(8192, 0);
    let image = super_image(
        &sample_lp(),
        &[
            (64 * SECTOR, &elf),
            (88 * SECTOR, &vendor[..4096]),
            (72 * SECTOR, &vendor[4096..]),
        ],
    );
    (image, elf, vendor)
}

#[test]
fn super_partitions_are_members_by_name_with_their_extents_assembled() {
    let (image, elf, vendor) = sample_super();
    assert_eq!(android::detect(&image), Some(Layout::Super));
    let c = parse(&image, Layout::Super).expect("parses");
    assert_eq!(c.variant, "super image (LP metadata v10.2)");
    let names: Vec<&str> = c.children.iter().map(|ch| ch.label.as_str()).collect();
    assert_eq!(names, ["system", "vendor"]);
    let system = &c.children[0];
    assert_eq!((system.offset, system.stored_size), (32768, 4096));
    assert_eq!(&system.data[..elf.len()], &elf[..]);
    assert_eq!(system.transform, None);
    let assembled = &c.children[1];
    assert_eq!(assembled.transform, Some("LP extents"));
    assert_eq!((assembled.offset, assembled.stored_size), (88 * 512, 4096));
    assert_eq!(assembled.data.len(), 12288);
    assert_eq!(&assembled.data[..8192], &vendor[..]);
    assert_eq!(&assembled.data[8192..], &[0u8; 4096][..]);
    for text in [
        "Logical partition metadata v10.2: 4 partitions in 2 groups on 2 block devices; geometry, header and table SHA-256 checksums verified",
        "2 metadata slots; slot 0 was read",
        "vendor: 1 zero extent filled with zeros",
        "vendor: 3 extents assembled into one 12 KiB image",
        "product: no extents (empty partition)",
        "odm: an extent lies on block device 1 (system_b), which is not in this file; not extracted",
        "The metadata names no CPU",
    ] {
        assert!(has_note(&c, text), "{text}\n{}", notes(&c));
    }

    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AndroidSuper);
    assert_eq!(p.primary.isa, Isa::X86_64, "{}", payload_notes(&p));
    assert_eq!(slice(&p, "system").isa, Isa::X86_64);
    let vendor_slice = slice(&p, "vendor");
    assert_eq!(vendor_slice.isa, Isa::AArch64);
    assert_eq!(
        vendor_slice
            .decoded
            .as_ref()
            .map(|d| (d.transform.as_str(), d.size)),
        Some(("LP extents", 12288))
    );
    let metadata = |key: &str| {
        p.metadata
            .iter()
            .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
            .map(|m| m.value.to_string())
            .unwrap_or_else(|| panic!("metadata {key}"))
    };
    assert_eq!(
        metadata("android_super_partition_1"),
        "vendor: group main; 3 extents (2 linear, 1 zero); 12288 B; readonly"
    );
    assert_eq!(
        metadata("android_super_group_1"),
        "main: maximum size 8388608 B"
    );
    assert_eq!(
        metadata("android_super_block_device_0"),
        "super: 65536 B; first logical sector 64"
    );
}

#[test]
fn super_empty_images_hold_the_metadata_only() {
    let lp = Lp {
        minor: 0,
        ..sample_lp()
    };
    let mut image = geometry(lp.metadata_max_size, lp.slots);
    image.extend_from_slice(&metadata(&lp));
    assert_eq!(android::detect(&image), Some(Layout::Super));
    let c = parse(&image, Layout::Super).expect("parses");
    assert_eq!(c.variant, "super_empty image (LP metadata v10.0)");
    assert!(c.children.is_empty());
    assert_eq!(c.consumed, image.len());
    assert!(
        has_note(&c, "super_empty image: metadata only"),
        "{}",
        notes(&c)
    );
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AndroidSuper);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

#[test]
fn damaged_primary_copies_fall_back_to_the_backups() {
    let (image, _, _) = sample_super();
    let mut geometry = image.clone();
    geometry[4096 + 40] ^= 1;
    let c = parse(&geometry, Layout::Super).expect("backup geometry");
    assert!(
        has_note(
            &c,
            "Primary LP geometry not used (Invalid LP geometry checksum at 0x1000); the backup geometry at 0x2000 was read"
        ),
        "{}",
        notes(&c)
    );
    geometry[8192 + 40] ^= 1;
    assert!(error_text(&geometry, Layout::Super).contains("Invalid LP geometry checksum at 0x1000"));

    let mut header = image.clone();
    header[METADATA_AT + 12] ^= 1;
    let c = parse(&header, Layout::Super).expect("backup metadata");
    // Slot 0's backup follows the two primary slots.
    assert!(
        has_note(&c, "the backup copy at 0x5000 was read"),
        "{}",
        notes(&c)
    );
    header[0x5000 + 12] ^= 1;
    assert!(error_text(&header, Layout::Super)
        .contains("Invalid LP metadata header checksum at 0x3000"));

    let mut tables = image.clone();
    tables[METADATA_AT + 256] ^= 1;
    tables[0x5000 + 256] ^= 1;
    assert!(error_text(&tables, Layout::Super)
        .contains("Invalid LP metadata tables checksum at 0x3100"));
}

/// Rebuild the sample image after `change` edits its metadata.
fn sample_with(change: impl FnOnce(&mut Lp<'_>)) -> Vec<u8> {
    let mut lp = sample_lp();
    change(&mut lp);
    super_image(&lp, &[])
}

#[test]
fn inconsistent_metadata_is_a_format_error() {
    let attributes = sample_with(|lp| lp.partitions[0].attributes = 0x10);
    assert!(
        error_text(&attributes, Layout::Super).contains("Invalid LP partition 0 attributes 0x10")
    );
    let updated = sample_with(|lp| {
        lp.minor = 0;
        lp.partitions[0].attributes = 4;
    });
    assert!(error_text(&updated, Layout::Super).contains("Invalid LP partition 0 attributes 0x4"));
    let group = sample_with(|lp| lp.partitions[1].group = 2);
    assert!(error_text(&group, Layout::Super).contains("Invalid LP partition 1: group index 2"));
    let device = sample_with(|lp| {
        lp.partitions[0].extents[0] = Extent::Linear {
            sectors: 8,
            physical: 64,
            device: 2,
        };
    });
    assert!(error_text(&device, Layout::Super).contains("Invalid LP extent 0: block device 2"));
    let overlap = sample_with(|lp| lp.devices[0].first_logical_sector = 40);
    assert!(error_text(&overlap, Layout::Super).contains("overlaps the first logical sector 40"));
    let none = sample_with(|lp| {
        lp.partitions.clear();
        lp.devices.clear();
    });
    assert!(error_text(&none, Layout::Super).contains("Missing LP super block device"));

    let (image, _, _) = sample_super();
    let mut version = image.clone();
    put16(&mut version, METADATA_AT + 4, 11);
    version[0x5000 + 4] = 11;
    assert!(error_text(&version, Layout::Super).contains("Unsupported LP metadata version 11.2"));
    let mut slots = image.clone();
    put32(&mut slots, 4096 + 44, 0);
    put32(&mut slots, 8192 + 44, 0);
    assert!(error_text(&slots, Layout::Super).contains("Invalid LP geometry checksum"));
}

#[test]
fn partitions_beyond_the_file_are_noted_and_not_listed() {
    let (image, _, _) = sample_super();
    // A sparse expansion cut short, or a truncated download.
    let cut = &image[..40 * 1024];
    let c = parse(cut, Layout::Super).expect("metadata is complete");
    let names: Vec<&str> = c.children.iter().map(|ch| ch.label.as_str()).collect();
    assert_eq!(names, ["system"]);
    assert!(
        has_note(
            &c,
            "vendor: extents end at 0xC000, beyond the 40960 B in the file"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "The file holds 40960 B of the 65536 B of block device super"
    ));
}

#[test]
fn every_prefix_errors_or_lists_only_what_it_holds() {
    let (image, _, _) = sample_super();
    // The first metadata copy (header and tables) ends here; a shorter
    // prefix cuts both it and its backup.
    let metadata_end = METADATA_AT + metadata(&sample_lp()).len();
    for end in 0..image.len() {
        match parse(&image[..end], Layout::Super) {
            Ok(c) => {
                assert!(end >= metadata_end, "prefix {end} parses");
                assert!(c
                    .children
                    .iter()
                    .all(|ch| ch.offset + ch.stored_size <= end));
            }
            Err(_) => assert!(end < metadata_end, "prefix {end} is an error"),
        }
    }
}

// ---------------------------------------------------------------------------
// Sparse image of a super image of an EROFS partition
// ---------------------------------------------------------------------------

/// `sparse_header_t` (little-endian): magic `0xED26FF3A`, version 1.0,
/// header sizes 28 and 12, block size 4096, total blocks, one RAW chunk
/// (`0xCAC1`: type, reserved, output blocks, input bytes with the header)
/// holding `raw`, checksum 0.
fn sparse(raw: &[u8]) -> Vec<u8> {
    let blocks = u32::try_from(raw.len() / 4096).unwrap();
    let mut image = vec![0u8; 28];
    put32(&mut image, 0, 0xed26_ff3a);
    put16(&mut image, 4, 1);
    put16(&mut image, 8, 28);
    put16(&mut image, 10, 12);
    put32(&mut image, 12, 4096);
    put32(&mut image, 16, blocks);
    put32(&mut image, 20, 1);
    let mut chunk = vec![0u8; 12];
    put16(&mut chunk, 0, 0xcac1);
    put32(&mut chunk, 4, blocks);
    put32(&mut chunk, 8, u32::try_from(12 + raw.len()).unwrap());
    image.extend_from_slice(&chunk);
    image.extend_from_slice(raw);
    image
}

#[test]
fn a_sparse_super_image_of_an_erofs_partition_is_classified_through_both() {
    let erofs = fixture("erofs/lz4.img");
    let sectors = (erofs.len() as u64).div_euclid(SECTOR);
    let lp = Lp {
        partitions: vec![Partition {
            name: "system",
            attributes: 1,
            group: 0,
            extents: vec![Extent::Linear {
                sectors,
                physical: 64,
                device: 0,
            }],
        }],
        groups: vec![("default", 0)],
        devices: vec![Device {
            name: "super",
            size: 32768 + erofs.len() as u64,
            first_logical_sector: 64,
        }],
        ..sample_lp()
    };
    let image = super_image(&lp, &[(64 * SECTOR, &erofs)]);
    let sparse = sparse(&image);
    let p = classify(&sparse);
    assert_eq!(p.format.format, FileFormat::AndroidSparse);
    assert_eq!(p.primary.isa, Isa::X86_64, "{}", payload_notes(&p));
    let text = payload_notes(&p);
    assert!(
        text.contains("Expanded image: x86_64 (contained Android super image)"),
        "{text}"
    );

    let direct = classify(&image);
    assert_eq!(direct.format.format, FileFormat::AndroidSuper);
    assert_eq!(slice(&direct, "system").isa, Isa::X86_64);
    let c = parse(&image, Layout::Super).expect("parses");
    assert_eq!(
        zrax::formats::erofs::detect(&c.children[0].data),
        Some(zrax::formats::erofs::Layout::Erofs)
    );
}

// ---------------------------------------------------------------------------
// DTB/DTBO tables (libufdt dt_table.h, big-endian)
// ---------------------------------------------------------------------------

/// A flattened device tree (big-endian): a 40-byte header (magic
/// `D00DFEED`, `totalsize`, `off_dt_struct` 56, `off_dt_strings`,
/// `off_mem_rsvmap` 40, version 17, last compatible version 16, boot CPU 0,
/// `size_dt_strings`, `size_dt_struct`), an empty reservation map, then a
/// root node with one `model` property and the strings block `model\0`.
fn fdt(model: &str) -> Vec<u8> {
    let mut structure = Vec::new();
    structure.extend_from_slice(&1u32.to_be_bytes()); // FDT_BEGIN_NODE
    structure.extend_from_slice(&[0; 4]); // root name "", padded
    let mut value = model.as_bytes().to_vec();
    value.push(0);
    structure.extend_from_slice(&3u32.to_be_bytes()); // FDT_PROP
    structure.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    structure.extend_from_slice(&0u32.to_be_bytes()); // nameoff of "model"
    structure.extend_from_slice(&value);
    pad_to(&mut structure, 4);
    structure.extend_from_slice(&2u32.to_be_bytes()); // FDT_END_NODE
    structure.extend_from_slice(&9u32.to_be_bytes()); // FDT_END
    let strings = b"model\0";
    let struct_at = 56;
    let strings_at = struct_at + structure.len();
    let total = strings_at + strings.len();
    let mut tree = vec![0u8; struct_at];
    be32(&mut tree, 0, 0xd00d_feed);
    be32(&mut tree, 4, u32::try_from(total).unwrap());
    be32(&mut tree, 8, u32::try_from(struct_at).unwrap());
    be32(&mut tree, 12, u32::try_from(strings_at).unwrap());
    be32(&mut tree, 16, 40);
    be32(&mut tree, 20, 17);
    be32(&mut tree, 24, 16);
    be32(&mut tree, 32, u32::try_from(strings.len()).unwrap());
    be32(&mut tree, 36, u32::try_from(structure.len()).unwrap());
    tree.extend_from_slice(&structure);
    tree.extend_from_slice(strings);
    tree
}

/// One `dt_table_entry`: the blob, `id`, `rev`, and the word at 16
/// (`custom[0]` in version 0, `flags` in version 1). `same_as` reuses an
/// earlier entry's blob, as `mkdtimg` does for repeated files.
struct DtEntry {
    blob: Vec<u8>,
    id: u32,
    rev: u32,
    word4: u32,
    same_as: Option<usize>,
}

/// `dt_table_header` (32 B): magic `0xD7B7AB1E`, `total_size`,
/// `header_size` 32, `dt_entry_size` 32, `dt_entry_count`,
/// `dt_entries_offset` 32, `page_size` 2048, `version`; then the entries
/// (`dt_size`, `dt_offset` from the header, `id`, `rev`, word 4, three
/// custom words) and the blobs back to back.
fn dtbo(version: u32, entries: &[DtEntry]) -> Vec<u8> {
    let mut image = vec![0u8; 32 + 32 * entries.len()];
    let mut placed: Vec<(usize, usize)> = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let (offset, size) = match entry.same_as {
            Some(k) => placed[k],
            None => {
                let offset = image.len();
                image.extend_from_slice(&entry.blob);
                (offset, entry.blob.len())
            }
        };
        placed.push((offset, size));
        let at = 32 + 32 * i;
        be32(&mut image, at, u32::try_from(size).unwrap());
        be32(&mut image, at + 4, u32::try_from(offset).unwrap());
        be32(&mut image, at + 8, entry.id);
        be32(&mut image, at + 12, entry.rev);
        be32(&mut image, at + 16, entry.word4);
    }
    let total = u32::try_from(image.len()).unwrap();
    be32(&mut image, 0, 0xd7b7_ab1e);
    be32(&mut image, 4, total);
    be32(&mut image, 8, 32);
    be32(&mut image, 12, 32);
    be32(&mut image, 16, u32::try_from(entries.len()).unwrap());
    be32(&mut image, 20, 32);
    be32(&mut image, 24, 2048);
    be32(&mut image, 28, version);
    image
}

fn dt_entry(blob: Vec<u8>, id: u32, word4: u32) -> DtEntry {
    DtEntry {
        blob,
        id,
        rev: 1,
        word4,
        same_as: None,
    }
}

/// One gzip member (RFC 1952): fixed header, DEFLATE data, CRC-32, size.
fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
    member.extend_from_slice(&zrax::formats::checksum::crc32(payload).to_le_bytes());
    member.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    member
}

/// A zlib stream (RFC 1950).
fn zlib(payload: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(payload, 6)
}

#[test]
fn dtbo_entries_are_device_trees_classified_on_their_own() {
    let mut shared = dt_entry(Vec::new(), 0x30, 0);
    shared.same_as = Some(0);
    let image = dtbo(
        0,
        &[
            dt_entry(fdt("board one"), 0x10, 0xabc),
            dt_entry(fdt("board two"), 0x20, 0),
            shared,
        ],
    );
    assert_eq!(android::detect(&image), Some(Layout::Dtbo));
    let c = parse(&image, Layout::Dtbo).expect("parses");
    assert_eq!(c.variant, "DTBO table v0");
    let labels: Vec<&str> = c.children.iter().map(|ch| ch.label.as_str()).collect();
    assert_eq!(
        labels,
        [
            "DT entry 0 (id 0x10, rev 0x1)",
            "DT entry 1 (id 0x20, rev 0x1)"
        ]
    );
    assert_eq!(c.children[0].offset, 32 + 3 * 32);
    assert!(!c.children[0].opaque);
    assert!(
        has_note(&c, "DTBO table version 0: 3 entries; page size 2048 B"),
        "{}",
        notes(&c)
    );
    assert!(has_note(&c, "1 entry shares the blob of an earlier entry"));

    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AndroidDtbo);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    let text = payload_notes(&p);
    assert!(
        text.contains("DT entry 0 (id 0x10, rev 0x1): unknown(0x0000) (contained DTB)"),
        "{text}"
    );
    assert!(slice(&p, "DT entry 1 (id 0x20, rev 0x1)").decoded.is_none());
    let metadata = p
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == "android_dtbo_entry_0"))
        .map(|m| m.value.to_string())
        .unwrap();
    assert!(
        metadata.contains("id 0x10; rev 0x1; custom 0xABC 0x0 0x0 0x0"),
        "{metadata}"
    );
}

#[test]
fn dtbo_version_1_entries_are_decompressed() {
    let one = fdt("gzip board");
    let two = fdt("zlib board");
    let image = dtbo(
        1,
        &[
            dt_entry(gzip(&one), 1, 2),
            dt_entry(zlib(&two), 2, 1),
            dt_entry(fdt("plain"), 3, 0),
            dt_entry(vec![0x5a; 16], 4, 7),
        ],
    );
    let c = parse(&image, Layout::Dtbo).expect("parses");
    assert_eq!(c.children[0].transform, Some("gzip"));
    assert_eq!(&c.children[0].data[..], &one[..]);
    assert_eq!(c.children[1].transform, Some("zlib"));
    assert_eq!(&c.children[1].data[..], &two[..]);
    assert_eq!(c.children[2].transform, None);
    assert!(c.children[3].opaque);
    assert!(
        has_note(
            &c,
            "DT entry 3 (id 0x4, rev 0x1): unknown compression format 7; kept opaque"
        ),
        "{}",
        notes(&c)
    );
}

#[test]
fn dtbo_tables_with_a_partition_tail_note_the_avb_footer() {
    let mut image = dtbo(0, &[dt_entry(fdt("board"), 1, 0)]);
    let original = image.len() as u64;
    image.resize(8192 - 64, 0);
    let mut footer = vec![0u8; 64];
    footer[..4].copy_from_slice(b"AVBf");
    footer[4..8].copy_from_slice(&1u32.to_be_bytes());
    footer[12..20].copy_from_slice(&original.to_be_bytes());
    footer[20..28].copy_from_slice(&8192u64.to_be_bytes());
    image.extend_from_slice(&footer);
    let c = parse(&image, Layout::Dtbo).expect("parses");
    assert!(
        has_note(
            &c,
            "AVB footer names a vbmeta image at 0x2000 (0 B) that is not in the file"
        ),
        "{}",
        notes(&c)
    );
}

#[test]
fn dtbo_corruption_is_a_format_error() {
    let image = dtbo(0, &[dt_entry(fdt("board"), 1, 0)]);
    let mut header_size = image.clone();
    be32(&mut header_size, 8, 36);
    assert!(
        error_text(&header_size, Layout::Dtbo).contains("Unsupported DTBO table header_size 36 B")
    );
    let mut version = image.clone();
    be32(&mut version, 28, 2);
    assert!(error_text(&version, Layout::Dtbo).contains("Unsupported DTBO table version 2"));
    let mut total = image.clone();
    be32(&mut total, 4, u32::try_from(image.len() + 1).unwrap());
    assert!(error_text(&total, Layout::Dtbo).contains("Truncated DTBO table: total_size"));
    let mut count = image.clone();
    be32(&mut count, 16, 1000);
    assert!(error_text(&count, Layout::Dtbo).contains("1000 entries at 0x20 do not fit"));
    let mut blob = image.clone();
    be32(&mut blob, 36, 16);
    assert!(
        error_text(&blob, Layout::Dtbo).contains("Invalid DTBO table entry 0 at 0x20: blob 0x10")
    );
    for end in 0..image.len() {
        assert!(parse(&image[..end], Layout::Dtbo).is_err(), "prefix {end}");
    }
}

// ---------------------------------------------------------------------------
// AVB vbmeta images (libavb, big-endian)
// ---------------------------------------------------------------------------

/// One descriptor: `tag` and `num_bytes_following` (u64 each), then the
/// fields, padded to a multiple of 8.
fn descriptor(tag: u64, fields: &[u8]) -> Vec<u8> {
    let mut body = fields.to_vec();
    pad_to(&mut body, 8);
    let mut out = vec![0u8; 16];
    be64(&mut out, 0, tag);
    be64(&mut out, 8, body.len() as u64);
    out.extend_from_slice(&body);
    out
}

/// `AvbPropertyDescriptor` (tag 0): key and value sizes, then key, NUL,
/// value, NUL.
fn property(key: &str, value: &str) -> Vec<u8> {
    let mut fields = vec![0u8; 16];
    be64(&mut fields, 0, key.len() as u64);
    be64(&mut fields, 8, value.len() as u64);
    fields.extend_from_slice(key.as_bytes());
    fields.push(0);
    fields.extend_from_slice(value.as_bytes());
    fields.push(0);
    descriptor(0, &fields)
}

/// `AvbHashtreeDescriptor` (tag 1) for `partition`: dm-verity version 1,
/// image size, tree offset and size, 4096 B data and hash blocks, 2 FEC
/// roots with offset and size, `sha1`, name, salt (16 B) and root digest
/// (20 B) lengths, flags 0, reserved.
fn hashtree(partition: &str) -> Vec<u8> {
    let mut fields = vec![0u8; 164];
    fields[..4].copy_from_slice(&1u32.to_be_bytes());
    fields[4..12].copy_from_slice(&(8u64 << 20).to_be_bytes());
    fields[12..20].copy_from_slice(&(8u64 << 20).to_be_bytes());
    fields[20..28].copy_from_slice(&65536u64.to_be_bytes());
    fields[28..32].copy_from_slice(&4096u32.to_be_bytes());
    fields[32..36].copy_from_slice(&4096u32.to_be_bytes());
    fields[36..40].copy_from_slice(&2u32.to_be_bytes());
    fields[40..48].copy_from_slice(&((8u64 << 20) + 65536).to_be_bytes());
    fields[48..56].copy_from_slice(&16384u64.to_be_bytes());
    fields[56..60].copy_from_slice(b"sha1");
    fields[88..92].copy_from_slice(&u32::try_from(partition.len()).unwrap().to_be_bytes());
    fields[92..96].copy_from_slice(&16u32.to_be_bytes());
    fields[96..100].copy_from_slice(&20u32.to_be_bytes());
    fields.extend_from_slice(partition.as_bytes());
    fields.extend_from_slice(&[0x11; 16]);
    fields.extend_from_slice(&[0x22; 20]);
    descriptor(1, &fields)
}

/// `AvbHashDescriptor` (tag 2): image size, `sha256`, name, salt (32 B)
/// and digest (32 B) lengths, flags 0, reserved, then the three fields.
fn hash_descriptor(partition: &str, image_size: u64) -> Vec<u8> {
    let mut fields = vec![0u8; 116];
    fields[..8].copy_from_slice(&image_size.to_be_bytes());
    fields[8..14].copy_from_slice(b"sha256");
    fields[40..44].copy_from_slice(&u32::try_from(partition.len()).unwrap().to_be_bytes());
    fields[44..48].copy_from_slice(&32u32.to_be_bytes());
    fields[48..52].copy_from_slice(&32u32.to_be_bytes());
    fields.extend_from_slice(partition.as_bytes());
    fields.extend_from_slice(&[0x33; 32]);
    fields.extend_from_slice(&[0x44; 32]);
    descriptor(2, &fields)
}

/// `AvbKernelCmdlineDescriptor` (tag 3): flags, length, the command line.
fn cmdline(flags: u32, text: &str) -> Vec<u8> {
    let mut fields = vec![0u8; 8];
    fields[..4].copy_from_slice(&flags.to_be_bytes());
    fields[4..8].copy_from_slice(&u32::try_from(text.len()).unwrap().to_be_bytes());
    fields.extend_from_slice(text.as_bytes());
    descriptor(3, &fields)
}

/// `AvbChainPartitionDescriptor` (tag 4): rollback index location, name
/// and public key lengths, flags 0, reserved, then name and key.
fn chain(partition: &str, location: u32, key: &[u8]) -> Vec<u8> {
    let mut fields = vec![0u8; 76];
    fields[..4].copy_from_slice(&location.to_be_bytes());
    fields[4..8].copy_from_slice(&u32::try_from(partition.len()).unwrap().to_be_bytes());
    fields[8..12].copy_from_slice(&u32::try_from(key.len()).unwrap().to_be_bytes());
    fields.extend_from_slice(partition.as_bytes());
    fields.extend_from_slice(key);
    descriptor(4, &fields)
}

/// The descriptors of the sample vbmeta image.
fn sample_descriptors() -> Vec<u8> {
    [
        property("com.android.build.boot.os_version", "14"),
        hash_descriptor("boot", 16384),
        hashtree("system"),
        cmdline(1, "dm=\"1 vroot none ro 1,0 16384 verity 1\""),
        chain("vbmeta_system", 1, &[0x55; 8]),
    ]
    .concat()
}

/// `AvbVBMetaImageHeader` (256 B): magic `AVB0`, required libavb 1.0,
/// authentication and auxiliary block sizes (multiples of 64), algorithm,
/// hash (offset 0, 32 B) and signature (offset 32, 512 B) in the
/// authentication block, public key (offset 0, 8 B) and descriptors (offset
/// 64) in the auxiliary block, rollback index 7, flags, rollback index
/// location 0, release string `avbtool 1.3.0`. The hash is SHA-256 of the
/// header and the auxiliary block for SHA256 algorithms, zero for `NONE`;
/// the signature is a placeholder.
fn vbmeta(algorithm: u32, descriptors: &[u8]) -> Vec<u8> {
    let mut auxiliary = vec![0x66u8; 64];
    auxiliary.extend_from_slice(descriptors);
    pad_to(&mut auxiliary, 64);
    let authentication_size = 576u64;
    let mut header = vec![0u8; 256];
    header[..4].copy_from_slice(b"AVB0");
    be32(&mut header, 4, 1);
    be64(&mut header, 12, authentication_size);
    be64(&mut header, 20, auxiliary.len() as u64);
    be32(&mut header, 28, algorithm);
    be64(&mut header, 40, if algorithm == 0 { 0 } else { 32 });
    be64(&mut header, 48, 32);
    be64(&mut header, 56, if algorithm == 0 { 0 } else { 512 });
    be64(&mut header, 72, 8);
    be64(&mut header, 96, 64);
    be64(&mut header, 104, descriptors.len() as u64);
    be64(&mut header, 112, 7);
    header[128..141].copy_from_slice(b"avbtool 1.3.0");
    let mut authentication = vec![0u8; 576];
    if algorithm != 0 {
        let digest = Sha256::new()
            .chain_update(&header)
            .chain_update(&auxiliary)
            .finalize();
        authentication[..32].copy_from_slice(&digest);
        authentication[32..544].fill(0x77);
    }
    let mut image = header;
    image.extend_from_slice(&authentication);
    image.extend_from_slice(&auxiliary);
    image
}

/// `AVB_ALGORITHM_TYPE_SHA256_RSA4096`.
const SHA256_RSA4096: u32 = 2;

#[test]
fn vbmeta_descriptors_are_summarized_and_the_hash_is_checked() {
    let image = vbmeta(SHA256_RSA4096, &sample_descriptors());
    assert_eq!(android::detect(&image), Some(Layout::Vbmeta));
    let c = parse(&image, Layout::Vbmeta).expect("parses");
    assert!(c.opaque);
    assert!(c.children.is_empty());
    assert_eq!(c.consumed, image.len());
    for text in [
        "AVB vbmeta image: requires libavb 1.0; SHA256_RSA4096; rollback index 7 at location 0; 5 descriptors",
        "SHA-256 of the header and auxiliary block matches the stored hash; RSA signature not verified",
        "Property com.android.build.boot.os_version = 14",
        "Hash descriptor for boot: sha256 over 16384 B; digest 32 B, not verified",
        "Hashtree descriptor for system: dm-verity v1, 8388608 B image, sha1, 4096 B data and 4096 B hash blocks, tree at 0x800000 (65536 B), FEC 2 roots at 0x810000 (16384 B); root digest 20 B, not verified",
        "Kernel cmdline descriptor (flags 0x1): dm=\"1 vroot none ro 1,0 16384 verity 1\"",
        "Chain partition descriptor for vbmeta_system: rollback index location 1, 8 B public key",
    ] {
        assert!(has_note(&c, text), "{text}\n{}", notes(&c));
    }
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AndroidVbmeta);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
    assert!(payload_notes(&p).contains("metadata-only; ISA analysis was not applied"));
}

#[test]
fn vbmeta_hash_mismatches_and_unsigned_images_are_reported() {
    let mut image = vbmeta(SHA256_RSA4096, &sample_descriptors());
    let key_at = image.len() - 64;
    image[key_at] ^= 1;
    let c = parse(&image, Layout::Vbmeta).expect("parses");
    assert!(has_note(
        &c,
        "SHA-256 of the header and auxiliary block does not match the stored hash"
    ));
    let unsigned = vbmeta(0, &sample_descriptors());
    let c = parse(&unsigned, Layout::Vbmeta).expect("parses");
    assert!(
        has_note(&c, "Algorithm NONE: the image is not signed"),
        "{}",
        notes(&c)
    );
}

#[test]
fn vbmeta_corruption_is_a_format_error() {
    let image = vbmeta(SHA256_RSA4096, &sample_descriptors());
    let mut release = image.clone();
    release[128..176].fill(b'x');
    assert!(error_text(&release, Layout::Vbmeta).contains("Invalid vbmeta release string"));
    let mut blocks = image.clone();
    be64(&mut blocks, 12, 577);
    assert!(error_text(&blocks, Layout::Vbmeta).contains("not multiples of 64"));
    let mut major = image.clone();
    be32(&mut major, 4, 2);
    assert!(error_text(&major, Layout::Vbmeta)
        .contains("Unsupported vbmeta required libavb version 2.0"));
    let mut algorithm = image.clone();
    be32(&mut algorithm, 28, 9);
    assert!(error_text(&algorithm, Layout::Vbmeta).contains("Unknown vbmeta algorithm type 9"));
    let mut hash = image.clone();
    be64(&mut hash, 32, 560);
    assert!(error_text(&hash, Layout::Vbmeta).contains("Invalid vbmeta hash range 0x230 + 32 B"));
    let mut length = image.clone();
    // The first descriptor's num_bytes_following, at auxiliary offset 64.
    be64(&mut length, 256 + 576 + 64 + 8, 12);
    assert!(error_text(&length, Layout::Vbmeta).contains("Invalid vbmeta descriptor length 12 B"));
    let location = vbmeta(SHA256_RSA4096, &chain("vbmeta_system", 0, &[1; 8]));
    assert!(error_text(&location, Layout::Vbmeta).contains("rollback index location 0"));
    let property = vbmeta(SHA256_RSA4096, &descriptor(0, &[0xff; 24]));
    assert!(error_text(&property, Layout::Vbmeta).contains("Invalid vbmeta property descriptor"));
    for end in 0..image.len() {
        assert!(
            parse(&image[..end], Layout::Vbmeta).is_err(),
            "prefix {end}"
        );
    }
}

// ---------------------------------------------------------------------------
// Mutation sweep
// ---------------------------------------------------------------------------

#[test]
fn byte_mutations_never_panic() {
    let options = ClassifierOptions::new();
    let (full, _, _) = sample_super();
    let cases: [(Vec<u8>, Layout, usize); 3] = [
        (full, Layout::Super, 0x6000),
        (
            dtbo(
                1,
                &[
                    dt_entry(gzip(&fdt("one")), 1, 2),
                    dt_entry(fdt("two"), 2, 0),
                ],
            ),
            Layout::Dtbo,
            usize::MAX,
        ),
        (
            vbmeta(SHA256_RSA4096, &sample_descriptors()),
            Layout::Vbmeta,
            usize::MAX,
        ),
    ];
    for (image, layout, dense_end) in cases {
        for i in (0..image.len()).filter(|&i| i < dense_end || i % 53 == 0) {
            for value in [0x00, 0xff, image[i] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[i] = value;
                let _ = parse(&mutated, layout);
                if i % 7 == 0 {
                    let _ = detect_payload(&mutated, &options);
                }
            }
        }
    }
}
