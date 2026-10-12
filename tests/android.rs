//! Android images: boot image headers v0 to v4 and vendor_boot v3/v4 with
//! decoded kernels and ramdisks, sparse images expanded into one partition
//! image, OTA payloads reassembled into partition images, and bootloader
//! packs (Qualcomm and ASUS `BOOTLDR!`, Qualcomm meta image, FBPK v1/v2),
//! with corrupted fields, truncation and mutation sweeps. Every fixture is
//! synthetic and built here from the documented wire layouts.

use sha2::{Digest, Sha256};
use zrax::formats::android::Layout;
use zrax::formats::checksum::{crc32, Sha1};
use zrax::formats::container::{self, Kind};
use zrax::formats::MAX_PAYLOAD;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa, MetadataValue};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// Machine code for AArch64 (`transforms/aarch64.text.bin`).
fn aarch64_code() -> Vec<u8> {
    fixture("transforms/aarch64.text.bin")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> zrax::Result<container::Container<'_>> {
    container::parse(data, Kind::Android(layout))
}

fn error_text(data: &[u8]) -> String {
    detect_payload(data, &ClassifierOptions::new())
        .expect_err("is a parse error")
        .to_string()
}

fn has_note(payload: &DetectionPayload, text: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(text))
}

fn notes(payload: &DetectionPayload) -> String {
    payload
        .notes
        .iter()
        .map(|n| n.message.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn slice<'a>(payload: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", payload.slices))
}

/// The custom metadata entry `key`, as its `Debug` text (the value type
/// has no `PartialEq`).
fn metadata(payload: &DetectionPayload, key: &str) -> Option<String> {
    payload
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| format!("{:?}", m.value))
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

/// Zero bytes up to the next multiple of `page`.
fn pad_to(data: &mut Vec<u8>, page: usize) {
    let remainder = data.len() % page;
    if remainder != 0 {
        data.resize(data.len() + page - remainder, 0);
    }
}

/// A 64-byte ELF64 little-endian header: executable, the given machine.
fn elf64(machine: u16) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut data, 16, 2);
    put16(&mut data, 18, machine);
    data
}

const EM_AARCH64: u16 = 183;
const EM_X86_64: u16 = 62;

/// Linux arm64 `Image`: `code0`/`code1` (0), `text_offset` 0x80000 (u64 at
/// 0x08), `image_size` (u64 at 0x10), flags 0, magic `ARM\x64` at 0x38;
/// then AArch64 code.
fn arm64_image(code: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 64];
    put64(&mut image, 0x08, 0x8_0000);
    put64(&mut image, 0x10, (64 + code.len()) as u64);
    image[0x38..0x3c].copy_from_slice(b"ARM\x64");
    image.extend_from_slice(code);
    image
}

/// One gzip member (RFC 1952): fixed header, DEFLATE data, CRC-32, size.
fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
    member.extend_from_slice(&crc32(payload).to_le_bytes());
    member.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    member
}

/// An LZ4 legacy frame (magic `0x184C2102`, then one block of a
/// little-endian stored size and LZ4 block data), as `lz4 -l` writes it.
fn lz4_legacy(payload: &[u8]) -> Vec<u8> {
    let block = lz4_flex::block::compress(payload);
    let mut frame = 0x184c_2102u32.to_le_bytes().to_vec();
    frame.extend_from_slice(&(block.len() as u32).to_le_bytes());
    frame.extend_from_slice(&block);
    frame
}

/// A newc cpio archive header and name for `TRAILER!!!`, gzip-compressed:
/// an empty initramfs.
fn gzip_ramdisk() -> Vec<u8> {
    let mut cpio = b"070701".to_vec();
    cpio.extend_from_slice(&[b'0'; 8 * 11]);
    cpio.extend_from_slice(b"0000000B00000000TRAILER!!!\0");
    pad_to(&mut cpio, 512);
    gzip(&cpio)
}

/// Default mkbootimg load addresses (`base 0x10000000` plus the default
/// offsets).
const KERNEL_ADDRESS: u32 = 0x1000_8000;
const RAMDISK_ADDRESS: u32 = 0x1100_0000;
const SECOND_ADDRESS: u32 = 0x10f0_0000;
const TAGS_ADDRESS: u32 = 0x1000_0100;
const DTB_ADDRESS: u64 = 0x11f0_0000;

/// `os_version` for Android 14.0.0, security patch level 2024-05:
/// `(14 << 25) | (0 << 18) | (0 << 11) | ((2024 - 2000) << 4) | 5`.
const OS_VERSION_14: u32 = (14 << 25) | (24 << 4) | 5;

/// The sections of a version 0 to 2 boot image.
#[derive(Default)]
struct PagedBoot<'a> {
    version: u32,
    page_size: u32,
    kernel: &'a [u8],
    ramdisk: &'a [u8],
    second: &'a [u8],
    /// v1 and v2 only.
    recovery_dtbo: &'a [u8],
    /// v2 only.
    dtb: &'a [u8],
    /// Overrides `header_version` at 0x28 (a Qualcomm `dt_size`).
    version_field: Option<u32>,
    /// Appended after `second` when `version_field` is set.
    appended_dt: &'a [u8],
}

/// mkbootimg's image ID: SHA-1 over each part followed by its size as a
/// little-endian u32, in the first 20 bytes of the 32-byte field.
/// (`Sha1` is checked against FIPS 180-4 vectors in its unit test.)
fn image_id(parts: &[&[u8]]) -> [u8; 32] {
    let mut sha = Sha1::new();
    for part in parts {
        sha.update(part);
        sha.update(&(part.len() as u32).to_le_bytes());
    }
    let mut id = [0u8; 32];
    id[..20].copy_from_slice(&sha.finish());
    id
}

/// `boot_img_hdr_v0` to `_v2` (mkbootimg `d2bb0af5` `bootimg.h`): magic,
/// kernel size and address, ramdisk size and address, second size and
/// address, tags address, page size, header version (0x28), OS version
/// (0x2C), name (16) at 0x30, cmdline (512) at 0x40, SHA-1 ID (32) at
/// 0x240, extra cmdline (1024) at 0x260; v1 adds the recovery DTBO size
/// (0x660), its absolute file offset (u64, 0x664) and the header size
/// (0x66C); v2 adds the DTB size (0x670) and address (u64, 0x674). The
/// header takes one page; every section starts on a page boundary.
fn paged_boot(b: &PagedBoot<'_>) -> Vec<u8> {
    let page = b.page_size as usize;
    let mut header = vec![0u8; page];
    header[..8].copy_from_slice(b"ANDROID!");
    put32(&mut header, 0x08, b.kernel.len() as u32);
    put32(&mut header, 0x0c, KERNEL_ADDRESS);
    put32(&mut header, 0x10, b.ramdisk.len() as u32);
    put32(&mut header, 0x14, RAMDISK_ADDRESS);
    put32(&mut header, 0x18, b.second.len() as u32);
    put32(&mut header, 0x1c, SECOND_ADDRESS);
    put32(&mut header, 0x20, TAGS_ADDRESS);
    put32(&mut header, 0x24, b.page_size);
    put32(&mut header, 0x28, b.version_field.unwrap_or(b.version));
    put32(&mut header, 0x2c, OS_VERSION_14);
    header[0x30..0x36].copy_from_slice(b"zboard");
    header[0x40..0x50].copy_from_slice(b"console=ttyMSM0 ");

    let mut image = header;
    let mut sections: Vec<&[u8]> = vec![b.kernel, b.ramdisk, b.second];
    if b.version_field.is_some() {
        sections.push(b.appended_dt);
    }
    for section in &sections {
        image.extend_from_slice(section);
        pad_to(&mut image, page);
    }
    let mut id_parts = sections.clone();
    if b.version >= 1 {
        let offset = image.len();
        image.extend_from_slice(b.recovery_dtbo);
        pad_to(&mut image, page);
        put32(&mut image, 0x660, b.recovery_dtbo.len() as u32);
        let recorded = if b.recovery_dtbo.is_empty() {
            0
        } else {
            offset
        };
        put64(&mut image, 0x664, recorded as u64);
        put32(&mut image, 0x66c, if b.version == 1 { 1648 } else { 1660 });
        id_parts.push(b.recovery_dtbo);
    }
    if b.version >= 2 {
        image.extend_from_slice(b.dtb);
        pad_to(&mut image, page);
        put32(&mut image, 0x670, b.dtb.len() as u32);
        put64(&mut image, 0x674, DTB_ADDRESS);
        id_parts.push(b.dtb);
    }
    let id = image_id(&id_parts);
    image[0x240..0x260].copy_from_slice(&id);
    image
}

/// `boot_img_hdr_v3`/`_v4`: magic, kernel size (0x08), ramdisk size
/// (0x0C), OS version (0x10), header size 1580/1584 (0x14), reserved
/// (16), header version (0x28), cmdline (1536) at 0x2C; v4 adds the boot
/// signature size (0x62C). Fixed 4096-byte pages: header, kernel,
/// ramdisk, then the v4 signature.
fn gki_boot(version: u32, kernel: &[u8], ramdisk: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 4096];
    image[..8].copy_from_slice(b"ANDROID!");
    put32(&mut image, 0x08, kernel.len() as u32);
    put32(&mut image, 0x0c, ramdisk.len() as u32);
    put32(&mut image, 0x10, OS_VERSION_14);
    put32(&mut image, 0x14, if version == 3 { 1580 } else { 1584 });
    put32(&mut image, 0x28, version);
    image[0x2c..0x3d].copy_from_slice(b"androidboot.gki=1");
    if version == 4 {
        put32(&mut image, 0x62c, signature.len() as u32);
    }
    for section in [kernel, ramdisk, signature] {
        image.extend_from_slice(section);
        pad_to(&mut image, 4096);
    }
    image
}

/// A vendor ramdisk table entry's content.
struct VendorRamdisk<'a> {
    name: &'a str,
    /// `VENDOR_RAMDISK_TYPE_*`: 1 platform, 2 recovery, 3 DLKM.
    kind: u32,
    data: &'a [u8],
}

/// `vendor_boot_img_hdr_v3`/`_v4`: magic `VNDRBOOT`, header version
/// (0x08), page size (0x0C), kernel address (0x10), ramdisk address
/// (0x14), vendor ramdisk size (0x18), cmdline (2048) at 0x1C, tags
/// address (0x81C), name (16) at 0x820, header size 2112/2128 (0x830), DTB
/// size (0x834), DTB address (u64, 0x838); v4 adds the ramdisk table size
/// (0x840), entry count (0x844), entry size 108 (0x848) and bootconfig
/// size (0x84C). After `ceil(header_size / page_size)` header pages come,
/// each page-aligned: the vendor ramdisks (concatenated without padding),
/// the DTB, the v4 ramdisk table (108-byte entries: size, offset in the
/// ramdisk section, type, name (32), 16 board IDs) and the bootconfig.
fn vendor_boot(
    version: u32,
    page_size: u32,
    ramdisks: &[VendorRamdisk<'_>],
    dtb: &[u8],
    bootconfig: &[u8],
) -> Vec<u8> {
    let header_size = if version == 3 { 2112 } else { 2128 };
    let page = page_size as usize;
    let mut image = vec![0u8; header_size];
    image[..8].copy_from_slice(b"VNDRBOOT");
    put32(&mut image, 0x08, version);
    put32(&mut image, 0x0c, page_size);
    put32(&mut image, 0x10, KERNEL_ADDRESS);
    put32(&mut image, 0x14, RAMDISK_ADDRESS);
    let total: usize = ramdisks.iter().map(|r| r.data.len()).sum();
    put32(&mut image, 0x18, total as u32);
    image[0x1c..0x2a].copy_from_slice(b"androidboot.x=");
    put32(&mut image, 0x81c, TAGS_ADDRESS);
    image[0x820..0x826].copy_from_slice(b"zboard");
    put32(&mut image, 0x830, header_size as u32);
    put32(&mut image, 0x834, dtb.len() as u32);
    put64(&mut image, 0x838, DTB_ADDRESS);
    let mut table = Vec::new();
    let mut offset = 0;
    for ramdisk in ramdisks {
        let mut entry = vec![0u8; 108];
        put32(&mut entry, 0x00, ramdisk.data.len() as u32);
        put32(&mut entry, 0x04, offset as u32);
        put32(&mut entry, 0x08, ramdisk.kind);
        entry[0x0c..0x0c + ramdisk.name.len()].copy_from_slice(ramdisk.name.as_bytes());
        put32(&mut entry, 0x2c, 0x1234);
        table.extend_from_slice(&entry);
        offset += ramdisk.data.len();
    }
    if version == 4 {
        put32(&mut image, 0x840, table.len() as u32);
        put32(&mut image, 0x844, ramdisks.len() as u32);
        put32(&mut image, 0x848, 108);
        put32(&mut image, 0x84c, bootconfig.len() as u32);
    }
    pad_to(&mut image, page);
    for ramdisk in ramdisks {
        image.extend_from_slice(ramdisk.data);
    }
    pad_to(&mut image, page);
    image.extend_from_slice(dtb);
    pad_to(&mut image, page);
    if version == 4 {
        image.extend_from_slice(&table);
        pad_to(&mut image, page);
        image.extend_from_slice(bootconfig);
        pad_to(&mut image, page);
    }
    image
}

/// A flattened device tree header (magic `D00DFEED`, big-endian) with an
/// empty structure block: enough to be recognized, and data in any case.
fn dtb() -> Vec<u8> {
    let mut tree = vec![0u8; 0x48];
    tree[0..4].copy_from_slice(&0xd00d_feedu32.to_be_bytes());
    tree[4..8].copy_from_slice(&0x48u32.to_be_bytes());
    tree[8..12].copy_from_slice(&0x38u32.to_be_bytes());
    tree[12..16].copy_from_slice(&0x48u32.to_be_bytes());
    tree[16..20].copy_from_slice(&0x28u32.to_be_bytes());
    tree[20..24].copy_from_slice(&17u32.to_be_bytes());
    tree[24..28].copy_from_slice(&16u32.to_be_bytes());
    tree[36..40].copy_from_slice(&0x10u32.to_be_bytes());
    tree[0x38..0x3c].copy_from_slice(&1u32.to_be_bytes());
    tree[0x40..0x44].copy_from_slice(&2u32.to_be_bytes());
    tree[0x44..0x48].copy_from_slice(&9u32.to_be_bytes());
    tree
}

/// Pad `image` to `partition_size` with a vbmeta image (`AVB0` and 252
/// zero bytes) and the 64-byte `AvbFooter` (big-endian): magic `AVBf`,
/// version 1.0, original image size, vbmeta offset and size, reserved.
fn with_avb_footer(mut image: Vec<u8>, partition_size: usize) -> Vec<u8> {
    let original = image.len() as u64;
    let vbmeta_offset = image.len();
    image.extend_from_slice(b"AVB0");
    image.resize(vbmeta_offset + 256, 0);
    image.resize(partition_size - 64, 0);
    let mut footer = vec![0u8; 64];
    footer[..4].copy_from_slice(b"AVBf");
    footer[4..8].copy_from_slice(&1u32.to_be_bytes());
    footer[12..20].copy_from_slice(&original.to_be_bytes());
    footer[20..28].copy_from_slice(&(vbmeta_offset as u64).to_be_bytes());
    footer[28..36].copy_from_slice(&256u64.to_be_bytes());
    image.extend_from_slice(&footer);
    image
}

#[test]
fn boot_v0_gzip_kernel_is_decoded_and_supplies_the_isa() {
    let kernel = gzip(&arm64_image(&aarch64_code()));
    let ramdisk = gzip_ramdisk();
    let image = paged_boot(&PagedBoot {
        version: 0,
        page_size: 2048,
        kernel: &kernel,
        ramdisk: &ramdisk,
        ..PagedBoot::default()
    });
    let payload = classify(&image);
    assert_eq!(payload.format.format, FileFormat::AndroidBoot);
    assert!(
        has_note(&payload, "Android boot image, header v0; page size 2048 B"),
        "{}",
        notes(&payload)
    );
    assert_eq!(payload.primary.isa, Isa::AArch64, "{}", notes(&payload));
    let kernel_slice = slice(&payload, "Kernel");
    assert_eq!(
        (kernel_slice.offset, kernel_slice.size),
        (2048, kernel.len() as u64)
    );
    let decoded = kernel_slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "gzip");
    assert_eq!(decoded.size, 64 + aarch64_code().len() as u64);
    let ramdisk_offset = 2048 + kernel.len().div_ceil(2048) * 2048;
    let ramdisk_slice = slice(&payload, "Ramdisk");
    assert_eq!(ramdisk_slice.offset, ramdisk_offset as u64);
    assert_eq!(
        ramdisk_slice.decoded.as_ref().map(|d| d.transform.as_str()),
        Some("gzip")
    );
    assert!(has_note(
        &payload,
        "OS version 14.0.0; security patch level 2024-05"
    ));
    assert!(has_note(&payload, "Image ID matches the mkbootimg SHA-1"));
    assert!(has_note(&payload, "Kernel: gzip stream decoded to"));
    assert!(has_note(&payload, "The header names no CPU"));
    assert_eq!(
        metadata(&payload, "android_kernel_address"),
        Some(format!(
            "{:?}",
            MetadataValue::Address(u64::from(KERNEL_ADDRESS))
        ))
    );
    assert_eq!(
        metadata(&payload, "android_board_name"),
        Some(format!("{:?}", MetadataValue::String("zboard".into())))
    );
}

#[test]
fn boot_header_names_no_isa_without_a_classifiable_kernel() {
    // The kernel is text, not code: the header's load addresses and board
    // name must not produce an ISA.
    let kernel = vec![b'k'; 600];
    let image = paged_boot(&PagedBoot {
        version: 0,
        page_size: 2048,
        kernel: &kernel,
        ..PagedBoot::default()
    });
    let c = parse(&image, Layout::Boot).expect("parses");
    assert!(c.target.is_none());
    assert_eq!(c.children.len(), 1);
    assert!(!c.children[0].opaque);
}

#[test]
fn boot_v2_places_recovery_dtbo_and_dtb_on_page_boundaries() {
    let kernel = arm64_image(&aarch64_code());
    let ramdisk = gzip_ramdisk();
    let second = elf64(EM_AARCH64);
    let dtbo = b"\xd7\xb7\xab\x1e recovery dtbo".to_vec();
    let tree = dtb();
    let image = paged_boot(&PagedBoot {
        version: 2,
        page_size: 4096,
        kernel: &kernel,
        ramdisk: &ramdisk,
        second: &second,
        recovery_dtbo: &dtbo,
        dtb: &tree,
        ..PagedBoot::default()
    });
    let payload = classify(&image);
    assert!(
        has_note(&payload, "Android boot image, header v2; page size 4096 B"),
        "{}",
        notes(&payload)
    );
    let page = 4096u64;
    let kernel_pages = (kernel.len() as u64).div_ceil(page);
    let ramdisk_pages = (ramdisk.len() as u64).div_ceil(page);
    let second_offset = page * (1 + kernel_pages + ramdisk_pages);
    assert_eq!(slice(&payload, "Second-stage loader").offset, second_offset);
    assert_eq!(slice(&payload, "Second-stage loader").isa, Isa::AArch64);
    let dtbo_offset = second_offset + page;
    assert_eq!(slice(&payload, "Recovery DTBO").offset, dtbo_offset);
    let dtb_slice = slice(&payload, "DTB");
    assert_eq!(
        (dtb_slice.offset, dtb_slice.size),
        (dtbo_offset + page, tree.len() as u64)
    );
    // Device trees and DTBO tables are data.
    assert!(matches!(dtb_slice.isa, Isa::Unknown(_)));
    assert!(matches!(
        slice(&payload, "Recovery DTBO").isa,
        Isa::Unknown(_)
    ));
    assert!(has_note(&payload, "DTB: opaque"));
    assert!(has_note(&payload, "Image ID matches the mkbootimg SHA-1"));
    assert_eq!(payload.primary.isa, Isa::AArch64);
}

#[test]
fn boot_v1_reports_a_recovery_dtbo_offset_that_differs_from_its_page() {
    let kernel = vec![1u8; 100];
    let dtbo = vec![2u8; 100];
    let mut image = paged_boot(&PagedBoot {
        version: 1,
        page_size: 2048,
        kernel: &kernel,
        recovery_dtbo: &dtbo,
        ..PagedBoot::default()
    });
    let c = parse(&image, Layout::Boot).expect("parses");
    let dtbo_child = c
        .children
        .iter()
        .find(|ch| ch.label == "Recovery DTBO")
        .expect("DTBO");
    assert_eq!(dtbo_child.offset, 4096);
    // Point the absolute offset 16 bytes later: the DTBO is read there.
    put64(&mut image, 0x664, 4096 + 16);
    let c = parse(&image, Layout::Boot).expect("parses");
    assert!(c
        .notes
        .iter()
        .any(|n| n.contains("Recovery DTBO offset 0x1010 differs")));
    put64(&mut image, 0x664, 1 << 40);
    let e = parse(&image, Layout::Boot).unwrap_err().to_string();
    assert!(
        e.contains("Truncated boot image recovery DTBO at 0x10000000000"),
        "{e}"
    );
}

#[test]
fn boot_v4_uses_4096_byte_pages_and_decodes_lz4_legacy_kernels() {
    // A real `lz4 -l` stream of the synthetic x86-64 ELF header.
    let kernel = fixture("compressed/payload.elf.legacy.lz4");
    let ramdisk = lz4_legacy(b"070701 lz4 ramdisk ramdisk ramdisk ramdisk");
    let mut signature = b"AVB0".to_vec();
    signature.resize(4096, 0);
    let image = gki_boot(4, &kernel, &ramdisk, &signature);
    let payload = classify(&image);
    assert_eq!(payload.format.format, FileFormat::AndroidBoot);
    assert!(
        has_note(
            &payload,
            "Android boot image, header v4; fixed 4096 B pages"
        ),
        "{}",
        notes(&payload)
    );
    let kernel_slice = slice(&payload, "Kernel");
    assert_eq!(kernel_slice.offset, 4096);
    assert_eq!(
        kernel_slice.decoded.as_ref().map(|d| d.transform.as_str()),
        Some("LZ4 legacy")
    );
    assert_eq!(kernel_slice.isa, Isa::X86_64);
    assert_eq!(slice(&payload, "Ramdisk").offset, 8192);
    let signature_slice = slice(&payload, "Boot signature");
    assert_eq!(signature_slice.offset, 12288);
    assert!(matches!(signature_slice.isa, Isa::Unknown(_)));
    assert!(has_note(&payload, "Boot signature: 4096 B"));
    assert!(has_note(&payload, "not verified"));
    assert!(has_note(&payload, "fixed 4096 B pages"));
    assert_eq!(payload.primary.isa, Isa::X86_64);
}

#[test]
fn boot_partition_tails_are_explained_or_noted() {
    let kernel = vec![1u8; 100];
    let image = paged_boot(&PagedBoot {
        version: 0,
        page_size: 2048,
        kernel: &kernel,
        ..PagedBoot::default()
    });
    let notes_of = |tail: &[u8]| {
        let mut data = image.clone();
        data.extend_from_slice(tail);
        parse(&data, Layout::Boot).expect("parses").notes
    };
    // Magisk SEANDROID_MAGIC and LG_BUMP_MAGIC after the last section.
    assert!(notes_of(b"SEANDROIDENFORCE")
        .iter()
        .any(|n| n == "Samsung SEANDROIDENFORCE marker after the last section"));
    let lg_bump = [
        0x41, 0xa9, 0xe4, 0x67, 0x74, 0x4d, 0x1d, 0x1b, 0xa4, 0x29, 0xf2, 0xec, 0xea, 0x65, 0x52,
        0x79,
    ];
    assert!(notes_of(&lg_bump)
        .iter()
        .any(|n| n == "LG bump trailer after the last section"));
    assert!(notes_of(b"vendor data")
        .iter()
        .any(|n| n == "11 B after the last section are not described by the header"));
    assert!(!notes_of(&[0xff; 64])
        .iter()
        .any(|n| n.contains("after the last section")));
}

#[test]
fn boot_v3_lists_an_undescribed_gki_certificate_and_an_avb_footer() {
    let kernel = gzip(&arm64_image(&aarch64_code()));
    let image = gki_boot(3, &kernel, &[], &[]);
    let end = image.len();
    let mut certified = image.clone();
    // certify_bootimg.py: a 16 KiB block of AVB vbmeta images.
    certified.extend_from_slice(b"AVB0");
    certified.resize(end + (16 << 10), 0);
    let c = parse(&certified, Layout::Boot).expect("parses");
    let certificate = c
        .children
        .iter()
        .find(|ch| ch.label == "Boot certificate")
        .expect("certificate");
    assert_eq!(
        (certificate.offset, certificate.stored_size),
        (end, 16 << 10)
    );
    assert!(certificate.opaque);

    let partition = with_avb_footer(image, end + (64 << 10));
    let payload = classify(&partition);
    assert!(has_note(&payload, "AVB footer: original image"));
    assert!(has_note(&payload, "signature not verified"));
    let vbmeta = slice(&payload, "AVB vbmeta");
    assert_eq!((vbmeta.offset, vbmeta.size), (end as u64, 256));
    assert_eq!(
        metadata(&payload, "android_avb_original_image_size"),
        Some(format!("{:?}", MetadataValue::Integer(end as u64)))
    );
    assert_eq!(payload.primary.isa, Isa::AArch64);
}

#[test]
fn boot_header_version_above_4_is_an_appended_device_tree_size() {
    let kernel = arm64_image(&aarch64_code());
    let tree = dtb();
    let image = paged_boot(&PagedBoot {
        version: 0,
        page_size: 2048,
        kernel: &kernel,
        version_field: Some(tree.len() as u32),
        appended_dt: &tree,
        ..PagedBoot::default()
    });
    let payload = classify(&image);
    assert!(
        has_note(
            &payload,
            "Android boot image, header v0; page size 2048 B; the header_version field holds"
        ),
        "{}",
        notes(&payload)
    );
    let dt = slice(&payload, "Appended device tree");
    let kernel_pages = kernel.len().div_ceil(2048) as u64;
    assert_eq!(dt.offset, 2048 * (1 + kernel_pages));
    assert!(matches!(dt.isa, Isa::Unknown(_)));
    assert!(has_note(&payload, "Image ID matches the mkbootimg SHA-1"));
    assert!(has_note(
        &payload,
        "holds the size of an appended device-tree image"
    ));
}

#[test]
fn boot_corruption_is_a_format_error() {
    let kernel = gzip(&arm64_image(&aarch64_code()));
    let image = paged_boot(&PagedBoot {
        version: 0,
        page_size: 2048,
        kernel: &kernel,
        ..PagedBoot::default()
    });
    let mut oversized = image.clone();
    put32(&mut oversized, 0x08, 1 << 30);
    assert!(error_text(&oversized).contains("Truncated boot image kernel at 0x800"));
    let mut page = image.clone();
    put32(&mut page, 0x24, 3000);
    assert!(error_text(&page).contains("Unsupported boot image page size 3000 B"));
    put32(&mut page, 0x24, 1 << 20);
    assert!(error_text(&page).contains("Unsupported boot image page size 1048576 B"));
    let large = paged_boot(&PagedBoot {
        version: 0,
        page_size: 64 << 10,
        kernel: &kernel,
        ..PagedBoot::default()
    });
    let payload = classify(&large);
    assert!(has_note(
        &payload,
        "Page size 64 KiB is outside the sizes AOSP mkbootimg.py writes"
    ));
    assert_eq!(slice(&payload, "Kernel").offset, 64 << 10);
    // A corrupt compressed kernel stays opaque with a note.
    let mut stream = image.clone();
    stream[2048 + 40] ^= 0xff;
    let payload = classify(&stream);
    assert!(has_note(
        &payload,
        "Kernel: payload does not decode as gzip"
    ));
    assert!(matches!(slice(&payload, "Kernel").isa, Isa::Unknown(_)));
    assert!(has_note(&payload, "Image ID is not the mkbootimg SHA-1"));
    // Every prefix that cuts the kernel is an error.
    for end in 0..2048 + kernel.len() {
        assert!(parse(&image[..end], Layout::Boot).is_err(), "prefix {end}");
    }
}

#[test]
fn vendor_boot_v4_ramdisk_table_entries_become_slices() {
    let platform = gzip_ramdisk();
    let dlkm = lz4_legacy(b"070701 vendor modules vendor modules vendor modules");
    let tree = dtb();
    let image = vendor_boot(
        4,
        2048,
        &[
            VendorRamdisk {
                name: "",
                kind: 1,
                data: &platform,
            },
            VendorRamdisk {
                name: "dlkm",
                kind: 3,
                data: &dlkm,
            },
        ],
        &tree,
        b"androidboot.hardware=zrax\n",
    );
    let payload = classify(&image);
    assert_eq!(payload.format.format, FileFormat::AndroidVendorBoot);
    assert!(
        has_note(
            &payload,
            "Android vendor_boot image, header v4; page size 2048 B"
        ),
        "{}",
        notes(&payload)
    );
    // A 2128-byte header takes two 2048-byte pages.
    let first = slice(&payload, "Vendor ramdisk 0 (platform)");
    assert_eq!((first.offset, first.size), (4096, platform.len() as u64));
    let second = slice(&payload, "Vendor ramdisk dlkm (DLKM)");
    assert_eq!(second.offset, 4096 + platform.len() as u64);
    assert_eq!(
        second.decoded.as_ref().map(|d| d.transform.as_str()),
        Some("LZ4 legacy")
    );
    let section_pages = (platform.len() + dlkm.len()).div_ceil(2048) as u64;
    let dtb_slice = slice(&payload, "DTB");
    assert_eq!(dtb_slice.offset, 4096 + 2048 * section_pages);
    let bootconfig = slice(&payload, "Bootconfig");
    assert_eq!(bootconfig.offset, dtb_slice.offset + 2048 * 2);
    assert!(matches!(bootconfig.isa, Isa::Unknown(_)));
    assert!(has_note(&payload, "Vendor ramdisk table: 2 entries"));
    assert_eq!(
        metadata(&payload, "android_dtb_address"),
        Some(format!("{:?}", MetadataValue::Address(DTB_ADDRESS)))
    );
}

#[test]
fn vendor_boot_v3_has_one_vendor_ramdisk() {
    let ramdisk = gzip_ramdisk();
    let tree = dtb();
    let image = vendor_boot(
        3,
        4096,
        &[VendorRamdisk {
            name: "",
            kind: 1,
            data: &ramdisk,
        }],
        &tree,
        &[],
    );
    let payload = classify(&image);
    assert!(
        has_note(
            &payload,
            "Android vendor_boot image, header v3; page size 4096 B"
        ),
        "{}",
        notes(&payload)
    );
    assert_eq!(slice(&payload, "Vendor ramdisk").offset, 4096);
    assert_eq!(slice(&payload, "DTB").offset, 8192);
}

#[test]
fn vendor_boot_table_entries_outside_the_section_are_errors() {
    let ramdisk = gzip_ramdisk();
    let image = vendor_boot(
        4,
        2048,
        &[VendorRamdisk {
            name: "a",
            kind: 1,
            data: &ramdisk,
        }],
        &dtb(),
        &[],
    );
    let table = 4096 + 2048 * (ramdisk.len().div_ceil(2048) + 1);
    let mut moved = image.clone();
    put32(&mut moved, table + 4, 8);
    assert!(error_text(&moved).contains("Invalid vendor ramdisk table entry 0"));
    let mut stride = image.clone();
    put32(&mut stride, 0x848, 100);
    assert!(error_text(&stride).contains("Invalid vendor ramdisk table entry size 100 B"));
    let mut version = image.clone();
    put32(&mut version, 0x08, 5);
    assert!(error_text(&version).contains("Unsupported vendor_boot header version 5"));
}

/// A sparse image chunk.
enum Chunk<'a> {
    /// `CHUNK_TYPE_RAW`: whole blocks of data.
    Raw(&'a [u8]),
    /// `CHUNK_TYPE_FILL`: a 32-bit pattern over `blocks` blocks.
    Fill(u32, u32),
    /// `CHUNK_TYPE_DONT_CARE`: `blocks` blocks of no data.
    DontCare(u32),
    /// `CHUNK_TYPE_CRC32` of the output so far.
    Crc32,
}

/// `sparse_header_t` (all little-endian): magic `0xED26FF3A`, version
/// 1.0, file header 28, chunk header 12, block size, total blocks, total
/// chunks, image checksum 0. Each `chunk_header_t`: type, reserved, output
/// blocks, input bytes including the header. Returns the image and its
/// expansion (DONT_CARE as zeros).
fn sparse(block_size: u32, chunks: &[Chunk<'_>]) -> (Vec<u8>, Vec<u8>) {
    let block = block_size as usize;
    let mut body = Vec::new();
    let mut expanded = Vec::new();
    for chunk in chunks {
        let (kind, blocks, data): (u16, u32, Vec<u8>) = match chunk {
            Chunk::Raw(bytes) => {
                expanded.extend_from_slice(bytes);
                (0xcac1, (bytes.len() / block) as u32, bytes.to_vec())
            }
            Chunk::Fill(value, blocks) => {
                for _ in 0..*blocks as usize * block / 4 {
                    expanded.extend_from_slice(&value.to_le_bytes());
                }
                (0xcac2, *blocks, value.to_le_bytes().to_vec())
            }
            Chunk::DontCare(blocks) => {
                expanded.resize(expanded.len() + *blocks as usize * block, 0);
                (0xcac3, *blocks, Vec::new())
            }
            Chunk::Crc32 => (0xcac4, 0, crc32(&expanded).to_le_bytes().to_vec()),
        };
        let mut header = vec![0u8; 12];
        put16(&mut header, 0, kind);
        put32(&mut header, 4, blocks);
        put32(&mut header, 8, (12 + data.len()) as u32);
        body.extend_from_slice(&header);
        body.extend_from_slice(&data);
    }
    let mut image = vec![0u8; 28];
    put32(&mut image, 0, 0xed26_ff3a);
    put16(&mut image, 4, 1);
    put16(&mut image, 8, 28);
    put16(&mut image, 10, 12);
    put32(&mut image, 12, block_size);
    put32(&mut image, 16, (expanded.len() / block) as u32);
    put32(&mut image, 20, chunks.len() as u32);
    image.extend_from_slice(&body);
    (image, expanded)
}

/// AArch64 code cut to whole 4 KiB blocks.
fn code_blocks() -> Vec<u8> {
    let mut code = aarch64_code();
    code.truncate(4096);
    code
}

#[test]
fn sparse_chunks_expand_into_one_partition_image() {
    let code = code_blocks();
    let (image, expanded) = sparse(
        4096,
        &[
            Chunk::Raw(&code),
            Chunk::Fill(0, 2),
            Chunk::DontCare(3),
            Chunk::Crc32,
        ],
    );
    let c = parse(&image, Layout::Sparse).expect("parses");
    assert_eq!(c.children.len(), 1);
    let child = &c.children[0];
    assert_eq!(child.label, "Expanded image");
    assert_eq!((child.offset, child.stored_size), (0, image.len()));
    assert_eq!(child.transform, Some("Android sparse"));
    assert_eq!(&child.data[..], &expanded[..]);

    let payload = classify(&image);
    assert_eq!(payload.format.format, FileFormat::AndroidSparse);
    assert!(
        has_note(&payload, "Android sparse image v1.0; block size 4096 B"),
        "{}",
        notes(&payload)
    );
    assert!(has_note(
        &payload,
        "6 blocks (24576 B expanded) in 4 chunks: 1 RAW, 1 FILL, 1 DONT_CARE, 1 CRC32"
    ));
    assert!(has_note(&payload, "1 CRC32 chunks verified"));
    let expanded_slice = slice(&payload, "Expanded image");
    assert_eq!(
        expanded_slice
            .decoded
            .as_ref()
            .map(|d| (d.transform.as_str(), d.size)),
        Some(("Android sparse", expanded.len() as u64))
    );
    assert_eq!(payload.primary.isa, Isa::AArch64, "{}", notes(&payload));
}

#[test]
fn sparse_image_of_a_boot_image_is_classified_through_it() {
    let kernel = gzip(&arm64_image(&aarch64_code()));
    let mut boot = paged_boot(&PagedBoot {
        version: 0,
        page_size: 4096,
        kernel: &kernel,
        ..PagedBoot::default()
    });
    pad_to(&mut boot, 4096);
    let (image, _) = sparse(4096, &[Chunk::Raw(&boot), Chunk::DontCare(4)]);
    let payload = classify(&image);
    assert_eq!(payload.format.format, FileFormat::AndroidSparse);
    assert_eq!(payload.primary.isa, Isa::AArch64);
    let expanded = slice(&payload, "Expanded image");
    assert_eq!(expanded.isa, Isa::AArch64);
    assert!(
        has_note(&payload, "(contained Android boot image)"),
        "{}",
        notes(&payload)
    );
}

#[test]
fn sparse_corruption_is_a_format_error() {
    let code = code_blocks();
    let (image, _) = sparse(4096, &[Chunk::Raw(&code), Chunk::Crc32]);
    let crc_at = image.len() - 4;
    let mut crc = image.clone();
    crc[crc_at] ^= 1;
    assert!(error_text(&crc).contains("Invalid sparse CRC32 chunk"));
    let mut kind = image.clone();
    put16(&mut kind, 28, 0xcac9);
    assert!(error_text(&kind).contains("Unknown sparse chunk type 0xCAC9 at 0x1C"));
    let mut blocks = image.clone();
    put32(&mut blocks, 16, 2);
    assert!(error_text(&blocks).contains("chunks cover 1 blocks, header declares 2"));
    let mut major = image.clone();
    put16(&mut major, 4, 2);
    assert!(error_text(&major).contains("Unsupported sparse image major version 2"));
    let mut block_size = image.clone();
    put32(&mut block_size, 12, 4098);
    assert!(error_text(&block_size).contains("Invalid sparse block size 4098 B"));
    let mut trailing = image.clone();
    trailing.extend_from_slice(b"junk");
    assert!(error_text(&trailing).contains("Unexpected 4 B after the last sparse chunk"));
    for end in 0..image.len() {
        assert!(
            parse(&image[..end], Layout::Sparse).is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn sparse_expansion_stops_at_the_payload_limit() {
    // 32768 DONT_CARE blocks of 4 KiB are 128 MiB: only 64 MiB are kept.
    let (image, _) = sparse(
        4096,
        &[Chunk::Fill(1, 1), Chunk::DontCare(32768), Chunk::Crc32],
    );
    let c = parse(&image, Layout::Sparse).expect("parses");
    assert_eq!(c.children[0].data.len(), MAX_PAYLOAD);
    assert!(c
        .notes
        .iter()
        .any(|n| n.contains("only the first 64 MiB were expanded")));
    assert!(c
        .notes
        .iter()
        .any(|n| n.contains("1 CRC32 chunks after the 64 MiB expansion limit not verified")));
}

/// Protobuf wire-format writer (protobuf.dev encoding guide): varints,
/// tags `(field << 3) | wire_type`, length-delimited fields.
fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Field `number` as a varint (wire type 0).
fn pb_varint(number: u32, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(u64::from(number) << 3, &mut out);
    varint(value, &mut out);
    out
}

/// Field `number` as length-delimited bytes (wire type 2).
fn pb_bytes(number: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint((u64::from(number) << 3) | 2, &mut out);
    varint(bytes.len() as u64, &mut out);
    out.extend_from_slice(bytes);
    out
}

/// `InstallOperation.Type` values (`update_metadata.proto`).
const OP_REPLACE: u64 = 0;
const OP_REPLACE_BZ: u64 = 1;
const OP_SOURCE_COPY: u64 = 4;
const OP_ZERO: u64 = 6;
const OP_REPLACE_XZ: u64 = 8;
const OP_PUFFDIFF: u64 = 9;

/// One `InstallOperation`: its type, data blob and destination extents
/// (start block, block count).
struct Operation {
    kind: u64,
    blob: Vec<u8>,
    extents: Vec<(u64, u64)>,
}

/// One `PartitionUpdate`: name, operations and the full image whose size
/// and SHA-256 go into `new_partition_info` (when given).
struct Partition {
    name: &'static str,
    operations: Vec<Operation>,
    image: Option<Vec<u8>>,
}

/// A major-version-2 `payload.bin`: magic `CrAU`, major version 2 (u64
/// BE), manifest size (u64 BE), metadata signature size (u32 BE), the
/// `DeltaArchiveManifest` (block size 3, signatures offset 4 and size 5,
/// minor version 12, partitions 13: name 1, new info 7 (size 1, hash 2),
/// operations 8: type 1, data offset 2, data length 3, destination
/// extents 6 (start 1, count 2), data SHA-256 8), the metadata signature,
/// the operation blobs back to back from `blob_start`, then the payload
/// signature.
fn ota_payload(partitions: &[Partition], minor_version: u64, signature: &[u8]) -> Vec<u8> {
    let mut blobs = Vec::new();
    let mut manifest = pb_varint(3, 4096);
    for p in partitions {
        let mut update = pb_bytes(1, p.name.as_bytes());
        if let Some(image) = &p.image {
            let mut info = pb_varint(1, image.len() as u64);
            info.extend(pb_bytes(2, &Sha256::digest(image)));
            update.extend(pb_bytes(7, &info));
        }
        for op in &p.operations {
            let mut operation = pb_varint(1, op.kind);
            if !op.blob.is_empty() {
                operation.extend(pb_varint(2, blobs.len() as u64));
                operation.extend(pb_varint(3, op.blob.len() as u64));
                operation.extend(pb_bytes(8, &Sha256::digest(&op.blob)));
                blobs.extend_from_slice(&op.blob);
            }
            for &(start, count) in &op.extents {
                let mut extent = pb_varint(1, start);
                extent.extend(pb_varint(2, count));
                operation.extend(pb_bytes(6, &extent));
            }
            update.extend(pb_bytes(8, &operation));
        }
        manifest.extend(pb_bytes(13, &update));
    }
    if !signature.is_empty() {
        manifest.extend(pb_varint(4, blobs.len() as u64));
        manifest.extend(pb_varint(5, signature.len() as u64));
    }
    manifest.extend(pb_varint(12, minor_version));
    let mut payload = b"CrAU".to_vec();
    payload.extend_from_slice(&2u64.to_be_bytes());
    payload.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    payload.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    payload.extend_from_slice(&manifest);
    payload.extend_from_slice(signature);
    payload.extend_from_slice(&blobs);
    payload.extend_from_slice(signature);
    payload
}

/// The boot and system partitions of a full payload: the boot image as one
/// REPLACE, the system image as REPLACE_XZ (the committed xz stream of the
/// synthetic x86-64 ELF), REPLACE_BZ and ZERO operations.
fn full_partitions() -> Vec<Partition> {
    let kernel = gzip(&arm64_image(&aarch64_code()));
    let mut boot = paged_boot(&PagedBoot {
        version: 0,
        page_size: 4096,
        kernel: &kernel,
        ..PagedBoot::default()
    });
    pad_to(&mut boot, 4096);
    let boot_blocks = (boot.len() / 4096) as u64;
    let elf = fixture("compressed/payload.elf");
    let mut system = elf.clone();
    system.resize(4096, 0);
    system.extend_from_slice(&elf);
    system.resize(3 * 4096, 0);
    vec![
        Partition {
            name: "boot",
            operations: vec![Operation {
                kind: OP_REPLACE,
                blob: boot.clone(),
                extents: vec![(0, boot_blocks)],
            }],
            image: Some(boot),
        },
        Partition {
            name: "system",
            operations: vec![
                Operation {
                    kind: OP_REPLACE_XZ,
                    blob: fixture("compressed/payload.elf.xz"),
                    extents: vec![(0, 1)],
                },
                Operation {
                    kind: OP_REPLACE_BZ,
                    blob: fixture("compressed/payload.elf.bz2"),
                    extents: vec![(1, 1)],
                },
                Operation {
                    kind: OP_ZERO,
                    blob: Vec::new(),
                    extents: vec![(2, 1)],
                },
            ],
            image: Some(system),
        },
    ]
}

#[test]
fn ota_full_payload_partitions_are_reassembled_and_classified() {
    let signature = vec![0x5a; 32];
    let partitions = full_partitions();
    let payload_bytes = ota_payload(&partitions, 0, &signature);
    let c = parse(&payload_bytes, Layout::Ota).expect("parses");
    let system = c.children.iter().find(|ch| ch.label == "system").unwrap();
    assert_eq!(&system.data[..], &partitions[1].image.as_ref().unwrap()[..]);
    assert_eq!(system.transform, Some("Android OTA"));

    let payload = classify(&payload_bytes);
    assert_eq!(payload.format.format, FileFormat::AndroidOta);
    assert!(
        has_note(
            &payload,
            "Full payload (minor version 0); block size 4096 B; 2 partitions"
        ),
        "{}",
        notes(&payload)
    );
    let boot = slice(&payload, "boot");
    assert_eq!(boot.isa, Isa::AArch64, "{}", notes(&payload));
    assert_eq!(slice(&payload, "system").isa, Isa::X86_64);
    assert_eq!(payload.primary.isa, Isa::AArch64);
    assert!(has_note(
        &payload,
        "operation data SHA-256 verified for 1; partition SHA-256 verified"
    ));
    assert!(has_note(&payload, "system: reassembled 12288 B from 3 operations; operation data SHA-256 verified for 2; partition SHA-256 verified"));
    assert!(has_note(&payload, "Metadata signature: 32 B; not verified"));
    assert!(has_note(&payload, "Payload signature: 32 B at"));
    assert_eq!(
        metadata(&payload, "android_ota_major_version"),
        Some(format!("{:?}", MetadataValue::Integer(2)))
    );
    // The boot partition's stored data is the REPLACE blob after the
    // header (24 B), manifest and metadata signature.
    let manifest_size = u64::from_be_bytes(payload_bytes[12..20].try_into().unwrap());
    assert_eq!(boot.offset, 24 + manifest_size + 32);
}

#[test]
fn ota_delta_partitions_stay_opaque() {
    let mut partitions = full_partitions();
    partitions.push(Partition {
        name: "vendor",
        operations: vec![
            Operation {
                kind: OP_SOURCE_COPY,
                blob: Vec::new(),
                extents: vec![(0, 4)],
            },
            Operation {
                kind: OP_PUFFDIFF,
                blob: vec![1, 2, 3, 4],
                extents: vec![(4, 1)],
            },
            Operation {
                kind: 99,
                blob: Vec::new(),
                extents: vec![(5, 1)],
            },
        ],
        image: None,
    });
    let payload = classify(&ota_payload(&partitions, 9, &[]));
    assert!(
        has_note(&payload, "Delta payload (minor version 9)"),
        "{}",
        notes(&payload)
    );
    let vendor = slice(&payload, "vendor");
    assert!(matches!(vendor.isa, Isa::Unknown(_)));
    assert!(has_note(&payload, "vendor: delta operations (SOURCE_COPY, PUFFDIFF) need the source partition; unknown operations (type 99); not reassembled"));
    assert!(has_note(&payload, "Payload is unsigned"));
    assert_eq!(slice(&payload, "boot").isa, Isa::AArch64);
}

#[test]
fn ota_corruption_is_a_format_error_or_an_opaque_partition() {
    let partitions = full_partitions();
    let good = ota_payload(&partitions, 0, &[0x5a; 16]);
    let mut major = good.clone();
    major[11] = 3;
    assert!(error_text(&major).contains("Unsupported OTA payload major version 3"));
    let mut manifest = good.clone();
    manifest[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(error_text(&manifest).contains("Invalid OTA manifest range 0x18"));
    manifest[12..20].copy_from_slice(&(1u64 << 32).to_be_bytes());
    assert!(error_text(&manifest).contains("Truncated OTA manifest at 0x18 + 4294967296 B"));
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"junk");
    assert!(error_text(&trailing).contains("Unexpected 4 B after the OTA payload"));
    for end in 0..good.len() - 16 {
        assert!(parse(&good[..end], Layout::Ota).is_err(), "prefix {end}");
    }
    // A blob whose SHA-256 does not match leaves that partition opaque.
    let manifest_size = u64::from_be_bytes(good[12..20].try_into().unwrap()) as usize;
    let mut blob = good.clone();
    blob[24 + manifest_size + 16 + 100] ^= 1;
    let payload = classify(&blob);
    assert!(has_note(
        &payload,
        "boot: operation 0 data SHA-256 does not match; not reassembled"
    ));
    assert!(matches!(slice(&payload, "boot").isa, Isa::Unknown(_)));
    assert_eq!(slice(&payload, "system").isa, Isa::X86_64);
}

#[test]
fn ota_partition_images_are_bounded_by_the_extraction_limits() {
    // ZERO operations far beyond the cap: each partition is cut at 64 MiB
    // and allocation stops at 256 MiB for the payload.
    let partitions: Vec<Partition> = ["a", "b", "c", "d", "e"]
        .into_iter()
        .map(|name| Partition {
            name,
            operations: vec![Operation {
                kind: OP_ZERO,
                blob: Vec::new(),
                extents: vec![(0, 1), (1 << 40, 1)],
            }],
            image: None,
        })
        .collect();
    let bytes = ota_payload(&partitions, 0, &[]);
    let c = parse(&bytes, Layout::Ota).expect("parses");
    for child in &c.children[..4] {
        assert_eq!(child.data.len(), MAX_PAYLOAD);
    }
    assert!(c.children[4].opaque);
    assert!(c
        .notes
        .iter()
        .any(|n| n.contains("e: not reassembled; the extraction limit of 256 MiB was reached")));
    assert!(c
        .notes
        .iter()
        .any(|n| n.contains("cut at the extraction limit")));
}

#[test]
fn ota_major_version_1_maps_root_and_kernel_operations() {
    // DeltaArchiveManifest v1: install_operations (1) for the root
    // partition, kernel_install_operations (2), block size 4096.
    let elf = elf64(EM_AARCH64);
    let mut operation = pb_varint(1, OP_REPLACE);
    operation.extend(pb_varint(2, 0));
    operation.extend(pb_varint(3, elf.len() as u64));
    let mut extent = pb_varint(1, 0);
    extent.extend(pb_varint(2, 1));
    operation.extend(pb_bytes(6, &extent));
    let mut manifest = pb_bytes(2, &operation);
    manifest.extend(pb_varint(3, 4096));
    let mut payload_bytes = b"CrAU".to_vec();
    payload_bytes.extend_from_slice(&1u64.to_be_bytes());
    payload_bytes.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    payload_bytes.extend_from_slice(&manifest);
    payload_bytes.extend_from_slice(&elf);
    let payload = classify(&payload_bytes);
    assert!(
        has_note(&payload, "Android OTA payload, major version 1"),
        "{}",
        notes(&payload)
    );
    let kernel = slice(&payload, "kernel");
    assert_eq!(kernel.offset, 20 + manifest.len() as u64);
    assert_eq!(kernel.isa, Isa::AArch64);
}

#[test]
fn ota_manifest_protobuf_errors_name_the_offset() {
    // Field 13 (partitions) claims 100 bytes; the manifest holds 2.
    let manifest = [0x6a, 100];
    let mut bytes = b"CrAU".to_vec();
    bytes.extend_from_slice(&2u64.to_be_bytes());
    bytes.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&manifest);
    assert!(error_text(&bytes).contains("Truncated OTA manifest field 13 at 0x1A + 100 B"));
    // A partition without its required name.
    let mut missing = bytes[..24].to_vec();
    let manifest = pb_bytes(13, &pb_varint(2, 1));
    missing[12..20].copy_from_slice(&(manifest.len() as u64).to_be_bytes());
    missing.extend_from_slice(&manifest);
    assert!(error_text(&missing).contains("Missing partition_name in the OTA manifest at 0x1A"));
}

/// Qualcomm `BOOTLDR!` pack (AOSP hammerhead `releasetools.py`, all
/// little-endian): magic, `num_images`, `start_offset`, `bootldr_size`
/// (sum of sizes, or `override_size`), then 68-byte entries (`name[64]`,
/// size); bodies back to back from `start_offset`.
fn qualcomm_bootldr(images: &[(&str, &[u8])], override_size: Option<u32>) -> Vec<u8> {
    let start = 20 + 68 * images.len();
    let total: usize = images.iter().map(|(_, body)| body.len()).sum();
    let mut pack = vec![0u8; start];
    pack[..8].copy_from_slice(b"BOOTLDR!");
    put32(&mut pack, 8, images.len() as u32);
    put32(&mut pack, 12, start as u32);
    put32(&mut pack, 16, override_size.unwrap_or(total as u32));
    for (i, (name, body)) in images.iter().enumerate() {
        let entry = 20 + 68 * i;
        pack[entry..entry + name.len()].copy_from_slice(name.as_bytes());
        put32(&mut pack, entry + 64, body.len() as u32);
    }
    for (_, body) in images {
        pack.extend_from_slice(body);
    }
    pack
}

#[test]
fn qualcomm_bootldr_members_are_classified_on_their_own() {
    let aboot = elf64(EM_AARCH64);
    let tz = elf64(EM_X86_64);
    let pack = qualcomm_bootldr(&[("aboot", &aboot), ("tz", &tz)], None);
    let payload = classify(&pack);
    assert_eq!(payload.format.format, FileFormat::AndroidBootloader);
    assert!(
        has_note(
            &payload,
            "Qualcomm BOOTLDR! pack: 2 images, 128 B of image data from 0x9C"
        ),
        "{}",
        notes(&payload)
    );
    assert_eq!(
        (
            slice(&payload, "aboot").offset,
            slice(&payload, "aboot").size
        ),
        (156, 64)
    );
    assert_eq!(slice(&payload, "aboot").isa, Isa::AArch64);
    assert_eq!(slice(&payload, "tz").isa, Isa::X86_64);
    assert_eq!(slice(&payload, "tz").offset, 220);
    assert!(has_note(
        &payload,
        "bootldr_size matches the sum of the image sizes"
    ));
    assert!(has_note(&payload, "The pack names no CPU"));

    let whole_file = qualcomm_bootldr(&[("aboot", &aboot)], Some(20 + 68 + 64));
    assert!(has_note(
        &classify(&whole_file),
        "bootldr_size equals the file size"
    ));
    let wrong = qualcomm_bootldr(&[("aboot", &aboot)], Some(1000));
    let e = error_text(&wrong);
    assert!(e.contains("as the ASUS layout,"), "{e}");
    assert!(
        e.contains("as the Qualcomm layout, Invalid BOOTLDR! bootldr_size 1000 B"),
        "{e}"
    );
    for end in 0..pack.len() {
        assert!(
            parse(&pack[..end], Layout::Bootldr).is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn bootldr_pack_valid_under_both_layouts_is_ambiguous() {
    // One Qualcomm image named " ": read as the ASUS layout, the count is
    // revision 1, `bootldr_size` the IFWI size and the name the droidboot
    // size (32 B), which also fits the file.
    let body = elf64(EM_AARCH64);
    let pack = qualcomm_bootldr(&[(" ", &body)], None);
    let c = parse(&pack, Layout::Bootldr).expect("parses");
    assert_eq!(c.variant, "Ambiguous BOOTLDR! pack");
    assert!(c.children.is_empty());
    let payload = classify(&pack);
    assert!(matches!(payload.primary.isa, Isa::Unknown(_)));
    assert!(has_note(
        &payload,
        "validates as both the Qualcomm and the ASUS fugu"
    ));
}

/// ASUS fugu `BOOTLDR!` revision 1 (AOSP fugu `releasetools.py`): magic,
/// revision 1 (u16), reserved u16 and u32, IFWI size (u32), droidboot size
/// (u32), the IFWI image from 0x18, then the droidboot image.
fn fugu_sized(ifwi: &[u8], droidboot: &[u8]) -> Vec<u8> {
    let mut pack = vec![0u8; 0x18];
    pack[..8].copy_from_slice(b"BOOTLDR!");
    put16(&mut pack, 8, 1);
    put32(&mut pack, 0x10, ifwi.len() as u32);
    put32(&mut pack, 0x14, droidboot.len() as u32);
    pack.extend_from_slice(ifwi);
    pack.extend_from_slice(droidboot);
    pack
}

/// ASUS fugu `BOOTLDR!` revision 2: magic, revision 2, reserved fields,
/// then chunks of `chunk_id[8]`, size (u32), flags (u8), three reserved
/// bytes and the data, to the end of the file.
fn fugu_chunks(chunks: &[(&[u8; 8], u8, &[u8])]) -> Vec<u8> {
    let mut pack = vec![0u8; 16];
    pack[..8].copy_from_slice(b"BOOTLDR!");
    put16(&mut pack, 8, 2);
    for (id, flags, data) in chunks {
        let mut header = vec![0u8; 16];
        header[..8].copy_from_slice(*id);
        put32(&mut header, 8, data.len() as u32);
        header[12] = *flags;
        pack.extend_from_slice(&header);
        pack.extend_from_slice(data);
    }
    pack
}

#[test]
fn fugu_bootldr_layouts_list_ifwi_droidboot_and_splash() {
    let droidboot = gki_boot(3, &fixture("compressed/payload.elf.legacy.lz4"), &[], &[]);
    let ifwi = elf64(EM_X86_64);
    let sized = classify(&fugu_sized(&ifwi, &droidboot));
    assert!(
        has_note(&sized, "ASUS BOOTLDR! pack revision 1: IFWI 64 B"),
        "{}",
        notes(&sized)
    );
    assert_eq!(slice(&sized, "IFWI").offset, 0x18);
    let boot = slice(&sized, "droidboot");
    assert_eq!(boot.offset, 0x18 + 64);
    assert_eq!(boot.isa, Isa::X86_64, "{}", notes(&sized));

    let splash = vec![0x42; 32];
    let chunked = classify(&fugu_chunks(&[
        (b"IFWI!!!!", 1, &ifwi),
        (b"DROIDBT!", 1, &droidboot),
        (b"SPLASHS!", 0, &splash),
    ]));
    assert!(
        has_note(
            &chunked,
            "ASUS BOOTLDR! pack: 3 chunks to the end of the file"
        ),
        "{}",
        notes(&chunked)
    );
    assert_eq!(slice(&chunked, "IFWI").offset, 32);
    assert_eq!(slice(&chunked, "droidboot").isa, Isa::X86_64);
    assert!(matches!(slice(&chunked, "splash").isa, Isa::Unknown(_)));
    assert!(has_note(&chunked, "splash: chunk flag bit 0 is clear"));
    assert!(has_note(&chunked, "ASUS BOOTLDR! pack: 3 chunks"));

    let mut unknown = fugu_chunks(&[(b"IFWI!!!!", 1, &ifwi)]);
    unknown[16..24].copy_from_slice(b"BOGUS!!!");
    let e = error_text(&unknown);
    assert!(
        e.contains("as the ASUS layout, Unknown ASUS BOOTLDR! chunk ID"),
        "{e}"
    );
}

/// Qualcomm meta image (CAF `meta_format.h`, little-endian): magic
/// `0xCE1AD63C`, version 1.0, image version (64), header size 76, entry
/// table size (16 entries of 80 B); each entry a 72-byte name, absolute
/// start offset and size; bodies back to back after the table.
fn meta_image(images: &[(&str, &[u8])]) -> Vec<u8> {
    let table_end = 76 + 16 * 80;
    let mut pack = vec![0u8; table_end];
    put32(&mut pack, 0, 0xce1a_d63c);
    put16(&mut pack, 4, 1);
    pack[8..20].copy_from_slice(b"META.1.0.zrx");
    put16(&mut pack, 0x48, 76);
    put16(&mut pack, 0x4a, 16 * 80);
    let mut offset = table_end;
    for (i, (name, body)) in images.iter().enumerate() {
        let entry = 76 + 80 * i;
        pack[entry..entry + name.len()].copy_from_slice(name.as_bytes());
        put32(&mut pack, entry + 0x48, offset as u32);
        put32(&mut pack, entry + 0x4c, body.len() as u32);
        offset += body.len();
    }
    for (_, body) in images {
        pack.extend_from_slice(body);
    }
    pack
}

#[test]
fn meta_image_entries_in_use_become_slices() {
    let hyp = elf64(EM_AARCH64);
    let pack = meta_image(&[("hyp", &hyp), ("pmic", b"pmic data")]);
    let payload = classify(&pack);
    assert!(
        has_note(&payload, "Qualcomm meta image v1.0: 2 of 16 entries in use"),
        "{}",
        notes(&payload)
    );
    assert_eq!(slice(&payload, "hyp").offset, 1356);
    assert_eq!(slice(&payload, "hyp").isa, Isa::AArch64);
    assert_eq!(slice(&payload, "pmic").offset, 1356 + 64);
    assert!(has_note(
        &payload,
        "2 of 16 entries in use; image version \"META.1.0.zrx\""
    ));
    let mut header = pack.clone();
    put16(&mut header, 0x48, 80);
    assert!(error_text(&header).contains("Unsupported meta image header size 80 B"));
    let mut table = pack.clone();
    put16(&mut table, 0x4a, 100);
    assert!(error_text(&table).contains("not a multiple of 80 B"));
    for end in 0..pack.len() {
        assert!(
            parse(&pack[..end], Layout::MetaImage).is_err(),
            "prefix {end}"
        );
    }
}

/// One FBPK entry: type (0 partition table, 1 partition data, 2 sideload),
/// name, product and data.
struct PackEntry<'a> {
    kind: u32,
    name: &'a str,
    product: &'a str,
    data: &'a [u8],
}

/// FBPK version 2 (`fbpack.py`, little-endian): `PackHeader` of magic
/// `FBPK`, version 2, header size 112, entry size 104, platform (16), pack
/// version (64), slot type 0, data alignment 16, entry count, total size;
/// `PackEntry` records of type, name (36), product (40), absolute data
/// offset (u64), size (u64), slotted, crc32 (written as given); each data
/// block aligned to 16 bytes from the file start.
fn fbpk_v2(entries: &[PackEntry<'_>], crc: bool) -> Vec<u8> {
    let table_end = 112 + 104 * entries.len();
    let mut pack = vec![0u8; table_end];
    pack[..4].copy_from_slice(b"FBPK");
    put32(&mut pack, 4, 2);
    put32(&mut pack, 8, 112);
    put32(&mut pack, 12, 104);
    pack[0x10..0x17].copy_from_slice(b"gs101zx");
    pack[0x20..0x2c].copy_from_slice(b"slider-1.0-z");
    put32(&mut pack, 0x64, 16);
    put32(&mut pack, 0x68, entries.len() as u32);
    for (i, e) in entries.iter().enumerate() {
        pad_to(&mut pack, 16);
        let entry = 112 + 104 * i;
        let offset = pack.len();
        put32(&mut pack, entry, e.kind);
        pack[entry + 4..entry + 4 + e.name.len()].copy_from_slice(e.name.as_bytes());
        pack[entry + 0x28..entry + 0x28 + e.product.len()].copy_from_slice(e.product.as_bytes());
        put64(&mut pack, entry + 0x50, offset as u64);
        put64(&mut pack, entry + 0x58, e.data.len() as u64);
        if crc {
            put32(&mut pack, entry + 0x64, crc32(e.data));
        }
        pack.extend_from_slice(e.data);
    }
    let total = pack.len() as u32;
    put32(&mut pack, 0x6c, total);
    pack
}

/// FBPK version 1 (qc_image_unpacker `packed_image.h`, little-endian):
/// magic `FBPK`, version 1, image version (68), entry count, total file
/// size; each 56-byte entry header (type, name (32), pad1 0, size, pad2 0,
/// absolute offset of the next entry header, checksum 0) is followed by
/// its data, padded to 4 bytes.
fn fbpk_v1(entries: &[PackEntry<'_>]) -> Vec<u8> {
    let mut pack = vec![0u8; 84];
    pack[..4].copy_from_slice(b"FBPK");
    put32(&mut pack, 4, 1);
    pack[8..20].copy_from_slice(b"b1c1-0.1-zrx");
    put32(&mut pack, 0x4c, entries.len() as u32);
    for e in entries {
        let start = pack.len();
        let mut header = vec![0u8; 56];
        put32(&mut header, 0, e.kind);
        header[4..4 + e.name.len()].copy_from_slice(e.name.as_bytes());
        put32(&mut header, 0x28, e.data.len() as u32);
        pack.extend_from_slice(&header);
        pack.extend_from_slice(e.data);
        pad_to(&mut pack, 4);
        let next = pack.len() as u32;
        put32(&mut pack, start + 0x30, next);
    }
    let total = pack.len() as u32;
    put32(&mut pack, 0x50, total);
    pack
}

#[test]
fn fbpk_v2_entries_are_classified_and_partition_tables_stay_opaque() {
    let abl = elf64(EM_AARCH64);
    let pack = fbpk_v2(
        &[
            PackEntry {
                kind: 0,
                name: "partition:0",
                product: "",
                data: b"FBPT partition table",
            },
            PackEntry {
                kind: 1,
                name: "abl",
                product: "oriole|raven",
                data: &abl,
            },
        ],
        true,
    );
    let payload = classify(&pack);
    assert_eq!(payload.format.format, FileFormat::AndroidBootloader);
    assert!(
        has_note(&payload, "FBPK v2 pack: 2 entries"),
        "{}",
        notes(&payload)
    );
    let table = slice(&payload, "partition:0");
    assert_eq!(table.offset, 320);
    assert!(matches!(table.isa, Isa::Unknown(_)));
    let abl_slice = slice(&payload, "abl (oriole|raven)");
    assert_eq!(abl_slice.offset, 352);
    assert_eq!(abl_slice.isa, Isa::AArch64);
    assert_eq!(payload.primary.isa, Isa::AArch64);
    assert!(has_note(
        &payload,
        "2 crc32 fields match the IEEE CRC-32 of their entry data"
    ));
    assert!(has_note(
        &payload,
        "1 partition-table entries (1 with the FBPT magic)"
    ));
    assert!(has_note(
        &payload,
        "platform \"gs101zx\"; pack version \"slider-1.0-z\""
    ));
    assert_eq!(
        metadata(&payload, "android_fbpk_platform"),
        Some(format!("{:?}", MetadataValue::String("gs101zx".into())))
    );
    let mut crc = pack.clone();
    put32(&mut crc, 112 + 104 + 0x64, 1);
    assert!(has_note(
        &classify(&crc),
        "1 crc32 fields not verified (algorithm and coverage unconfirmed)"
    ));
    let mut kind = pack.clone();
    put32(&mut kind, 112 + 104, 7);
    assert!(has_note(&classify(&kind), "1 entries have an unknown type"));
    let mut version = pack.clone();
    put32(&mut version, 4, 3);
    assert!(error_text(&version).contains("Unsupported FBPK version 3"));
    let mut offset = pack.clone();
    put64(&mut offset, 112 + 104 + 0x50, 1 << 40);
    assert!(error_text(&offset).contains("Truncated FBPK v2 entry 1 data"));
    let mut overlap = pack.clone();
    put64(&mut overlap, 112 + 0x50, 8);
    assert!(error_text(&overlap).contains("overlaps the entry table"));
    for end in 0..pack.len() {
        assert!(parse(&pack[..end], Layout::Fbpk).is_err(), "prefix {end}");
    }
}

#[test]
fn fbpk_v1_entries_follow_their_headers() {
    let xbl = elf64(EM_AARCH64);
    let pack = fbpk_v1(&[
        PackEntry {
            kind: 0,
            name: "partition:0",
            product: "",
            data: b"FBPT table",
        },
        PackEntry {
            kind: 1,
            name: "xbl",
            product: "",
            data: &xbl,
        },
    ]);
    let payload = classify(&pack);
    assert!(
        has_note(&payload, "FBPK v1 pack: 2 entries"),
        "{}",
        notes(&payload)
    );
    assert_eq!(slice(&payload, "partition:0").offset, 84 + 56);
    let xbl_slice = slice(&payload, "xbl");
    assert_eq!(xbl_slice.offset, 84 + 56 + 12 + 56);
    assert_eq!(xbl_slice.isa, Isa::AArch64);
    assert!(has_note(&payload, "layout from community unpackers"));
    let mut pad = pack.clone();
    put32(&mut pad, 84 + 0x24, 1);
    assert!(error_text(&pad).contains("nonzero pad1 or pad2"));
    let mut next = pack.clone();
    put32(&mut next, 84 + 0x30, 100);
    assert!(error_text(&next).contains("Invalid FBPK v1 next_offset 0x64 in entry 0"));
    for end in 0..pack.len() {
        assert!(parse(&pack[..end], Layout::Fbpk).is_err(), "prefix {end}");
    }
}

/// Every fixture, its layout and detected format, small enough for
/// exhaustive sweeps.
fn sweep_fixtures() -> Vec<(Vec<u8>, FileFormat)> {
    let code = aarch64_code()[..512].to_vec();
    let kernel = gzip(&arm64_image(&code));
    let ramdisk = lz4_legacy(b"070701 ramdisk ramdisk ramdisk");
    let tree = dtb();
    let elf = elf64(EM_AARCH64);
    let block = {
        let mut block = code.clone();
        block.resize(512, 0);
        block
    };
    let small_partitions = vec![Partition {
        name: "boot",
        operations: vec![
            Operation {
                kind: OP_REPLACE,
                blob: elf.clone(),
                extents: vec![(0, 1)],
            },
            Operation {
                kind: OP_REPLACE_XZ,
                blob: fixture("compressed/payload.elf.xz"),
                extents: vec![(1, 1)],
            },
        ],
        image: None,
    }];
    vec![
        (
            paged_boot(&PagedBoot {
                version: 2,
                page_size: 2048,
                kernel: &kernel,
                ramdisk: &ramdisk,
                second: &elf,
                recovery_dtbo: b"dtbo",
                dtb: &tree,
                ..PagedBoot::default()
            }),
            FileFormat::AndroidBoot,
        ),
        (
            gki_boot(4, &kernel, &ramdisk, b"AVB0"),
            FileFormat::AndroidBoot,
        ),
        (
            vendor_boot(
                4,
                2048,
                &[VendorRamdisk {
                    name: "dlkm",
                    kind: 3,
                    data: &ramdisk,
                }],
                &tree,
                b"a=b\n",
            ),
            FileFormat::AndroidVendorBoot,
        ),
        (
            sparse(
                512,
                &[
                    Chunk::Raw(&block),
                    Chunk::Fill(7, 1),
                    Chunk::DontCare(1),
                    Chunk::Crc32,
                ],
            )
            .0,
            FileFormat::AndroidSparse,
        ),
        (
            ota_payload(&small_partitions, 0, &[1; 8]),
            FileFormat::AndroidOta,
        ),
        (
            qualcomm_bootldr(&[("aboot", &elf), ("rpm", b"rpm")], None),
            FileFormat::AndroidBootloader,
        ),
        (
            fugu_sized(&elf, b"droidboot"),
            FileFormat::AndroidBootloader,
        ),
        (
            fugu_chunks(&[(b"IFWI!!!!", 1, &elf), (b"SPLASHS!", 1, b"splash")]),
            FileFormat::AndroidBootloader,
        ),
        (meta_image(&[("hyp", &elf)]), FileFormat::AndroidBootloader),
        (
            fbpk_v2(
                &[PackEntry {
                    kind: 1,
                    name: "abl",
                    product: "",
                    data: &elf,
                }],
                false,
            ),
            FileFormat::AndroidBootloader,
        ),
        (
            fbpk_v1(&[PackEntry {
                kind: 1,
                name: "xbl",
                product: "",
                data: &elf,
            }]),
            FileFormat::AndroidBootloader,
        ),
    ]
}

#[test]
fn every_fixture_is_detected_as_its_own_format() {
    for (data, format) in sweep_fixtures() {
        let payload = classify(&data);
        assert_eq!(payload.format.format, format, "{}", notes(&payload));
        let layout = zrax::formats::android::detect(&data).expect("Android magic");
        assert_eq!(payload.format.variant_name.as_deref(), Some(layout.label()));
    }
}

#[test]
fn byte_mutations_and_truncations_never_panic() {
    let options = ClassifierOptions::new();
    for (data, _) in sweep_fixtures() {
        for end in 0..data.len() {
            let _ = detect_payload(&data[..end], &options);
        }
        for i in 0..data.len() {
            for mutation in [0x00, 0xff, data[i] ^ 0x01] {
                let mut mutated = data.clone();
                mutated[i] = mutation;
                let _ = container::parse(
                    &mutated,
                    Kind::Android(zrax::formats::android::detect(&mutated).unwrap_or(Layout::Boot)),
                );
                if i % 5 == 0 {
                    let _ = detect_payload(&mutated, &options);
                }
            }
        }
    }
}
