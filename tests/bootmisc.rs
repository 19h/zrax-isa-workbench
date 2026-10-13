//! Miscellaneous boot images: OP-TEE headers (version 1 `tee.bin` with init
//! and paged parts, version 2 image tables), Amlogic USB burning images
//! (item tables 1 and 2, CRC-32, VERIFY SHA-1 records, item roles), Allwinner
//! IMAGEWTY images (awimage-packed plaintext and RC6-encrypted fixtures,
//! hand-built version 0x0300 images) and barebox ARM heads (A32, Thumb-2,
//! A64 branch and NOP), with corruption, truncation and mutation sweeps.

use zrax::formats::checksum::Sha1;
use zrax::formats::container::Kind;
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa, MetadataKey, MetadataValue,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// clang-generated A32 and AArch64 machine code, and a synthetic x86-64
/// ELF header.
fn arm_code() -> Vec<u8> {
    fixture("socboot2/arm.text.bin")
}

fn aarch64_code() -> Vec<u8> {
    fixture("transforms/aarch64.text.bin")
}

fn elf_x86_64() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn assert_note(p: &DetectionPayload, text: &str) {
    assert!(has_note(p, text), "missing note {text:?}: {:#?}", p.notes);
}

fn metadata_text(p: &DetectionPayload, key: &str) -> String {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .unwrap_or_else(|| panic!("metadata {key}: {:?}", p.metadata))
        .value
        .to_string()
}

fn entry_point(p: &DetectionPayload) -> Option<u64> {
    p.metadata.iter().find_map(|m| match (&m.key, &m.value) {
        (MetadataKey::EntryPoint, MetadataValue::Address(address)) => Some(*address),
        _ => None,
    })
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label}: {:#?}", p.slices))
}

fn put_u16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn pad_to(data: &mut Vec<u8>, align: usize) {
    while data.len() % align != 0 {
        data.push(0);
    }
}

// ---------------------------------------------------------------------------
// OP-TEE
// ---------------------------------------------------------------------------

const OPTEE_MAGIC: u32 = 0x4554_504f;
const OPTEE_ARM32: u8 = 0;
const OPTEE_ARM64: u8 = 1;

/// Version 1 `tee.bin` (optee_os `output_header_v1`): magic, version 1,
/// architecture, flags 0, init size, load address high and low words, init
/// memory usage, paged size; then the init and paged parts.
fn optee_v1(arch: u8, load: u64, init: &[u8], paged: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x1c];
    put_u32(&mut data, 0, OPTEE_MAGIC);
    data[4] = 1;
    data[5] = arch;
    put_u32(&mut data, 0x08, init.len() as u32);
    put_u32(&mut data, 0x0c, (load >> 32) as u32);
    put_u32(&mut data, 0x10, load as u32);
    put_u32(&mut data, 0x14, 0x0010_0000);
    put_u32(&mut data, 0x18, paged.len() as u32);
    data.extend_from_slice(init);
    data.extend_from_slice(paged);
    data
}

/// One version 2 image record: load address high and low words, image ID
/// (0 pager, 1 paged), size.
struct OpteeImage {
    high: u32,
    low: u32,
    id: u32,
    size: u32,
}

/// Version 2 `tee-header_v2.bin` (optee_os `output_header_v2`): magic,
/// version 2, architecture, flags 0, image count, image records.
fn optee_v2(arch: u8, images: &[OpteeImage]) -> Vec<u8> {
    let mut data = vec![0u8; 0x0c];
    put_u32(&mut data, 0, OPTEE_MAGIC);
    data[4] = 2;
    data[5] = arch;
    put_u32(&mut data, 0x08, images.len() as u32);
    for image in images {
        for word in [image.high, image.low, image.id, image.size] {
            data.extend_from_slice(&word.to_le_bytes());
        }
    }
    data
}

/// The pager at `0x0E10_0000` and a paged image whose address the loader
/// chooses, as `output_header_v2` writes them.
fn paged_v2_images() -> Vec<OpteeImage> {
    vec![
        OpteeImage {
            high: 0,
            low: 0x0e10_0000,
            id: 0,
            size: 0x4_0000,
        },
        OpteeImage {
            high: 0xffff_ffff,
            low: 0xffff_ffff,
            id: 1,
            size: 0x2_0000,
        },
    ]
}

#[test]
fn optee_v1_arch_field_names_aarch64_and_both_parts_are_code() {
    let code = aarch64_code();
    let (init, paged) = code.split_at(4096);
    let image = optee_v1(OPTEE_ARM64, 0x0e10_0000, init, paged);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::OpteeImage);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("OP-TEE header v1 image (tee.bin)")
    );
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::AArch64, 64, Endianness::Little)
    );
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(entry_point(&p), Some(0x0e10_0000));
    assert_note(&p, "Architecture field 1 names AArch64");
    let pager = slice(&p, "Init part (pager)");
    assert_eq!(
        (pager.offset, pager.size, pager.isa),
        (0x1c, 4096, Isa::AArch64)
    );
    let paged_slice = slice(&p, "Paged part");
    assert_eq!(
        (paged_slice.offset, paged_slice.size),
        (0x1c + 4096, paged.len() as u64)
    );
    assert_eq!(metadata_text(&p, "optee_arch"), "AArch64");
}

#[test]
fn optee_v1_aarch32_takes_the_code_byte_order_from_the_code() {
    let image = optee_v1(OPTEE_ARM32, 0x8400_0000, &arm_code(), &[]);
    let p = classify(&image);
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::Arm, 32));
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_note(&p, "does not state the A32 code byte order");
    assert_eq!(p.slices.len(), 1);
}

#[test]
fn optee_v1_sizes_must_cover_the_file_exactly() {
    let code = aarch64_code();
    let image = optee_v1(OPTEE_ARM64, 0, &code[..512], &code[512..1024]);
    let mut short = image.clone();
    short.truncate(image.len() - 1);
    assert!(error_text(&short).contains("Truncated OP-TEE paged part"));
    let mut long = image.clone();
    long.extend_from_slice(b"junk");
    assert!(error_text(&long).contains("Unexpected 4 B after the OP-TEE image"));
    // Erased flash after the image is allowed.
    let mut padded = image.clone();
    padded.extend_from_slice(&[0xff; 64]);
    assert_eq!(classify(&padded).format.format, FileFormat::OpteeImage);
    let mut no_pager = image.clone();
    put_u32(&mut no_pager, 0x08, 0);
    assert!(error_text(&no_pager).contains("Invalid OP-TEE init size 0 B"));
    let mut arch = image;
    arch[5] = 2;
    assert!(error_text(&arch).contains("Unknown OP-TEE architecture 2"));
}

#[test]
fn optee_v2_header_names_the_target_of_its_separate_images() {
    let header = optee_v2(OPTEE_ARM64, &paged_v2_images());
    let p = classify(&header);
    assert_eq!(p.format.format, FileFormat::OpteeImage);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("OP-TEE header v2 (tee-header_v2.bin)")
    );
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::AArch64, 64));
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(p.slices.len(), 0);
    assert_eq!(entry_point(&p), Some(0x0e10_0000));
    assert_note(&p, "the images are separate files");
    assert_eq!(
        metadata_text(&p, "optee_image_0"),
        "pager image; load 0xE100000; 256 KiB"
    );
    assert_eq!(
        metadata_text(&p, "optee_image_1"),
        "paged image; load address chosen by the loader; 128 KiB"
    );
}

#[test]
fn optee_v2_tables_are_checked_like_tf_a() {
    let pager = || OpteeImage {
        high: 0,
        low: 0x1000,
        id: 0,
        size: 16,
    };
    assert!(error_text(&optee_v2(OPTEE_ARM64, &[])).contains("Invalid OP-TEE image count 0"));
    let three = optee_v2(OPTEE_ARM64, &[pager(), pager(), pager()]);
    assert!(error_text(&three).contains("Invalid OP-TEE image count 3"));
    let duplicate = optee_v2(OPTEE_ARM64, &[pager(), pager()]);
    assert!(error_text(&duplicate).contains("Duplicate OP-TEE image ID 0 in record 1"));
    let unknown = optee_v2(OPTEE_ARM64, &[OpteeImage { id: 2, ..pager() }]);
    assert!(error_text(&unknown).contains("Unknown OP-TEE image ID 2 in record 0"));
    // An image after the header is listed only when it is recognized.
    let mut with_elf = optee_v2(OPTEE_ARM32, &[pager()]);
    with_elf.extend_from_slice(&elf_x86_64());
    let p = classify(&with_elf);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(slice(&p, "Trailing data").offset, 0x1c);
}

#[test]
fn optee_needs_a_documented_header_version() {
    let mut header = optee_v2(OPTEE_ARM64, &paged_v2_images());
    header[4] = 3;
    assert!(!matches!(
        detect_format(&header),
        DetectedFormat::Container {
            kind: Kind::BootMisc(_)
        }
    ));
}

// ---------------------------------------------------------------------------
// Amlogic
// ---------------------------------------------------------------------------

const AML_MAGIC: u32 = 0x27b5_1956;

/// CRC-32 as Amlogic's `calc_img_crc` computes it: reflected polynomial
/// `0xEDB88320`, initial value `0xFFFFFFFF`, no final XOR. Written bit by
/// bit so it does not share the crate's table.
fn amlogic_crc(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// One item: main and sub type, data, file type (0 normal, 0xFE sparse),
/// and the item whose data a backup item shares.
#[derive(Clone)]
struct AmlItem {
    main: &'static str,
    sub: &'static str,
    data: Vec<u8>,
    file_type: u32,
    backup_of: Option<u16>,
}

fn aml_item(main: &'static str, sub: &'static str, data: Vec<u8>) -> AmlItem {
    AmlItem {
        main,
        sub,
        data,
        file_type: 0,
        backup_of: None,
    }
}

/// The 48-byte VERIFY contents for `data` (`gen_sha1sum_verify`).
fn verify_record(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let digest = hasher.finish();
    let mut record = b"sha1sum ".to_vec();
    for byte in digest {
        record.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    record
}

/// A partition item followed by its VERIFY item, as `image_pack` writes
/// `[LIST_VERIFY]` entries.
fn verified_partition(sub: &'static str, data: Vec<u8>) -> [AmlItem; 2] {
    let verify = verify_record(&data);
    [
        aml_item("PARTITION", sub, data),
        aml_item("VERIFY", sub, verify),
    ]
}

/// An Amlogic burning image: the 64-byte header (CRC, version, magic, image
/// size, alignment 4, item count), the item table (128-byte version 1 or
/// 576-byte version 2 records: ID, file type, reader offset 0, data offset,
/// size, main and sub type names, verify flag, backup flag and ID), then the
/// item data aligned to 4 bytes; the CRC covers everything after itself.
fn amlogic(version: u32, items: &[AmlItem]) -> Vec<u8> {
    let (record_size, name_size) = if version == 1 { (128, 32) } else { (576, 256) };
    let mut data = vec![0u8; 64 + items.len() * record_size];
    put_u32(&mut data, 4, version);
    put_u32(&mut data, 8, AML_MAGIC);
    put_u32(&mut data, 0x14, 4);
    put_u32(&mut data, 0x18, items.len() as u32);
    let mut offsets = Vec::new();
    for item in items {
        let offset = match item.backup_of {
            Some(source) => offsets[usize::from(source)],
            None => {
                pad_to(&mut data, 4);
                let offset = data.len();
                data.extend_from_slice(&item.data);
                offset
            }
        };
        offsets.push(offset);
    }
    for (i, item) in items.iter().enumerate() {
        let record = 64 + i * record_size;
        put_u32(&mut data, record, i as u32);
        put_u32(&mut data, record + 4, item.file_type);
        put_u64(&mut data, record + 0x10, offsets[i] as u64);
        put_u64(&mut data, record + 0x18, item.data.len() as u64);
        let main = record + 0x20;
        data[main..main + item.main.len()].copy_from_slice(item.main.as_bytes());
        let sub = main + name_size;
        data[sub..sub + item.sub.len()].copy_from_slice(item.sub.as_bytes());
        let after = sub + name_size;
        put_u32(&mut data, after, u32::from(item.main == "VERIFY"));
        if let Some(source) = item.backup_of {
            put_u16(&mut data, after + 4, 1);
            put_u16(&mut data, after + 6, source);
        }
    }
    let size = data.len() as u64;
    put_u64(&mut data, 0x0c, size);
    let crc = amlogic_crc(&data[4..]);
    put_u32(&mut data, 0, crc);
    data
}

/// Recomputes the CRC after a test edits an image.
fn reseal_amlogic(data: &mut [u8]) {
    let crc = amlogic_crc(&data[4..]);
    put_u32(data, 0, crc);
}

/// DDR and U-Boot USB stages, the boot loader partition, a recognized and
/// an unrecognized partition, each partition with its VERIFY record, the
/// platform configuration and an encrypted stage.
fn amlogic_items() -> Vec<AmlItem> {
    let mut items = vec![
        aml_item("USB", "DDR", arm_code()),
        aml_item("USB", "UBOOT", aarch64_code()),
        aml_item("USB", "UBOOT_ENC", vec![0x5a; 256]),
    ];
    items.extend(verified_partition("bootloader", arm_code()));
    items.extend(verified_partition("boot", elf_x86_64()));
    items.extend(verified_partition("logo", vec![0x33; 300]));
    items.push(aml_item(
        "conf",
        "platform",
        b"Platform:0x0811\nDDRLoad:0xd9000000\n".to_vec(),
    ));
    items
}

#[test]
fn amlogic_v2_items_are_classified_by_role() {
    let image = amlogic(2, &amlogic_items());
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AmlogicUpgrade);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Amlogic USB burning image")
    );
    assert_note(&p, "version 2: 10 items, 256 B item names; CRC-32 0x");
    assert_note(&p, "3 VERIFY SHA-1 records verified");
    assert_note(&p, "listed as opaque data: PARTITION/logo");
    assert_note(
        &p,
        "Items named as encrypted (_ENC) are opaque: USB/UBOOT_ENC",
    );
    assert_eq!(slice(&p, "USB/DDR").isa, Isa::Arm);
    assert_eq!(slice(&p, "USB/UBOOT").isa, Isa::AArch64);
    // The boot loader partition is code even though no format is recognized.
    assert_eq!(slice(&p, "PARTITION/bootloader").isa, Isa::Arm);
    assert_eq!(slice(&p, "PARTITION/boot").isa, Isa::X86_64);
    for opaque in [
        "USB/UBOOT_ENC",
        "PARTITION/logo",
        "VERIFY/boot",
        "conf/platform",
    ] {
        assert!(matches!(slice(&p, opaque).isa, Isa::Unknown(_)), "{opaque}");
    }
    // The first classified item names the primary ISA; no field does.
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    let boot = slice(&p, "PARTITION/boot");
    assert_eq!(&image[boot.offset as usize..][..4], b"\x7fELF");
    assert_eq!(metadata_text(&p, "amlogic_version"), "2");
}

#[test]
fn amlogic_v1_uses_32_byte_names() {
    let p = classify(&amlogic(1, &amlogic_items()));
    assert_eq!(p.format.format, FileFormat::AmlogicUpgrade);
    assert_note(&p, "version 1: 10 items, 32 B item names");
    assert_eq!(slice(&p, "PARTITION/boot").isa, Isa::X86_64);
}

#[test]
fn amlogic_backup_and_sparse_items_are_noted() {
    let mut items = vec![aml_item("PARTITION", "boot", elf_x86_64())];
    items.push(AmlItem {
        backup_of: Some(0),
        ..aml_item("PARTITION", "bootbak", elf_x86_64())
    });
    items.push(AmlItem {
        file_type: 0x77,
        ..aml_item("PARTITION", "odd", vec![1; 8])
    });
    let p = classify(&amlogic(2, &items));
    assert_note(
        &p,
        "Backup items share the data of an earlier item: PARTITION/bootbak (item 0)",
    );
    assert_note(
        &p,
        "file type other than normal (0) or sparse (0xFE): PARTITION/odd (0x77)",
    );
    assert_eq!(
        slice(&p, "PARTITION/bootbak").offset,
        slice(&p, "PARTITION/boot").offset
    );
}

#[test]
fn amlogic_crc_and_item_ids_are_checked_and_digest_mismatches_noted() {
    let image = amlogic(2, &amlogic_items());
    let mut corrupt = image.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(
        error_text(&corrupt).starts_with("Boot image parse error: Invalid Amlogic image CRC-32")
    );

    let mut items = amlogic_items();
    let verify = items
        .iter_mut()
        .find(|i| i.main == "VERIFY" && i.sub == "boot")
        .expect("VERIFY/boot");
    verify.data[8] = if verify.data[8] == b'0' { b'1' } else { b'0' };
    let p = classify(&amlogic(2, &items));
    assert_note(
        &p,
        "VERIFY SHA-1 records that do not match their item: PARTITION/boot (recorded ",
    );
    assert_note(&p, "2 VERIFY SHA-1 records verified");

    let mut wrong_id = image.clone();
    put_u32(&mut wrong_id, 64 + 576, 7);
    reseal_amlogic(&mut wrong_id);
    assert!(error_text(&wrong_id).contains("Invalid Amlogic item ID 7 in record 1"));

    let mut beyond = image.clone();
    put_u64(&mut beyond, 64 + 0x18, 1 << 20);
    reseal_amlogic(&mut beyond);
    assert!(error_text(&beyond).contains("Truncated Amlogic item 0 (USB/DDR) data"));

    let mut version = image.clone();
    put_u32(&mut version, 4, 3);
    reseal_amlogic(&mut version);
    assert!(error_text(&version).contains("Unsupported Amlogic image version 3"));

    let mut count = image.clone();
    put_u32(&mut count, 0x18, 1000);
    reseal_amlogic(&mut count);
    assert!(error_text(&count).contains("Invalid Amlogic item count 1000"));

    let mut trailing = image;
    trailing.extend_from_slice(b"tail");
    assert!(error_text(&trailing).contains("Unexpected 4 B after the Amlogic image"));
}

#[test]
fn amlogic_overlapping_items_cannot_multiply_the_hashing() {
    // Four partitions share one 4 KiB range, each with its VERIFY record.
    let data = vec![0x42; 4096];
    let mut items = Vec::new();
    for _ in 0..4 {
        let backup_of = (!items.is_empty()).then_some(0);
        items.push(AmlItem {
            backup_of,
            ..aml_item("PARTITION", "shared", data.clone())
        });
        items.push(aml_item("VERIFY", "shared", verify_record(&data)));
    }
    let p = classify(&amlogic(1, &items));
    assert_note(&p, "VERIFY SHA-1 records verified");
    assert_note(
        &p,
        "beyond the hashing budget (twice the image size) were not checked",
    );
}

#[test]
fn amlogic_verify_records_not_in_the_packer_form_are_counted() {
    let items = vec![
        aml_item("PARTITION", "boot", elf_x86_64()),
        aml_item("VERIFY", "boot", b"md5sum 0123".to_vec()),
        aml_item("VERIFY", "orphan", verify_record(b"x")),
    ];
    let p = classify(&amlogic(2, &items));
    assert_note(
        &p,
        "VERIFY items not in the packer's form or not after their item; not checked: boot, orphan",
    );
}

// ---------------------------------------------------------------------------
// Allwinner IMAGEWTY
// ---------------------------------------------------------------------------

#[test]
fn awimage_plain_v1_image_lists_its_files() {
    let image = fixture("bootmisc/imagewty-plain.img");
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AllwinnerImage);
    assert_eq!(p.format.variant_name.as_deref(), Some("IMAGEWTY image"));
    assert_note(&p, "header version 0x0100: 3 files");
    assert_note(&p, "awutils' reverse-engineered layout");
    let payload = slice(&p, "./payload.fex (12345678/PAYLOAD_00000000)");
    assert_eq!(
        (payload.offset, payload.size, payload.isa),
        (0x1000, 512, Isa::X86_64)
    );
    assert_eq!(payload.decoded, None);
    assert!(matches!(
        slice(&p, "./sys_config.fex (COMMON/SYS_CONFIG100000)").isa,
        Isa::Unknown(_)
    ));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(metadata_text(&p, "imagewty_usb_id"), "0x8743:0x1234");
}

#[test]
fn awimage_encrypted_image_is_decrypted_with_the_published_keys() {
    let image = fixture("bootmisc/imagewty-encrypted.img");
    assert_ne!(&image[..8], b"IMAGEWTY");
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AllwinnerImage);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("IMAGEWTY image (RC6-encrypted header)")
    );
    let payload = slice(&p, "./payload.fex (12345678/PAYLOAD_00000000)");
    assert_eq!(
        (payload.offset, payload.size, payload.isa),
        (0x1000, 512, Isa::X86_64)
    );
    let decoded = payload.decoded.as_ref().expect("decrypted range");
    assert_eq!((decoded.transform.as_str(), decoded.size), ("RC6", 512));
    assert_note(
        &p,
        "additional Twofish layer that awutils does not decrypt; opaque: ./tool.bin",
    );
}

/// One version 0x0300 item: main type, sub type, file name, file data,
/// encryption plug-in ID.
struct WtyItem {
    main: &'static str,
    sub: &'static str,
    name: &'static str,
    data: Vec<u8>,
    plugin: &'static str,
}

/// A version 0x0300 image (Allwinner `ImageHead_t`, `ImageItem_t`): the
/// 1024-byte header (magic, version 0x0300, size 0x60, image version,
/// 64-bit length, alignment 1024, PID, VID, hardware and firmware IDs, item
/// size 1024, item count, item table offset 1024), 1024-byte item records
/// (version 0x0100, size 1024, main and sub type, name, 64-bit stored
/// length, file length and offset, plug-in ID), and the data in 1024-byte
/// aligned slots.
fn imagewty_v3(items: &[WtyItem]) -> Vec<u8> {
    let mut data = vec![0u8; 1024 * (items.len() + 1)];
    data[..8].copy_from_slice(b"IMAGEWTY");
    put_u32(&mut data, 0x08, 0x0300);
    put_u32(&mut data, 0x0c, 0x60);
    put_u32(&mut data, 0x14, 0x0010_0234);
    put_u32(&mut data, 0x20, 1024);
    put_u32(&mut data, 0x24, 0x1234);
    put_u32(&mut data, 0x28, 0x8743);
    put_u32(&mut data, 0x2c, 0x1680);
    put_u32(&mut data, 0x30, 0x1680);
    put_u32(&mut data, 0x38, 1024);
    put_u32(&mut data, 0x3c, items.len() as u32);
    put_u32(&mut data, 0x40, 1024);
    for (i, item) in items.iter().enumerate() {
        let offset = data.len();
        data.extend_from_slice(&item.data);
        pad_to(&mut data, 1024);
        let stored = data.len() - offset;
        let record = 1024 * (i + 1);
        put_u32(&mut data, record, 0x0100);
        put_u32(&mut data, record + 4, 1024);
        data[record + 8..record + 8 + item.main.len()].copy_from_slice(item.main.as_bytes());
        data[record + 0x10..record + 0x10 + item.sub.len()].copy_from_slice(item.sub.as_bytes());
        data[record + 0x24..record + 0x24 + item.name.len()].copy_from_slice(item.name.as_bytes());
        put_u64(&mut data, record + 0x124, stored as u64);
        put_u64(&mut data, record + 0x12c, item.data.len() as u64);
        put_u64(&mut data, record + 0x134, offset as u64);
        data[record + 0x13c..record + 0x13c + item.plugin.len()]
            .copy_from_slice(item.plugin.as_bytes());
    }
    let length = data.len() as u64;
    put_u64(&mut data, 0x18, length);
    data
}

fn wty_items() -> Vec<WtyItem> {
    vec![
        WtyItem {
            main: "12345678",
            sub: "UBOOT_0000000000",
            name: "u-boot.fex",
            data: elf_x86_64(),
            plugin: "",
        },
        WtyItem {
            main: "RFSFAT16",
            sub: "BOOT_00000000000",
            name: "boot.fex",
            data: elf_x86_64(),
            plugin: "aes-plugin",
        },
        WtyItem {
            main: "COMMON  ",
            sub: "SYS_CONFIG100000",
            name: "sys_config.fex",
            data: b"[platform]\r\n".to_vec(),
            plugin: "",
        },
    ]
}

// RC6-32/20/32 encryption ("The RC6 Block Cipher" v1.1, section 2.2), for
// building encrypted fixtures independently of the parser.

fn rc6_schedule(key: &[u8; 32]) -> [u32; 44] {
    let mut words: Vec<u32> = key
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().expect("four bytes")))
        .collect();
    let mut s = [0u32; 44];
    s[0] = 0xb7e1_5163;
    for i in 1..44 {
        s[i] = s[i - 1].wrapping_add(0x9e37_79b9);
    }
    let (mut a, mut b, mut i, mut j) = (0u32, 0u32, 0usize, 0usize);
    for _ in 0..3 * 44 {
        a = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
        s[i] = a;
        b = words[j]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(a.wrapping_add(b) % 32);
        words[j] = b;
        i = (i + 1) % 44;
        j = (j + 1) % words.len();
    }
    s
}

fn rc6_encrypt(s: &[u32; 44], bytes: &mut [u8]) {
    let f = |x: u32| {
        x.wrapping_mul(x.wrapping_mul(2).wrapping_add(1))
            .rotate_left(5)
    };
    for block in bytes.chunks_exact_mut(16) {
        let mut w = [0u32; 4];
        for (word, b) in w.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes(b.try_into().expect("four bytes"));
        }
        let [mut a, mut b, mut c, mut d] = w;
        b = b.wrapping_add(s[0]);
        d = d.wrapping_add(s[1]);
        for round in 1..=20 {
            let t = f(b);
            let u = f(d);
            a = (a ^ t).rotate_left(u % 32).wrapping_add(s[2 * round]);
            c = (c ^ u).rotate_left(t % 32).wrapping_add(s[2 * round + 1]);
            (a, b, c, d) = (b, c, d, a);
        }
        a = a.wrapping_add(s[42]);
        c = c.wrapping_add(s[43]);
        for (b, word) in block.chunks_exact_mut(4).zip([a, b, c, d]) {
            b.copy_from_slice(&word.to_le_bytes());
        }
    }
}

/// awutils `crypto_init`: 31 `fill` bytes and a final `last` byte.
fn awutils_key(fill: u8, last: u8) -> [u8; 32] {
    let mut key = [fill; 32];
    key[31] = last;
    key
}

/// Encrypt a version 0x0300 image the way awimage does: header with the
/// `i` key, item table with the `m` key, file data with the `g` key.
fn encrypt_imagewty(image: &mut [u8], count: usize) {
    let table_end = 1024 * (count + 1);
    rc6_encrypt(&rc6_schedule(&awutils_key(0, b'i')), &mut image[..1024]);
    rc6_encrypt(
        &rc6_schedule(&awutils_key(1, b'm')),
        &mut image[1024..table_end],
    );
    rc6_encrypt(
        &rc6_schedule(&awutils_key(2, b'g')),
        &mut image[table_end..],
    );
}

#[test]
fn imagewty_v3_plug_in_encrypted_and_unrecognized_files_are_opaque() {
    let p = classify(&imagewty_v3(&wty_items()));
    assert_eq!(p.format.format, FileFormat::AllwinnerImage);
    assert_note(&p, "header version 0x0300: 3 files");
    assert!(!has_note(&p, "reverse-engineered"));
    let uboot = slice(&p, "u-boot.fex (12345678/UBOOT_0000000000)");
    assert_eq!(
        (uboot.offset, uboot.size, uboot.isa),
        (4096, 256, Isa::X86_64)
    );
    assert!(matches!(
        slice(&p, "boot.fex (RFSFAT16/BOOT_00000000000)").isa,
        Isa::Unknown(_)
    ));
    assert_note(
        &p,
        "Files with an encryption plug-in ID are opaque: boot.fex",
    );
    assert_eq!(metadata_text(&p, "imagewty_hardware_id"), "0x1680");
}

#[test]
fn imagewty_v3_encrypted_image_round_trips() {
    let items = wty_items();
    let mut image = imagewty_v3(&items);
    encrypt_imagewty(&mut image, items.len());
    let p = classify(&image);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("IMAGEWTY image (RC6-encrypted header)")
    );
    let uboot = slice(&p, "u-boot.fex (12345678/UBOOT_0000000000)");
    assert_eq!(
        (uboot.offset, uboot.size, uboot.isa),
        (4096, 1024, Isa::X86_64)
    );
    assert_eq!(uboot.decoded.as_ref().map(|d| d.size), Some(256));
}

#[test]
fn imagewty_structure_errors_name_the_field() {
    let image = imagewty_v3(&wty_items());
    let mut version = image.clone();
    put_u32(&mut version, 8, 0x0200);
    assert!(error_text(&version).contains("Unsupported IMAGEWTY header version 0x0200"));
    let mut count = image.clone();
    put_u32(&mut count, 0x3c, 100);
    assert!(error_text(&count).contains("Invalid IMAGEWTY item count 100"));
    let mut offset = image.clone();
    put_u64(&mut offset, 1024 + 0x134, 1 << 20);
    assert!(error_text(&offset).contains("Truncated IMAGEWTY item 0 (u-boot.fex"));
    let mut lengths = image.clone();
    put_u64(&mut lengths, 1024 + 0x12c, 4096);
    assert!(error_text(&lengths).contains("file length 4096 B exceeds the stored length 1024 B"));
    let mut declared = image.clone();
    put_u64(&mut declared, 0x18, image.len() as u64 + 1);
    assert!(error_text(&declared).contains("Truncated IMAGEWTY image"));
    let mut trailing = image;
    trailing.extend_from_slice(b"tail");
    assert!(error_text(&trailing).contains("Unexpected 4 B after the IMAGEWTY image"));
}

// ---------------------------------------------------------------------------
// barebox
// ---------------------------------------------------------------------------

/// A barebox image: an assembled head (the first 0x50 bytes of a
/// committed fixture), `code`, and the image size at 0x2C.
fn barebox(head: &str, code: &[u8]) -> Vec<u8> {
    let mut image = fixture(&format!("bootmisc/barebox-{head}.bin"));
    image.truncate(0x50);
    image.extend_from_slice(code);
    let size = image.len() as u32;
    put_u32(&mut image, 0x2c, size);
    image
}

#[test]
fn barebox_a32_branch_names_arm() {
    let p = classify(&barebox("a32", &arm_code()));
    assert_eq!(p.format.format, FileFormat::BareboxImage);
    assert_eq!(p.format.variant_name.as_deref(), Some("barebox image"));
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_note(&p, "A32 B 0xEA000012 to image offset 0x50");
    assert_eq!(metadata_text(&p, "barebox_text_base"), "0x00000000");
}

#[test]
fn barebox_thumb2_head_names_arm() {
    let p = classify(&barebox("thumb2", &arm_code()));
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_note(&p, "into Thumb-2 code");
}

#[test]
fn barebox_aarch64_heads_name_aarch64() {
    for (head, note) in [
        ("a64-branch", "A64 B 0x14000014 to image offset 0x50"),
        ("a64-nop", "A64 NOP and text base 0xFFFFFFFF"),
    ] {
        let p = classify(&barebox(head, &aarch64_code()));
        assert_eq!(p.format.format, FileFormat::BareboxImage, "{head}");
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth),
            (Isa::AArch64, 64),
            "{head}"
        );
        assert_eq!(p.primary.source, ClassificationSource::FileFormat, "{head}");
        assert_note(&p, note);
    }
}

#[test]
fn barebox_without_a_documented_head_takes_the_isa_from_the_code() {
    let mut unknown = barebox("a32", &aarch64_code());
    put_u32(&mut unknown, 0, 0);
    let p = classify(&unknown);
    assert_eq!(p.format.format, FileFormat::BareboxImage);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert_note(&p, "not a documented barebox head; ISA from the code model");
    // An A64 NOP head needs the 0xFFFFFFFF text base of head_64.S.
    let mut nop = barebox("a64-nop", &aarch64_code());
    put_u32(&mut nop, 0x28, 0);
    assert_note(&classify(&nop), "not 0xFFFFFFFF; ISA from the code model");
    // A branch into the head is not a branch to code.
    let mut into_head = barebox("a32", &arm_code());
    put_u32(&mut into_head, 0, 0xea00_0002);
    assert_note(&classify(&into_head), "outside the image code");
}

#[test]
fn barebox_size_and_trailing_data() {
    let image = barebox("a32", &arm_code());
    let mut short = image.clone();
    put_u32(&mut short, 0x2c, 0x40);
    assert!(error_text(&short).contains("Invalid barebox image size 64 B"));
    let mut long = image.clone();
    put_u32(&mut long, 0x2c, image.len() as u32 + 4);
    assert!(error_text(&long).contains("Truncated barebox image"));
    let mut spare = image.clone();
    put_u32(&mut spare, 0x30, 0x1234_5678);
    assert_note(
        &classify(&spare),
        "spare words at 0x30 hold board or system-on-chip data",
    );
    let mut appended = image.clone();
    appended.extend_from_slice(&elf_x86_64());
    let p = classify(&appended);
    assert_eq!(p.primary.isa, Isa::Arm);
    let trailing = slice(&p, "Trailing data");
    assert_eq!(
        (trailing.offset, trailing.isa),
        (image.len() as u64, Isa::X86_64)
    );
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

/// Small instances of every layout, for the sweeps.
fn small_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let arm = &arm_code()[..96];
    let aarch64 = &aarch64_code()[..96];
    let items = [
        aml_item("USB", "DDR", arm.to_vec()),
        aml_item("PARTITION", "boot", vec![7; 24]),
        aml_item("VERIFY", "boot", verify_record(&[7; 24])),
    ];
    let mut encrypted = imagewty_v3(&[WtyItem {
        main: "12345678",
        sub: "UBOOT_0000000000",
        name: "u-boot.fex",
        data: elf_x86_64()[..64].to_vec(),
        plugin: "",
    }]);
    encrypt_imagewty(&mut encrypted, 1);
    vec![
        ("optee v1", optee_v1(OPTEE_ARM64, 0x1000, aarch64, &[9; 16])),
        ("optee v2", optee_v2(OPTEE_ARM64, &paged_v2_images())),
        ("amlogic v1", amlogic(1, &items)),
        ("amlogic v2", amlogic(2, &items[..1])),
        ("imagewty plain", fixture("bootmisc/imagewty-plain.img")),
        ("imagewty encrypted", encrypted),
        ("barebox a32", barebox("a32", arm)),
        ("barebox a64", barebox("a64-branch", aarch64)),
    ]
}

#[test]
fn every_prefix_is_an_error_or_not_the_layout() {
    for (name, image) in small_fixtures() {
        let full = classify(&image);
        assert!(
            matches!(
                full.format.format,
                FileFormat::OpteeImage
                    | FileFormat::AmlogicUpgrade
                    | FileFormat::AllwinnerImage
                    | FileFormat::BareboxImage
            ),
            "{name}: {:?}",
            full.format.format
        );
        for end in 0..image.len() {
            if let Ok(p) = detect_payload(&image[..end], &ClassifierOptions::new()) {
                // Cutting only erased flash or zero fill may still parse.
                let only_padding = image[end..].iter().all(|&b| b == 0 || b == 0xff);
                assert!(
                    p.format.format != full.format.format || only_padding,
                    "{name}: prefix {end} still parses as {:?}",
                    p.format.format
                );
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    let mutations: [fn(u8) -> u8; 3] = [|_| 0x00, |_| 0xff, |b| b ^ 0x01];
    for (_, image) in small_fixtures() {
        // Each position of the first 2 KiB, then every 61st byte.
        let positions = (0..image.len()).filter(|&i| i < 2048 || i % 61 == 0);
        for i in positions {
            for mutate in mutations {
                let mut mutated = image.clone();
                mutated[i] = mutate(mutated[i]);
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}

#[test]
fn json_ids_are_stable() {
    let ids = [
        (FileFormat::OpteeImage, "\"opteeimage\""),
        (FileFormat::AmlogicUpgrade, "\"amlogicupgrade\""),
        (FileFormat::AllwinnerImage, "\"allwinnerimage\""),
        (FileFormat::BareboxImage, "\"bareboximage\""),
    ];
    for (format, id) in ids {
        assert_eq!(serde_json::to_string(&format).expect("serializes"), id);
    }
}
