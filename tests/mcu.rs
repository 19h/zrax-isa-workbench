//! MCU update images: UF2 block files (family IDs, reassembly, file
//! containers, RP2350 workaround blocks), STM32 DfuSe files, Silicon Labs
//! GBL v3 tag streams (plain, LZ4, LZMA, encrypted) and Cypress `.cyacd` /
//! `.cyacd2` text, with checksums, truncation and mutation sweeps. Fixtures
//! are built here from the documented wire layouts around compiled code in
//! `tests/fixtures/mcu`.

use zrax::formats::checksum::{crc32, crc32_update};
use zrax::formats::container::Kind;
use zrax::formats::mcu::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa, MetadataValue,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mcu");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

/// Cortex-M4 Thumb-2 code (`generate.sh`).
fn thumb() -> Vec<u8> {
    fixture("thumbv7em.text.bin")
}

/// RV32IMAC code (`generate.sh`).
fn riscv32() -> Vec<u8> {
    fixture("riscv32.text.bin")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn metadata<'a>(payload: &'a DetectionPayload, key: &str) -> Option<&'a MetadataValue> {
    payload
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| &m.value)
}

fn metadata_text(payload: &DetectionPayload, key: &str) -> String {
    metadata(payload, key)
        .unwrap_or_else(|| panic!("metadata {key}"))
        .to_string()
}

fn has_note(payload: &DetectionPayload, text: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(text))
}

fn mcu_layout(data: &[u8]) -> Option<Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: Kind::Mcu(layout),
        } => Some(layout),
        _ => None,
    }
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// A 64-byte ELF64 little-endian x86-64 header.
fn elf_x86_64() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    data[16..20].copy_from_slice(&[2, 0, 0x3e, 0]);
    data
}

/// Feed every prefix and every single-byte mutation (0x00, 0xFF, low bit
/// flipped) through detection, the parser of `layout` and classification.
fn sweep(file: &[u8], layout: Layout) {
    let options = ClassifierOptions::new();
    for end in 0..file.len() {
        let _ = mcu::parse_container(&file[..end], layout);
        let _ = detect_payload(&file[..end], &options);
    }
    for i in 0..file.len() {
        for value in [0x00, 0xff, file[i] ^ 0x01] {
            let mut mutated = file.to_vec();
            mutated[i] = value;
            let _ = mcu::parse_container(&mutated, layout);
            let _ = detect_payload(&mutated, &options);
        }
    }
}

// UF2 (microsoft/uf2 README at 90e9741f): 512-byte blocks, every field a
// little-endian u32.

const UF2_MAGIC_START0: u32 = 0x0a32_4655;
const UF2_MAGIC_START1: u32 = 0x9e5d_5157;
const UF2_MAGIC_END: u32 = 0x0ab1_6f30;
const UF2_FLAG_NOT_MAIN_FLASH: u32 = 0x0000_0001;
const UF2_FLAG_FILE_CONTAINER: u32 = 0x0000_1000;
const UF2_FLAG_FAMILY_ID_PRESENT: u32 = 0x0000_2000;
const UF2_FLAG_MD5_PRESENT: u32 = 0x0000_4000;
const UF2_FLAG_EXTENSION_FLAGS_PRESENT: u32 = 0x0000_8000;
const UF2_PAYLOAD: usize = 256;

/// RP2350 datasheet Table 469 and `uf2families.json`.
const RP2XXX_ABSOLUTE: u32 = 0xe48b_ff57;
const RP2XXX_DATA: u32 = 0xe48b_ff58;
const RP2350_ARM_S: u32 = 0xe48b_ff59;
const RP2350_RISCV: u32 = 0xe48b_ff5a;
const ESP32S3: u32 = 0xc47e_5767;

/// pico-sdk `UF2_EXTENSION_RP2_IGNORE_BLOCK` as a whole tag word (size 4,
/// type `0x9957E3`).
const RP2_IGNORE_BLOCK_TAG: u32 = 0x9957_e304;

/// The fields of one UF2 block.
struct Uf2Block<'a> {
    flags: u32,
    target_address: u32,
    payload: &'a [u8],
    block_no: u32,
    num_blocks: u32,
    /// `fileSize` or `familyID`.
    word28: u32,
    /// Bytes stored right after the payload in `data[]` (file name or
    /// extension tags).
    trailer: &'a [u8],
}

fn uf2_block(fields: &Uf2Block<'_>) -> Vec<u8> {
    let mut block = vec![0u8; 512];
    put_u32(&mut block, 0, UF2_MAGIC_START0); // magicStart0
    put_u32(&mut block, 4, UF2_MAGIC_START1); // magicStart1
    put_u32(&mut block, 8, fields.flags); // flags
    put_u32(&mut block, 12, fields.target_address); // targetAddr
    put_u32(&mut block, 16, fields.payload.len() as u32); // payloadSize
    put_u32(&mut block, 20, fields.block_no); // blockNo
    put_u32(&mut block, 24, fields.num_blocks); // numBlocks
    put_u32(&mut block, 28, fields.word28); // fileSize or familyID
    let end = 32 + fields.payload.len();
    block[32..end].copy_from_slice(fields.payload); // data[], zero padded
    block[end..end + fields.trailer.len()].copy_from_slice(fields.trailer);
    put_u32(&mut block, 508, UF2_MAGIC_END); // magicEnd
    block
}

/// `code` written from `address` in 256-byte payloads, numbered `0..n`,
/// with the family flag and ID when `family` is given (as `uf2conv.py`
/// writes it).
fn uf2_image(code: &[u8], address: u32, family: Option<u32>) -> Vec<u8> {
    let chunks: Vec<&[u8]> = code.chunks(UF2_PAYLOAD).collect();
    let mut file = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        file.extend(uf2_block(&Uf2Block {
            flags: family.map_or(0, |_| UF2_FLAG_FAMILY_ID_PRESENT),
            target_address: address + (i * UF2_PAYLOAD) as u32,
            payload: chunk,
            block_no: i as u32,
            num_blocks: chunks.len() as u32,
            word28: family.unwrap_or(0),
            trailer: &[],
        }));
    }
    file
}

#[test]
fn uf2_family_id_names_the_isa_and_blocks_reassemble_into_one_section() {
    let code = thumb();
    let file = uf2_image(&code, 0x1000_0000, Some(RP2350_ARM_S));
    assert_eq!(mcu_layout(&file), Some(Layout::Uf2));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Uf2);
    assert_eq!(p.format.variant_name.as_deref(), Some("UF2 block file"));
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(metadata_text(&p, "uf2_family_id"), "0xE48BFF59");
    assert_eq!(
        metadata_text(&p, "uf2_section_0"),
        format!(
            "file 0x0; destination 0x10000000; {} B stored; {} B decoded (UF2 blocks)",
            file.len(),
            code.len()
        )
    );
    assert!(metadata(&p, "uf2_section_1").is_none());
    assert!(has_note(
        &p,
        "RP2350_ARM_S: Raspberry Pi RP2350, Secure Arm image) names"
    ));
}

#[test]
fn uf2_rp2350_riscv_and_esp32s3_family_ids_name_their_own_isas() {
    let p = classify(&uf2_image(&riscv32(), 0x1000_0000, Some(RP2350_RISCV)));
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::RiscV32, 32, Endianness::Little)
    );
    // The family ID is an explicit target field: it outranks the code
    // model, which reports the disagreement.
    let p = classify(&uf2_image(&thumb(), 0x0001_0000, Some(ESP32S3)));
    assert_eq!(p.primary.isa, Isa::Xtensa);
    assert!(has_note(&p, "Container names"));
}

#[test]
fn uf2_without_a_family_id_is_classified_by_the_code_model() {
    let p = classify(&uf2_image(&thumb(), 0x0000_2000, None));
    assert_eq!(p.format.format, FileFormat::Uf2);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(&p, "No family ID; ISA from the code model"));
}

#[test]
fn uf2_with_two_families_yields_one_child_per_family() {
    let arm = uf2_image(&thumb(), 0x1000_0000, Some(RP2350_ARM_S));
    let riscv = uf2_image(&riscv32(), 0x1000_0000, Some(RP2350_RISCV));
    let file = [arm.clone(), riscv.clone()].concat();
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Uf2);
    assert_eq!(p.slices.len(), 2);
    let arm_slice = p
        .slices
        .iter()
        .find(|s| s.isa == Isa::Arm)
        .expect("Arm child");
    assert_eq!(
        arm_slice.label.as_deref(),
        Some("RP2350_ARM_S (Raspberry Pi RP2350, Secure Arm image)")
    );
    assert_eq!((arm_slice.offset, arm_slice.size), (0, arm.len() as u64));
    let decoded = arm_slice.decoded.as_ref().expect("reassembled");
    assert_eq!(decoded.transform, "UF2 blocks");
    assert_eq!(decoded.size, thumb().len() as u64);
    let riscv_slice = p
        .slices
        .iter()
        .find(|s| s.isa == Isa::RiscV32)
        .expect("RISC-V child");
    assert_eq!(
        riscv_slice.label.as_deref(),
        Some("RP2350_RISCV (Raspberry Pi RP2350, RISC-V image)")
    );
    assert_eq!(
        (riscv_slice.offset, riscv_slice.size),
        (arm.len() as u64, riscv.len() as u64)
    );
}

#[test]
fn uf2_address_gaps_are_not_materialized() {
    let code = thumb();
    let (low, high) = code[..512].split_at(256);
    let block = |address: u32, payload: &[u8], block_no: u32| {
        uf2_block(&Uf2Block {
            flags: 0,
            target_address: address,
            payload,
            block_no,
            num_blocks: 2,
            word28: 0,
            trailer: &[],
        })
    };
    // 64 MiB between the two blocks.
    let file = [block(0, low, 0), block(0x0400_0000, high, 1)].concat();
    let p = classify(&file);
    assert_eq!(
        metadata_text(&p, "uf2_section_0"),
        "file 0x20; destination 0x0; 256 B"
    );
    assert_eq!(
        metadata_text(&p, "uf2_section_1"),
        "file 0x220; destination 0x4000000; 256 B"
    );
}

#[test]
fn uf2_duplicate_overlapping_and_missing_blocks_are_errors() {
    let code = thumb();
    let block = |address: u32, block_no: u32, num_blocks: u32| {
        uf2_block(&Uf2Block {
            flags: 0,
            target_address: address,
            payload: &code[..256],
            block_no,
            num_blocks,
            word28: 0,
            trailer: &[],
        })
    };
    let message = |file: &[u8]| {
        mcu::parse_container(file, Layout::Uf2)
            .expect_err("rejected")
            .to_string()
    };
    let duplicate = [block(0x100, 0, 2), block(0x100, 1, 2)].concat();
    assert!(message(&duplicate).contains("Duplicate UF2 blocks at 0x0 and 0x200"));
    let overlapping = [block(0x100, 0, 2), block(0x180, 1, 2)].concat();
    assert!(message(&overlapping).contains("Overlapping UF2 blocks"));
    let missing = [block(0, 0, 3), block(0x100, 1, 3)].concat();
    assert!(message(&missing).contains("Missing UF2 blocks: the run at 0x0 has 2 of 3 blocks"));
    let misnumbered = [block(0, 0, 2), block(0x100, 0, 2)].concat();
    assert!(message(&misnumbered).contains("Missing UF2 blocks"));
    // A strong magic makes a damaged file a format error, not raw code.
    let mut broken = uf2_image(&code, 0, None);
    broken[508] ^= 0xff;
    let error = detect_payload(&broken, &ClassifierOptions::new()).unwrap_err();
    assert!(error.to_string().contains("Invalid UF2 magicEnd at 0x1FC"));
    assert!(message(&broken[..700]).contains("Truncated UF2 block at 0x200: 188 of 512 B"));
}

#[test]
fn uf2_payload_size_respects_the_md5_record() {
    let code = thumb();
    let block = |flags: u32, size: usize| {
        uf2_block(&Uf2Block {
            flags,
            target_address: 0,
            payload: &code[..size],
            block_no: 0,
            num_blocks: 1,
            word28: 0,
            trailer: &[],
        })
    };
    assert!(mcu::parse_container(&block(0, 476), Layout::Uf2).is_ok());
    assert!(mcu::parse_container(&block(UF2_FLAG_MD5_PRESENT, 452), Layout::Uf2).is_ok());
    assert!(mcu::parse_container(&block(UF2_FLAG_MD5_PRESENT, 456), Layout::Uf2).is_err());
    let p = classify(&block(UF2_FLAG_MD5_PRESENT, 452));
    assert!(has_note(&p, "MD5 records in 1 block; not verified"));
}

#[test]
fn uf2_side_blocks_and_contained_files_are_not_flash() {
    let elf = elf_x86_64();
    let name = b"app.elf\0";
    let file_block = |payload: &[u8], offset: u32, block_no: u32| {
        uf2_block(&Uf2Block {
            flags: UF2_FLAG_FILE_CONTAINER,
            target_address: offset,
            payload,
            block_no,
            num_blocks: 3,
            word28: elf.len() as u32,
            trailer: name,
        })
    };
    let comment = uf2_block(&Uf2Block {
        flags: UF2_FLAG_NOT_MAIN_FLASH,
        target_address: 0,
        payload: b"source code comments",
        block_no: 2,
        num_blocks: 3,
        word28: 0,
        trailer: &[],
    });
    let file = [
        file_block(&elf[..32], 0, 0),
        file_block(&elf[32..], 32, 1),
        comment,
    ]
    .concat();
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Uf2);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].label.as_deref(), Some("app.elf"));
    assert_eq!(
        p.slices[0].decoded.as_ref().map(|d| d.transform.as_str()),
        Some("UF2 file container")
    );
    assert_eq!(metadata_text(&p, "uf2_file_0"), "app.elf; 64 B; 2 blocks");
    assert!(has_note(&p, "1 block flagged not main flash"));
    assert!(has_note(&p, "No main-flash payload"));
}

#[test]
fn uf2_rp2xxx_data_downloads_are_opaque() {
    let p = classify(&uf2_image(&thumb(), 0x1000_0000, Some(RP2XXX_DATA)));
    assert_eq!(p.format.format, FileFormat::Uf2);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert!(has_note(&p, "marks a data download; not analyzed"));
}

#[test]
fn uf2_rp2350_e10_workaround_block_is_not_part_of_the_image() {
    let filler = [0xef; UF2_PAYLOAD];
    // picotool --abs-block: one RP2XXX_ABSOLUTE block at the end of flash,
    // numbered 0 of 2; picotool 2.1.0 and later also tag it to be ignored.
    let workaround = |flags: u32, trailer: &[u8]| {
        uf2_block(&Uf2Block {
            flags: UF2_FLAG_FAMILY_ID_PRESENT | flags,
            target_address: 0x10ff_ff00,
            payload: &filler,
            block_no: 0,
            num_blocks: 2,
            word28: RP2XXX_ABSOLUTE,
            trailer,
        })
    };
    let image = uf2_image(&thumb(), 0x1000_0000, Some(RP2350_ARM_S));
    let untagged = [workaround(0, &[]), image.clone()].concat();
    let p = classify(&untagged);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(p.slices.is_empty());
    assert!(has_note(&p, "Block at 0x0 is the RP2350-E10 workaround"));
    let tag = RP2_IGNORE_BLOCK_TAG.to_le_bytes();
    let tagged = [workaround(UF2_FLAG_EXTENSION_FLAGS_PRESENT, &tag), image].concat();
    let p = classify(&tagged);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(has_note(
        &p,
        "1 block tagged UF2_EXTENSION_RP2_IGNORE_BLOCK"
    ));
}

#[test]
fn uf2_extension_tags_become_metadata() {
    // README example tags: firmware version "0.1.2" (size 9, padded to
    // 12), device description "ACME Toaster mk3" (size 20), terminator.
    let mut tags = vec![0x09, 0xbc, 0xc7, 0x9f];
    tags.extend_from_slice(b"0.1.2\0\0\0");
    tags.extend_from_slice(&[0x14, 0x9d, 0x0d, 0x65]);
    tags.extend_from_slice(b"ACME Toaster mk3");
    tags.extend_from_slice(&[0; 4]);
    let code = thumb();
    let file = uf2_block(&Uf2Block {
        flags: UF2_FLAG_EXTENSION_FLAGS_PRESENT,
        target_address: 0,
        payload: &code[..256],
        block_no: 0,
        num_blocks: 1,
        word28: 0,
        trailer: &tags,
    });
    let p = classify(&file);
    assert_eq!(metadata_text(&p, "uf2_firmware_version"), "0.1.2");
    assert_eq!(
        metadata_text(&p, "uf2_device_description"),
        "ACME Toaster mk3"
    );
}

#[test]
fn uf2_truncations_never_claim_the_payload() {
    let file = uf2_image(&thumb()[..600], 0x1000_0000, Some(RP2350_ARM_S));
    for end in 0..file.len() {
        let claimed = detect_payload(&file[..end], &ClassifierOptions::new())
            .is_ok_and(|p| p.format.format == FileFormat::Uf2);
        assert!(!claimed, "prefix {end}");
    }
}

#[test]
fn uf2_survives_mutation() {
    let code = thumb();
    let mut tags = vec![0x09, 0xbc, 0xc7, 0x9f];
    tags.extend_from_slice(b"0.1.2\0\0\0");
    let tagged = uf2_block(&Uf2Block {
        flags: UF2_FLAG_FAMILY_ID_PRESENT | UF2_FLAG_EXTENSION_FLAGS_PRESENT,
        target_address: 0x1000_0000,
        payload: &code[..64],
        block_no: 0,
        num_blocks: 1,
        word28: RP2350_ARM_S,
        trailer: &tags,
    });
    let file_block = uf2_block(&Uf2Block {
        flags: UF2_FLAG_FILE_CONTAINER,
        target_address: 0,
        payload: &code[..64],
        block_no: 0,
        num_blocks: 1,
        word28: 64,
        trailer: b"x.bin\0",
    });
    let file = [tagged, file_block].concat();
    assert_eq!(classify(&file).primary.isa, Isa::Arm);
    sweep(&file, Layout::Uf2);
}

// STM32 DfuSe (dfu-util v0.11, pydfu.py v1.24.0, DFU 1.1 Appendix B).

const BCD_DFU_DFUSE: u16 = 0x011a;

/// One DfuSe target image.
struct DfuTarget<'a> {
    alternate: u8,
    /// Target name; empty for an unnamed target.
    name: &'a str,
    /// Element address and data.
    elements: Vec<(u32, &'a [u8])>,
}

/// DfuSe prefix, target prefixes with their elements, and the 16-byte DFU
/// suffix whose CRC is the un-inverted CRC-32 register.
fn dfuse(targets: &[DfuTarget<'_>]) -> Vec<u8> {
    let mut images = Vec::new();
    for target in targets {
        let mut elements = Vec::new();
        for (address, data) in &target.elements {
            elements.extend_from_slice(&address.to_le_bytes()); // dwElementAddress
            elements.extend_from_slice(&(data.len() as u32).to_le_bytes()); // dwElementSize
            elements.extend_from_slice(data);
        }
        images.extend_from_slice(b"Target"); // szSignature
        images.push(target.alternate); // bAlternateSetting
        images.extend_from_slice(&u32::from(!target.name.is_empty()).to_le_bytes()); // bTargetNamed
        let mut name = [0u8; 255];
        name[..target.name.len()].copy_from_slice(target.name.as_bytes());
        images.extend_from_slice(&name); // szTargetName
        images.extend_from_slice(&(elements.len() as u32).to_le_bytes()); // dwTargetSize
        images.extend_from_slice(&(target.elements.len() as u32).to_le_bytes()); // dwNbElements
        images.extend_from_slice(&elements);
    }
    let mut file = b"DfuSe".to_vec(); // szSignature
    file.push(1); // bVersion
    file.extend_from_slice(&((images.len() + 11) as u32).to_le_bytes()); // DFUImageSize
    file.push(targets.len() as u8); // bTargets
    file.extend_from_slice(&images);
    dfu_suffix(&mut file, BCD_DFU_DFUSE);
    file
}

/// Append the DFU suffix: bcdDevice, idProduct, idVendor (ST's DFU
/// bootloader 0483:DF11), bcdDFU, "UFD", bLength 16, dwCRC.
fn dfu_suffix(file: &mut Vec<u8>, bcd_dfu: u16) {
    file.extend_from_slice(&0x0200u16.to_le_bytes()); // bcdDevice
    file.extend_from_slice(&0xdf11u16.to_le_bytes()); // idProduct
    file.extend_from_slice(&0x0483u16.to_le_bytes()); // idVendor
    file.extend_from_slice(&bcd_dfu.to_le_bytes()); // bcdDFU
    file.extend_from_slice(b"UFD"); // ucDfuSignature
    file.push(16); // bLength
    let crc = crc32_update(!0, file); // dwCRC: no final inversion
    file.extend_from_slice(&crc.to_le_bytes());
}

#[test]
fn dfuse_elements_become_sections_and_the_suffix_crc_is_verified() {
    let code = thumb();
    let (first, second) = code.split_at(4096);
    let file = dfuse(&[DfuTarget {
        alternate: 0,
        name: "Internal Flash",
        elements: vec![(0x0800_0000, first), (0x0800_2000, second)],
    }]);
    assert_eq!(mcu_layout(&file), Some(Layout::Dfuse));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Dfuse);
    assert_eq!(p.format.variant_name.as_deref(), Some("DfuSe 1.1a file"));
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(
        &p,
        "DfuSe: 1 target, 2 elements; DFU suffix CRC-32 verified"
    ));
    assert_eq!(metadata_text(&p, "dfuse_vendor_id"), "0x0483");
    assert_eq!(metadata_text(&p, "dfuse_product_id"), "0xDF11");
    assert_eq!(
        metadata_text(&p, "dfuse_target_0"),
        format!(
            "alternate setting 0; named \"Internal Flash\"; 2 elements; {} B",
            code.len() + 16
        )
    );
    // Prefix 11 B, target prefix 274 B, element header 8 B.
    assert_eq!(
        metadata_text(&p, "dfuse_section_0"),
        "file 0x125; destination 0x8000000; 4096 B"
    );
    assert_eq!(
        metadata_text(&p, "dfuse_section_1"),
        format!("file 0x112D; destination 0x8002000; {} B", second.len())
    );
}

#[test]
fn dfuse_suffix_and_target_defects_are_errors() {
    let code = thumb();
    let good = dfuse(&[DfuTarget {
        alternate: 0,
        name: "",
        elements: vec![(0x0800_0000, &code[..64])],
    }]);
    let message = |file: &[u8]| {
        mcu::parse_container(file, Layout::Dfuse)
            .expect_err("rejected")
            .to_string()
    };
    let mut bad_crc = good.clone();
    let crc_at = bad_crc.len() - 4;
    bad_crc[crc_at] ^= 1;
    assert!(message(&bad_crc).contains("Invalid DFU suffix CRC-32"));
    let mut plain_dfu = good[..good.len() - 16].to_vec();
    dfu_suffix(&mut plain_dfu, 0x0100);
    assert!(message(&plain_dfu).contains("Unsupported DFU suffix bcdDFU 0x0100"));
    let mut no_signature = good[..good.len() - 16].to_vec();
    no_signature.extend_from_slice(&[0; 16]);
    assert!(message(&no_signature).contains("Missing DFU suffix signature"));
    // An element larger than its target, with a valid CRC.
    let mut oversized = good[..good.len() - 16].to_vec();
    let size_at = 11 + 274 + 4;
    put_u32(&mut oversized, size_at, 65);
    dfu_suffix(&mut oversized, BCD_DFU_DFUSE);
    assert!(message(&oversized).contains("Truncated DfuSe element 0 of target 0"));
    // A strong signature makes the damaged file a format error.
    assert!(detect_payload(&bad_crc, &ClassifierOptions::new()).is_err());
}

#[test]
fn dfuse_truncations_are_errors_and_mutations_do_not_panic() {
    let code = thumb();
    let file = dfuse(&[
        DfuTarget {
            alternate: 0,
            name: "Internal Flash",
            elements: vec![(0x0800_0000, &code[..32]), (0x0800_0400, &code[32..48])],
        },
        DfuTarget {
            alternate: 1,
            name: "",
            elements: vec![(0x1fff_c000, &[0xaa; 16])],
        },
    ]);
    assert_eq!(classify(&file).format.format, FileFormat::Dfuse);
    for end in 0..file.len() {
        assert!(
            mcu::parse_container(&file[..end], Layout::Dfuse).is_err(),
            "prefix {end}"
        );
    }
    sweep(&file, Layout::Dfuse);
}

// Silicon Labs GBL v3 (gecko_sdk v4.5.1 btl_gbl_format.h): little-endian
// tagId and length, then the payload.

const GBL_TAG_HEADER: u32 = 0x03a6_17eb;
const GBL_TAG_APPLICATION: u32 = 0xf40a_0af4;
const GBL_TAG_BOOTLOADER: u32 = 0xf509_09f5;
const GBL_TAG_PROGRAM: u32 = 0xfe01_01fe;
const GBL_TAG_PROGRAM_LZ4: u32 = 0xfd05_05fd;
const GBL_TAG_PROGRAM_LZMA: u32 = 0xfd07_07fd;
const GBL_TAG_ENCRYPTION_INIT: u32 = 0xfa06_06fa;
const GBL_TAG_ENCRYPTED_DATA: u32 = 0xf907_07f9;
const GBL_TAG_SIGNATURE: u32 = 0xf70a_0af7;
const GBL_TAG_END: u32 = 0xfc04_04fc;
const GBL_TYPE_ENCRYPTION_AESCCM: u32 = 0x0000_0001;
const GBL_TYPE_SIGNATURE_ECDSA: u32 = 0x0000_0100;

/// One tag: `tagId`, `length`, payload.
fn gbl_tag(id: u32, payload: &[u8]) -> Vec<u8> {
    let mut tag = id.to_le_bytes().to_vec();
    tag.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    tag.extend_from_slice(payload);
    tag
}

/// Header tag (`version` 0x03000000, `type`), the given tags, and the end
/// tag whose `gblCrc` is the zlib CRC-32 of every byte before it.
fn gbl(gbl_type: u32, tags: &[Vec<u8>]) -> Vec<u8> {
    let mut header = 0x0300_0000u32.to_le_bytes().to_vec(); // version
    header.extend_from_slice(&gbl_type.to_le_bytes()); // type
    let mut file = gbl_tag(GBL_TAG_HEADER, &header);
    for tag in tags {
        file.extend_from_slice(tag);
    }
    file.extend_from_slice(&GBL_TAG_END.to_le_bytes());
    file.extend_from_slice(&4u32.to_le_bytes());
    let crc = crc32(&file);
    file.extend_from_slice(&crc.to_le_bytes()); // gblCrc
    file
}

/// `ApplicationData_t`: type (MCU), version, capabilities, product ID.
fn gbl_application() -> Vec<u8> {
    let mut data = 0x10u32.to_le_bytes().to_vec(); // type: APPLICATION_TYPE_MCU
    data.extend_from_slice(&0x0001_0002u32.to_le_bytes()); // version
    data.extend_from_slice(&0u32.to_le_bytes()); // capabilities
    data.extend_from_slice(&[0x5a; 16]); // productId
    gbl_tag(GBL_TAG_APPLICATION, &data)
}

/// A program tag: `flashStartAddress`, then the data.
fn gbl_program(id: u32, address: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = address.to_le_bytes().to_vec();
    payload.extend_from_slice(data);
    gbl_tag(id, &payload)
}

#[test]
fn gbl_program_tags_become_sections_and_the_end_crc_is_verified() {
    let code = thumb();
    let file = gbl(
        0,
        &[
            gbl_application(),
            gbl_program(GBL_TAG_PROGRAM, 0x0000_4000, &code),
        ],
    );
    assert_eq!(mcu_layout(&file), Some(Layout::Gbl));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Gbl);
    assert_eq!(p.format.variant_name.as_deref(), Some("GBL v3 file"));
    // GBL names no ISA: the program data goes to the code model.
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(
        &p,
        "GBL v3: 1 program section; end-tag CRC-32 verified"
    ));
    assert_eq!(
        metadata_text(&p, "gbl_application_type"),
        "0x00000010 (MCU)"
    );
    // Header tag 16 B, application tag 36 B, program tag header 8 B and
    // address 4 B.
    assert_eq!(
        metadata_text(&p, "gbl_section_0"),
        format!("file 0x40; destination 0x4000; {} B", code.len())
    );
}

#[test]
fn gbl_lz4_and_lzma_program_tags_are_decoded() {
    let code = thumb();
    let lz4 = lz4_flex::block::compress(&code);
    let lzma = fixture("thumbv7em.text.bin.lzma");
    let file = gbl(
        0,
        &[
            gbl_application(),
            gbl_program(GBL_TAG_PROGRAM_LZ4, 0x0000_4000, &lz4),
            gbl_program(GBL_TAG_PROGRAM_LZMA, 0x0002_0000, &lzma),
        ],
    );
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::Arm);
    let lz4_at = 16 + 36 + 12;
    assert_eq!(
        metadata_text(&p, "gbl_section_0"),
        format!(
            "file 0x{lz4_at:X}; destination 0x4000; {} B stored; {} B decoded (LZ4 block)",
            lz4.len(),
            code.len()
        )
    );
    assert_eq!(
        metadata_text(&p, "gbl_section_1"),
        format!(
            "file 0x{:X}; destination 0x20000; {} B stored; {} B decoded (LZMA)",
            lz4_at + lz4.len() + 12,
            lzma.len(),
            code.len()
        )
    );
}

#[test]
fn gbl_undecodable_compressed_data_is_listed_as_opaque() {
    let file = gbl(
        0,
        &[gbl_program(GBL_TAG_PROGRAM_LZ4, 0, &[0x00, 0x05, 0x00])],
    );
    let p = classify(&file);
    assert!(has_note(&p, "GBL program LZ4 tag at 0x10 does not decode"));
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].label.as_deref(), Some("Undecoded program LZ4"));
}

#[test]
fn gbl_bootloader_tags_are_separate_children() {
    let mut bootloader = 0x0002_0000u32.to_le_bytes().to_vec(); // bootloaderVersion
    bootloader.extend_from_slice(&0x0800_0000u32.to_le_bytes()); // address
    bootloader.extend_from_slice(&elf_x86_64());
    let file = gbl(
        0,
        &[gbl_application(), gbl_tag(GBL_TAG_BOOTLOADER, &bootloader)],
    );
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(has_note(&p, "Primary ISA selected from Bootloader"));
    let child = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("Bootloader"))
        .expect("bootloader child");
    assert_eq!(child.isa, Isa::X86_64);
    assert_eq!(child.offset, (16 + 36 + 16) as u64);
}

#[test]
fn gbl_encrypted_files_are_opaque_and_signatures_are_not_verified() {
    let mut init = 64u32.to_le_bytes().to_vec(); // msgLen
    init.extend_from_slice(&[0x11; 12]); // nonce
    let file = gbl(
        GBL_TYPE_ENCRYPTION_AESCCM | GBL_TYPE_SIGNATURE_ECDSA,
        &[
            gbl_tag(GBL_TAG_ENCRYPTION_INIT, &init),
            gbl_tag(GBL_TAG_ENCRYPTED_DATA, &thumb()[..64]),
            gbl_tag(GBL_TAG_SIGNATURE, &[0x22; 64]),
        ],
    );
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Gbl);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert!(has_note(
        &p,
        "Encrypted GBL (AES-CCM): 1 encrypted data tag"
    ));
    assert!(has_note(&p, "ECDSA P-256 signature present; not verified"));
    // A plaintext program tag cannot appear in an encrypted file.
    let plaintext = gbl(
        GBL_TYPE_ENCRYPTION_AESCCM,
        &[gbl_program(GBL_TAG_PROGRAM, 0, &[1, 2, 3, 4])],
    );
    let error = mcu::parse_container(&plaintext, Layout::Gbl).unwrap_err();
    assert!(error.to_string().contains("plaintext in an encrypted file"));
}

#[test]
fn gbl_crc_order_and_unknown_tags_are_checked() {
    let program = gbl_program(GBL_TAG_PROGRAM, 0, &thumb()[..64]);
    let message = |file: &[u8]| {
        mcu::parse_container(file, Layout::Gbl)
            .expect_err("rejected")
            .to_string()
    };
    let mut bad_crc = gbl(0, &[program.clone()]);
    let last = bad_crc.len() - 1;
    bad_crc[last] ^= 0x80;
    assert!(message(&bad_crc).contains("Invalid GBL end tag CRC-32"));
    let out_of_order = gbl(0, &[program.clone(), gbl_application()]);
    assert!(message(&out_of_order).contains("Invalid GBL tag order: application info tag"));
    let unknown = gbl(0, &[gbl_tag(0x1234_5678, &[0; 4])]);
    assert!(message(&unknown).contains("Unknown GBL tag 0x12345678 at 0x10"));
    let mut trailing = gbl(0, &[program]);
    trailing.extend_from_slice(b"junk");
    assert!(message(&trailing).contains("Unexpected 4 B after the GBL end tag"));
    assert!(detect_payload(&bad_crc, &ClassifierOptions::new()).is_err());
}

#[test]
fn gbl_truncations_are_errors_and_mutations_do_not_panic() {
    let code = thumb();
    let file = gbl(
        GBL_TYPE_SIGNATURE_ECDSA,
        &[
            gbl_application(),
            gbl_program(GBL_TAG_PROGRAM, 0x4000, &code[..48]),
            gbl_program(
                GBL_TAG_PROGRAM_LZ4,
                0x8000,
                &lz4_flex::block::compress(&code[..64]),
            ),
            gbl_tag(GBL_TAG_SIGNATURE, &[0x22; 64]),
        ],
    );
    assert_eq!(classify(&file).format.format, FileFormat::Gbl);
    for end in 0..file.len() {
        assert!(
            mcu::parse_container(&file[..end], Layout::Gbl).is_err(),
            "prefix {end}"
        );
    }
    sweep(&file, Layout::Gbl);
}

// Cypress .cyacd (cybtldr_parse.c, cyflash cyacd.py) and Infineon .cyacd2
// (AN213924 rev *H).

/// `.cyacd` text: header (silicon ID BE, revision, checksum type) and
/// rows `:` array ID, row number (BE), data length (BE), data, checksum
/// (two's complement of the byte sum), CRLF line endings.
fn cyacd(silicon_id: u32, checksum_type: u8, rows: &[(u8, u16, &[u8])]) -> Vec<u8> {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let mut text = hex(&silicon_id.to_be_bytes());
    text.push_str(&hex(&[0x11, checksum_type])); // silicon revision, checksum type
    text.push_str("\r\n");
    for (array, row, data) in rows {
        let mut record = vec![*array];
        record.extend_from_slice(&row.to_be_bytes());
        record.extend_from_slice(&(data.len() as u16).to_be_bytes());
        record.extend_from_slice(data);
        let sum = record.iter().fold(0u8, |sum, b| sum.wrapping_add(*b));
        record.push(sum.wrapping_neg());
        text.push(':');
        text.push_str(&hex(&record));
        text.push_str("\r\n");
    }
    text.into_bytes()
}

/// `.cyacd2` text: header (file version 1, silicon ID LE, revision,
/// checksum type, app ID, product ID LE), metadata lines, then rows `:`
/// byte address (LE) and data, CRLF line endings.
fn cyacd2(metadata_lines: &[&str], rows: &[(u32, &[u8])]) -> Vec<u8> {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let mut header = vec![1]; // file version
    header.extend_from_slice(&0x1a00_0100u32.to_le_bytes()); // silicon ID
    header.push(0x21); // silicon revision
    header.push(1); // checksum type: CRC
    header.push(1); // app ID
    header.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // product ID
    let mut text = hex(&header);
    text.push_str("\r\n");
    for line in metadata_lines {
        text.push_str(line);
        text.push_str("\r\n");
    }
    for (address, data) in rows {
        text.push(':');
        text.push_str(&hex(&address.to_le_bytes()));
        text.push_str(&hex(data));
        text.push_str("\r\n");
    }
    text.into_bytes()
}

#[test]
fn cyacd_rows_merge_into_sections_and_every_checksum_is_checked() {
    let code = thumb();
    let rows: Vec<(u8, u16, &[u8])> = code
        .chunks(128)
        .enumerate()
        .map(|(i, chunk)| (0, 0x40 + i as u16, chunk))
        .collect();
    let file = cyacd(0x0490_1193, 0, &rows);
    assert_eq!(mcu_layout(&file), Some(Layout::Cyacd));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Cyacd);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some(".cyacd bootloadable")
    );
    assert!(p.format.confidence < 1.0);
    // The silicon ID names a device, not an ISA: the code model decides.
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(metadata_text(&p, "cyacd_silicon_id"), "0x04901193");
    assert_eq!(metadata_text(&p, "cyacd_packet_checksum"), "16-bit sum");
    // The last row is shorter, so it does not continue the run.
    let full_rows = code.len() / 128;
    assert_eq!(
        metadata(&p, "cyacd_section_0").map(ToString::to_string),
        Some(format!(
            "file 0xE; destination 0x40; {} B stored; {} B decoded (ASCII hex)",
            // Each row is ':' and 134 B as hex, then CR LF; the section
            // ends before the last row's line ending.
            full_rows * (1 + 2 * 134 + 2) - 2,
            full_rows * 128
        ))
    );
    assert!(has_note(&p, "every row checksum verified"));
    // One bad checksum and the text is no longer recognized.
    let mut corrupt = file.clone();
    let checksum_at = 14 + 1 + 2 * 133;
    corrupt[checksum_at] = if corrupt[checksum_at] == b'0' {
        b'1'
    } else {
        b'0'
    };
    assert_eq!(mcu_layout(&corrupt), None);
    let error = mcu::parse_container(&corrupt, Layout::Cyacd).unwrap_err();
    assert!(error.to_string().contains("Invalid cyacd row checksum"));
}

#[test]
fn cyacd_checksum_type_selects_the_packet_checksum_not_the_row_checksum() {
    let file = cyacd(0x0490_1193, 1, &[(0, 1, &[0xaa, 0x55])]);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Cyacd);
    assert_eq!(metadata_text(&p, "cyacd_packet_checksum"), "CRC-16");
    assert_eq!(mcu_layout(&cyacd(0x0490_1193, 2, &[(0, 1, &[0xaa])])), None);
}

#[test]
fn cyacd2_rows_use_byte_addresses_and_carry_appinfo() {
    let code = riscv32();
    let rows: Vec<(u32, &[u8])> = code
        .chunks(512)
        .enumerate()
        .map(|(i, chunk)| (0x1000_0000 + (i * 512) as u32, chunk))
        .collect();
    let file = cyacd2(&["@APPINFO:0x10000000,0x2000"], &rows);
    assert_eq!(mcu_layout(&file), Some(Layout::Cyacd2));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Cyacd);
    assert_eq!(p.format.variant_name.as_deref(), Some(".cyacd2 DFU image"));
    assert_eq!(p.primary.isa, Isa::RiscV32);
    assert_eq!(metadata_text(&p, "cyacd_app_verify_start"), "0x10000000");
    assert_eq!(metadata_text(&p, "cyacd_app_verify_length"), "0x2000");
    assert_eq!(metadata_text(&p, "cyacd_product_id"), "0x01020304");
    assert_eq!(metadata_text(&p, "cyacd_silicon_id"), "0x1A000100");
    assert!(metadata_text(&p, "cyacd_section_0").contains("destination 0x10000000"));
    assert!(metadata(&p, "cyacd_section_1").is_none());
    let overlapping = cyacd2(&[], &[(0x100, &[1; 8]), (0x104, &[2; 8])]);
    assert_eq!(mcu_layout(&overlapping), None);
}

#[test]
fn cyacd2_eiv_rows_make_the_rows_opaque() {
    let code = riscv32();
    let file = cyacd2(
        &[
            "@APPINFO:0x10000000,0x200",
            "@EIV:00112233445566778899AABBCCDDEEFF",
        ],
        &[(0x1000_0000, &code[..512])],
    );
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Cyacd);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert!(has_note(&p, "data rows are treated as encrypted"));
}

#[test]
fn cyacd_truncation_is_only_accepted_at_row_boundaries() {
    let code = thumb();
    let file = cyacd(
        0x0490_1193,
        0,
        &[(0, 1, &code[..16]), (0, 2, &code[16..32])],
    );
    for end in 0..file.len() {
        if mcu_layout(&file[..end]).is_some() {
            // .cyacd has no row count or end record, so dropping whole
            // rows is undetectable; a cut inside a row never parses.
            let at_line_end =
                file[..end].ends_with(b"\n") || matches!(file.get(end), None | Some(b'\r' | b'\n'));
            assert!(at_line_end, "prefix {end}");
        }
    }
    sweep(&file, Layout::Cyacd);
    let rows = cyacd2(&["@APPINFO:0x0,0x20", "@EIV:"], &[(0, &code[..16])]);
    assert_eq!(mcu_layout(&rows), Some(Layout::Cyacd2));
    sweep(&rows, Layout::Cyacd2);
}
