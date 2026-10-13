//! MCU update wrappers: USB DFU suffix files around any firmware, Silicon
//! Labs EBL tag streams (plain and encrypted, AAT platform field) and Nordic
//! nRF5 DFU init packets, with CRCs, tag order, field rules, truncation and
//! mutation sweeps. DFU and EBL files are built here from the documented
//! wire layouts around the compiled code in `tests/fixtures/mcu`; the init
//! packets there were encoded by protoc (see its README).

use sha2::{Digest, Sha256};
use zrax::formats::checksum::{crc32, crc32_update};
use zrax::formats::container::Kind;
use zrax::formats::mcu::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa, MetadataKey, MetadataValue,
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
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
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

fn entry_point(payload: &DetectionPayload) -> Option<u64> {
    payload
        .metadata
        .iter()
        .find_map(|m| match (&m.key, &m.value) {
            (MetadataKey::EntryPoint, MetadataValue::Address(address)) => Some(*address),
            _ => None,
        })
}

fn mcu_layout(data: &[u8]) -> Option<Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: Kind::Mcu(layout),
        } => Some(layout),
        _ => None,
    }
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    mcu::parse_container(data, layout)
        .expect_err("rejected")
        .to_string()
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

// USB DFU 1.1 Appendix B: a suffix of little-endian fields after the
// firmware, ending in the CRC-32 register over every byte before it.

const BCD_DFU_1_0: u16 = 0x0100;
const BCD_DFU_DFUSE: u16 = 0x011a;

/// The suffix fields that vary between tests.
struct DfuSuffix<'a> {
    vendor: u16,
    product: u16,
    bcd_dfu: u16,
    /// Vendor fields stored before the standard 16 bytes (counted in
    /// `bLength`).
    vendor_fields: &'a [u8],
}

const PID_CODES_TEST: DfuSuffix<'static> = DfuSuffix {
    vendor: 0x1209,
    product: 0x0001,
    bcd_dfu: BCD_DFU_1_0,
    vendor_fields: &[],
};

/// `firmware`, any vendor fields, then bcdDevice (0x0102), idProduct,
/// idVendor, bcdDFU, "UFD", bLength and dwCRC (no final inversion).
fn dfu_file(firmware: &[u8], suffix: &DfuSuffix<'_>) -> Vec<u8> {
    let mut file = firmware.to_vec();
    file.extend_from_slice(suffix.vendor_fields);
    file.extend_from_slice(&0x0102u16.to_le_bytes()); // bcdDevice
    file.extend_from_slice(&suffix.product.to_le_bytes()); // idProduct
    file.extend_from_slice(&suffix.vendor.to_le_bytes()); // idVendor
    file.extend_from_slice(&suffix.bcd_dfu.to_le_bytes()); // bcdDFU
    file.extend_from_slice(b"UFD"); // ucDfuSignature
    file.push((16 + suffix.vendor_fields.len()) as u8); // bLength
    let crc = crc32_update(!0, &file);
    file.extend_from_slice(&crc.to_le_bytes()); // dwCRC
    file
}

/// A GBL v3 file (gecko_sdk v4.5.1 `btl_gbl_format.h`): header tag
/// (`version` 0x03000000, `type` 0), one program data tag at 0x4000 and the
/// end tag whose `gblCrc` is the zlib CRC-32 of every byte before it; every
/// field little-endian.
fn gbl(code: &[u8]) -> Vec<u8> {
    let mut file = 0x03a6_17ebu32.to_le_bytes().to_vec(); // header tagId
    file.extend_from_slice(&8u32.to_le_bytes()); // length
    file.extend_from_slice(&0x0300_0000u32.to_le_bytes()); // version
    file.extend_from_slice(&0u32.to_le_bytes()); // type
    file.extend_from_slice(&0xfe01_01feu32.to_le_bytes()); // program data tagId
    file.extend_from_slice(&((code.len() + 4) as u32).to_le_bytes()); // length
    file.extend_from_slice(&0x4000u32.to_le_bytes()); // flashStartAddress
    file.extend_from_slice(code);
    file.extend_from_slice(&0xfc04_04fcu32.to_le_bytes()); // end tagId
    file.extend_from_slice(&4u32.to_le_bytes()); // length
    let crc = crc32(&file);
    file.extend_from_slice(&crc.to_le_bytes()); // gblCrc
    file
}

/// Recompute dwCRC after a test edits a suffix field.
fn fix_dfu_crc(file: &mut [u8]) {
    let crc_at = file.len() - 4;
    let crc = crc32_update(!0, &file[..crc_at]);
    file[crc_at..].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn dfu_suffix_firmware_is_one_child_classified_by_the_code_model() {
    let code = thumb();
    let file = dfu_file(&code, &PID_CODES_TEST);
    assert_eq!(mcu_layout(&file), Some(Layout::DfuSuffix));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::DfuSuffix);
    assert_eq!(p.format.variant_name.as_deref(), Some("DFU 1.1 file"));
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(
        &p,
        "DFU suffix: bcdDFU 0x0100; CRC-32 verified; 5484 B of firmware before the 16 B suffix"
    ));
    assert!(has_note(
        &p,
        "USB vendor 0x1209, product 0x0001 name the device, not an ISA"
    ));
    assert!(has_note(&p, "Primary ISA selected from DFU firmware"));
    assert_eq!(metadata_text(&p, "dfu_vendor_id"), "0x1209");
    assert_eq!(metadata_text(&p, "dfu_product_id"), "0x0001");
    assert_eq!(metadata_text(&p, "dfu_device_version"), "0x0102");
    assert_eq!(metadata_text(&p, "dfu_suffix_length"), "16");
    assert_eq!(
        metadata_text(&p, "dfu_component_0"),
        format!("file 0x0; {} B", code.len())
    );
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].label.as_deref(), Some("DFU firmware"));
    assert_eq!(
        (p.slices[0].offset, p.slices[0].size),
        (0, code.len() as u64)
    );
    assert_eq!(p.slices[0].isa, Isa::Arm);
}

#[test]
fn dfu_suffix_firmware_with_a_header_reports_its_own_format() {
    // The suffix is checked before the MCU magics at offset 0, so a GBL file
    // inside keeps its suffix and is classified on its own.
    let code = thumb();
    let file = dfu_file(&gbl(&code), &PID_CODES_TEST);
    assert_eq!(mcu_layout(&file), Some(Layout::DfuSuffix));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::DfuSuffix);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(has_note(
        &p,
        "DFU firmware: arm (contained Silicon Labs GBL)"
    ));
    // Executable formats are detected before the MCU block: an ELF with a
    // suffix stays an ELF.
    let p = classify(&dfu_file(&elf_x86_64(), &PID_CODES_TEST));
    assert_eq!(p.format.format, FileFormat::Elf);
    assert_eq!(p.primary.isa, Isa::X86_64);
    // DfuSe files carry the same suffix but keep their own layout.
    let mut dfuse_like = b"DfuSe\x01".to_vec();
    dfuse_like.extend_from_slice(&[0; 10]);
    let file = dfu_file(
        &dfuse_like,
        &DfuSuffix {
            bcd_dfu: BCD_DFU_DFUSE,
            ..PID_CODES_TEST
        },
    );
    assert_eq!(mcu_layout(&file), Some(Layout::Dfuse));
}

#[test]
fn dfu_suffix_vendor_fields_and_wildcard_ids() {
    let code = thumb();
    let file = dfu_file(
        &code[..256],
        &DfuSuffix {
            vendor: 0xffff,
            product: 0xffff,
            bcd_dfu: BCD_DFU_1_0,
            vendor_fields: &[0xa5; 4],
        },
    );
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::DfuSuffix);
    // bLength 20: the firmware ends before the vendor fields.
    assert_eq!(p.slices[0].size, 256);
    assert_eq!(metadata_text(&p, "dfu_suffix_length"), "20");
    assert!(has_note(
        &p,
        "bLength 20 B: 4 B of vendor suffix fields before the standard 16 B; not interpreted"
    ));
    assert!(has_note(
        &p,
        "USB vendor 0xFFFF: the file may be sent to any device; the suffix names no ISA"
    ));
}

#[test]
fn dfu_suffix_crc_length_and_version_defects() {
    let code = thumb();
    let good = dfu_file(&code[..128], &PID_CODES_TEST);
    // A wrong CRC means there is no suffix: not recognized, and the parser
    // names the CRC.
    let mut bad_crc = good.clone();
    let last = bad_crc.len() - 1;
    bad_crc[last] ^= 0x01;
    assert_ne!(mcu_layout(&bad_crc), Some(Layout::DfuSuffix));
    assert!(parse_error(&bad_crc, Layout::DfuSuffix).contains("Invalid DFU suffix CRC-32"));
    // A valid suffix with a defect is a format error, not raw code.
    let dfuse_without_prefix = dfu_file(
        &code[..128],
        &DfuSuffix {
            bcd_dfu: BCD_DFU_DFUSE,
            ..PID_CODES_TEST
        },
    );
    assert_eq!(mcu_layout(&dfuse_without_prefix), Some(Layout::DfuSuffix));
    assert_eq!(
        parse_error(&dfuse_without_prefix, Layout::DfuSuffix),
        "MCU image parse error: Missing DfuSe prefix for DFU suffix bcdDFU 0x011A at 0x86"
    );
    assert!(detect_payload(&dfuse_without_prefix, &ClassifierOptions::new()).is_err());
    let newer = dfu_file(
        &code[..128],
        &DfuSuffix {
            bcd_dfu: 0x0110,
            ..PID_CODES_TEST
        },
    );
    assert!(parse_error(&newer, Layout::DfuSuffix)
        .contains("Unsupported DFU suffix bcdDFU 0x0110 at 0x86; DFU 1.1 files use 0x0100"));
    let mut short_length = good.clone();
    let length_at = short_length.len() - 5;
    short_length[length_at] = 15;
    fix_dfu_crc(&mut short_length);
    assert!(parse_error(&short_length, Layout::DfuSuffix)
        .contains("Invalid DFU suffix bLength 15 B at 0x8B"));
    // bLength may not swallow the whole file: some firmware must remain.
    let mut whole = good.clone();
    whole[length_at] = 144;
    fix_dfu_crc(&mut whole);
    assert!(parse_error(&whole, Layout::DfuSuffix).contains("Invalid DFU suffix bLength 144 B"));
    let empty = dfu_file(&[], &PID_CODES_TEST);
    assert!(parse_error(&empty, Layout::DfuSuffix).contains("Truncated DFU file: 16 B"));
}

#[test]
fn dfu_suffix_truncations_are_errors_and_mutations_do_not_panic() {
    let file = dfu_file(&thumb()[..96], &PID_CODES_TEST);
    for end in 0..file.len() {
        assert!(
            mcu::parse_container(&file[..end], Layout::DfuSuffix).is_err(),
            "prefix {end}"
        );
        assert_ne!(mcu_layout(&file[..end]), Some(Layout::DfuSuffix));
    }
    sweep(&file, Layout::DfuSuffix);
}

// Silicon Labs EBL (UG103.6 chapter 5, Gecko SDK Suite v2.6 ebl.h): tag ID
// and length big-endian, header fields big-endian, AAT fields
// little-endian, end CRC little-endian.

const EBLTAG_HEADER: u16 = 0x0000;
const EBLTAG_METADATA: u16 = 0xf608;
const EBLTAG_PROG: u16 = 0xfe01;
const EBLTAG_MFGPROG: u16 = 0x02fe;
const EBLTAG_ERASEPROG: u16 = 0xfd03;
const EBLTAG_END: u16 = 0xfc04;
const EBLTAG_ENC_HEADER: u16 = 0xfb05;
const EBLTAG_ENC_INIT: u16 = 0xfa06;
const EBLTAG_ENC_EBL_DATA: u16 = 0xf907;
const EBLTAG_ENC_MAC: u16 = 0xf709;
const IMAGE_SIGNATURE: u16 = 0xe350;
const APP_ADDRESS_TABLE_TYPE: u16 = 0x0aa7;
const EMBER_PLATFORM_CORTEXM3: u8 = 4;
const EMBER_PLATFORM_XAP2B: u8 = 2;
const EMBER_MICRO_CORTEXM3_EFR32: u8 = 24;

/// One tag: big-endian tag ID and length, then the payload.
fn ebl_tag(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut tag = id.to_be_bytes().to_vec();
    tag.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    tag.extend_from_slice(payload);
    tag
}

/// The 128 header bytes of an application address table
/// (`HalAppAddressTableType`, little-endian): top of stack, reset vector,
/// NMI and hard fault handlers, type, version, vector table, then
/// platInfo, microInfo, phyInfo, aatSize and the version fields.
fn aat(table_type: u16, platform: u8, micro: u8) -> Vec<u8> {
    let mut table = vec![0u8; 128];
    table[0..4].copy_from_slice(&0x2000_8000u32.to_le_bytes()); // topOfStack
    table[4..8].copy_from_slice(&0x0000_40c1u32.to_le_bytes()); // resetVector
    table[8..12].copy_from_slice(&0x0000_40d1u32.to_le_bytes()); // nmiHandler
    table[12..16].copy_from_slice(&0x0000_40d3u32.to_le_bytes()); // hardFaultHandler
    table[16..18].copy_from_slice(&table_type.to_le_bytes()); // type
    table[18..20].copy_from_slice(&0x010au16.to_le_bytes()); // version (AAT_VERSION)
    table[20..24].copy_from_slice(&0x0000_4100u32.to_le_bytes()); // vectorTable
    table[24] = platform; // platInfo
    table[25] = micro; // microInfo
    table[26] = 15; // phyInfo (PHY_RAIL in EFR32 builds)
    table[27] = 172; // aatSize
    table[28..30].copy_from_slice(&0x5700u16.to_le_bytes()); // softwareVersion
    table[88..92].copy_from_slice(&0x0000_0003u32.to_le_bytes()); // customerApplicationVersion
    table
}

/// Header tag: version 0x0201, IMAGE_SIGNATURE, flashAddr (where the AAT
/// goes), aatCrc (synthetic, not computed), then the AAT bytes.
fn ebl_header(flash_address: u32, table: &[u8]) -> Vec<u8> {
    let mut payload = 0x0201u16.to_be_bytes().to_vec(); // version
    payload.extend_from_slice(&IMAGE_SIGNATURE.to_be_bytes()); // signature
    payload.extend_from_slice(&flash_address.to_be_bytes()); // flashAddr
    payload.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // aatCrc
    payload.extend_from_slice(table); // aatBuff
    ebl_tag(EBLTAG_HEADER, &payload)
}

/// A program tag: big-endian flashAddr, then the data.
fn ebl_program(id: u16, address: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = address.to_be_bytes().to_vec();
    payload.extend_from_slice(data);
    ebl_tag(id, &payload)
}

/// The tags, then the end tag whose little-endian eblCrc is the zlib CRC-32
/// of every byte before it.
fn ebl(tags: &[Vec<u8>]) -> Vec<u8> {
    let mut file = tags.concat();
    file.extend_from_slice(&EBLTAG_END.to_be_bytes());
    file.extend_from_slice(&4u16.to_be_bytes());
    let crc = crc32(&file);
    file.extend_from_slice(&crc.to_le_bytes()); // eblCrc
    file
}

/// Header tag for the EFR32 platform and one erase-then-program tag of
/// `code` right after the AAT.
fn efr32_ebl(code: &[u8]) -> Vec<u8> {
    ebl(&[
        ebl_header(
            0x0000_4000,
            &aat(
                APP_ADDRESS_TABLE_TYPE,
                EMBER_PLATFORM_CORTEXM3,
                EMBER_MICRO_CORTEXM3_EFR32,
            ),
        ),
        ebl_program(EBLTAG_ERASEPROG, 0x0000_4080, code),
    ])
}

#[test]
fn ebl_program_tags_become_sections_and_the_aat_platform_names_cortex_m() {
    let code = thumb();
    let file = efr32_ebl(&code);
    assert_eq!(mcu_layout(&file), Some(Layout::Ebl));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::SilabsEbl);
    assert_eq!(p.format.variant_name.as_deref(), Some("EBL v2 file"));
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(entry_point(&p), Some(0x40c1));
    assert!(has_note(
        &p,
        "EBL: 1 program section; end-tag CRC-32 verified; the AAT names the platform"
    ));
    assert!(has_note(
        &p,
        "AAT platform 4 (CortexM3) names an Arm Cortex-M core"
    ));
    assert_eq!(metadata_text(&p, "ebl_version"), "0x0201");
    assert_eq!(metadata_text(&p, "ebl_aat_address"), "0x00004000");
    assert_eq!(metadata_text(&p, "ebl_aat_crc"), "0x12345678");
    assert_eq!(metadata_text(&p, "ebl_platform"), "4 (CortexM3)");
    assert_eq!(metadata_text(&p, "ebl_micro"), "24 (efr32)");
    assert_eq!(metadata_text(&p, "ebl_software_version"), "0x5700");
    // Header tag 4 + 140 B, program tag header 4 B and flashAddr 4 B.
    assert_eq!(
        metadata_text(&p, "ebl_section_0"),
        format!("file 0x98; destination 0x4080; {} B", code.len())
    );
}

#[test]
fn ebl_without_the_cortex_m_platform_leaves_the_isa_to_the_code_model() {
    let code = riscv32();
    let xap = ebl(&[
        ebl_header(0, &aat(APP_ADDRESS_TABLE_TYPE, EMBER_PLATFORM_XAP2B, 1)),
        ebl_program(EBLTAG_PROG, 0, &code),
    ]);
    let p = classify(&xap);
    assert_eq!(p.format.format, FileFormat::SilabsEbl);
    assert!(has_note(
        &p,
        "AAT platform 2 (XAP2b) is not mapped to an ISA"
    ));
    assert!(has_note(&p, "the format names no ISA"));
    assert_eq!(p.primary.isa, Isa::RiscV32);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(metadata_text(&p, "ebl_micro"), "1");
    // An AAT whose type is not the application table is not read.
    let other_type = ebl(&[
        ebl_header(0, &aat(0xffff, EMBER_PLATFORM_CORTEXM3, 24)),
        ebl_program(EBLTAG_PROG, 0, &code),
    ]);
    let p = classify(&other_type);
    assert!(has_note(
        &p,
        "AAT type 0xFFFF is not the application address table"
    ));
    assert!(metadata(&p, "ebl_platform").is_none());
    assert_eq!(entry_point(&p), None);
    // A header that holds no AAT names nothing.
    let bare = ebl(&[ebl_header(0, &[]), ebl_program(EBLTAG_PROG, 0, &code)]);
    let p = classify(&bare);
    assert!(has_note(
        &p,
        "The header holds 0 B of the application address table"
    ));
    // The named platform wins over the code model, which is reported.
    let mismatch = ebl(&[
        ebl_header(0, &aat(APP_ADDRESS_TABLE_TYPE, EMBER_PLATFORM_CORTEXM3, 24)),
        ebl_program(EBLTAG_PROG, 0, &code),
    ]);
    let p = classify(&mismatch);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(has_note(
        &p,
        "Container names arm; the loaded code classifies as"
    ));
}

#[test]
fn ebl_manufacturing_data_and_metadata_are_opaque_children() {
    let code = thumb();
    let file = ebl(&[
        ebl_header(
            0x0800_4000,
            &aat(APP_ADDRESS_TABLE_TYPE, EMBER_PLATFORM_CORTEXM3, 3),
        ),
        ebl_tag(EBLTAG_METADATA, b"build 42"),
        ebl_program(EBLTAG_PROG, 0x0800_4080, &code[..2048]),
        ebl_program(EBLTAG_PROG, 0x0800_4880, &code[2048..4096]),
        ebl_program(EBLTAG_MFGPROG, 0x0804_0800, &[0x5a; 8]),
    ]);
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(metadata_text(&p, "ebl_micro"), "3 (em357)");
    assert!(has_note(&p, "EBL: 2 program sections"));
    let labels: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(labels, ["Metadata", "Manufacturing data at 0x8040800"]);
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
    assert!(has_note(
        &p,
        "Metadata: opaque; payload ISA analysis skipped"
    ));
    // Header 144 B, metadata tag 12 B, two program tags of 2056 B, then the
    // manufacturing tag header and address.
    let mfg_data = 144 + 12 + 2 * 2056 + 8;
    assert_eq!(
        metadata_text(&p, "ebl_component_1"),
        format!("file 0x{mfg_data:X}; 8 B; opaque")
    );
    assert_eq!(
        metadata_text(&p, "ebl_section_1"),
        format!(
            "file 0x{:X}; destination 0x8004880; 2048 B",
            144 + 12 + 2056 + 8
        )
    );
}

/// Encryption header (version, encType AES-CCM, signature), encryption init
/// (msgLen, 12-byte nonce), one encrypted data tag, the MAC and the end tag.
fn encrypted_ebl(with_mac: bool) -> Vec<u8> {
    let mut header = 0x0201u16.to_be_bytes().to_vec(); // version
    header.extend_from_slice(&1u16.to_be_bytes()); // encType: ENC_TYPE_CCM
    header.extend_from_slice(&IMAGE_SIGNATURE.to_be_bytes()); // signature
    let mut init = 64u32.to_be_bytes().to_vec(); // msgLen
    init.extend_from_slice(&[0x11; 12]); // nonce
    let mut tags = vec![
        ebl_tag(EBLTAG_ENC_HEADER, &header),
        ebl_tag(EBLTAG_ENC_INIT, &init),
        ebl_tag(EBLTAG_ENC_EBL_DATA, &thumb()[..64]),
    ];
    if with_mac {
        tags.push(ebl_tag(EBLTAG_ENC_MAC, &[0x22; 16]));
    }
    ebl(&tags)
}

#[test]
fn ebl_encrypted_files_are_opaque_and_the_mac_is_not_verified() {
    let file = encrypted_ebl(true);
    assert_eq!(mcu_layout(&file), Some(Layout::Ebl));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::SilabsEbl);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert!(has_note(
        &p,
        "Encrypted EBL: 1 encrypted data tag; the key is not in the file"
    ));
    assert!(has_note(&p, "AES-CCM MAC present; not verified"));
    assert_eq!(metadata_text(&p, "ebl_encryption"), "AES-CCM");
    assert_eq!(metadata_text(&p, "ebl_encrypted_length"), "64");
    assert_eq!(p.slices[0].label.as_deref(), Some("Encrypted EBL data"));
    // Figure 5.2: the MAC comes before the end tag.
    let no_mac = encrypted_ebl(false);
    assert!(parse_error(&no_mac, Layout::Ebl).contains("Invalid EBL tag order: end tag"));
    // Plaintext program data cannot follow an encryption header.
    let mut header = 0x0201u16.to_be_bytes().to_vec();
    header.extend_from_slice(&1u16.to_be_bytes());
    header.extend_from_slice(&IMAGE_SIGNATURE.to_be_bytes());
    let mixed = ebl(&[
        ebl_tag(EBLTAG_ENC_HEADER, &header),
        ebl_program(EBLTAG_PROG, 0, &[0; 4]),
    ]);
    assert!(parse_error(&mixed, Layout::Ebl).contains("Invalid EBL tag order: program data tag"));
}

#[test]
fn ebl_crc_order_signature_and_lengths_are_checked() {
    let code = thumb();
    let good = efr32_ebl(&code[..64]);
    let mut bad_crc = good.clone();
    let last = bad_crc.len() - 1;
    bad_crc[last] ^= 0x80;
    assert!(parse_error(&bad_crc, Layout::Ebl).contains("Invalid EBL end tag CRC-32"));
    // The header magic makes the damaged file a format error.
    assert!(detect_payload(&bad_crc, &ClassifierOptions::new()).is_err());
    let header = ebl_header(0, &aat(APP_ADDRESS_TABLE_TYPE, EMBER_PLATFORM_CORTEXM3, 24));
    let program = ebl_program(EBLTAG_PROG, 0x4080, &code[..64]);
    let repeated = ebl(&[header.clone(), program.clone(), header.clone()]);
    assert!(parse_error(&repeated, Layout::Ebl).contains("Invalid EBL tag order: header tag at 0x"));
    let no_header = ebl(std::slice::from_ref(&program));
    assert_eq!(mcu_layout(&no_header), None);
    assert!(parse_error(&no_header, Layout::Ebl)
        .contains("Missing EBL header tag at 0x0: program data tag"));
    let unknown = ebl(&[header.clone(), ebl_tag(0x1234, &[0; 4])]);
    assert_eq!(
        parse_error(&unknown, Layout::Ebl),
        "MCU image parse error: Unknown EBL tag 0x1234 at 0x90"
    );
    let odd = ebl(&[header.clone(), ebl_program(EBLTAG_PROG, 0, &[1, 2, 3])]);
    assert!(parse_error(&odd, Layout::Ebl)
        .contains("Invalid EBL program data tag at 0x90: 3 B of data is not a multiple of 2 B"));
    let short_program = ebl(&[header.clone(), ebl_program(EBLTAG_PROG, 0, &[])]);
    assert!(parse_error(&short_program, Layout::Ebl)
        .contains("Invalid EBL program data tag length 4 B at 0x92; expected at least 6 B"));
    let mut long_header = header.clone();
    long_header[3] = 141;
    long_header.push(0);
    let long_header = ebl(&[long_header, program.clone()]);
    assert!(parse_error(&long_header, Layout::Ebl)
        .contains("Invalid EBL header tag length 141 B at 0x2; at most 140 B"));
    let mut version3 = header.clone();
    version3[4] = 0x03;
    let version3 = ebl(&[version3, program.clone()]);
    assert!(parse_error(&version3, Layout::Ebl).contains("Unsupported EBL version 0x0301 at 0x4"));
    let mut long_end = ebl(&[header.clone(), program.clone()]);
    let end_length_at = long_end.len() - 5;
    long_end[end_length_at] = 5;
    long_end.push(0);
    assert!(parse_error(&long_end, Layout::Ebl).contains("Invalid EBL end tag length 5 B"));
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing, Layout::Ebl).contains("Unexpected 4 B after the EBL end tag"));
    // Erased-flash padding to a block boundary is accepted.
    let mut padded = good.clone();
    padded.resize(padded.len().div_euclid(64) * 64 + 64, 0xff);
    let c = mcu::parse_container(&padded, Layout::Ebl).expect("padding is accepted");
    assert_eq!(c.consumed, good.len());
}

#[test]
fn ebl_truncations_are_errors_and_mutations_do_not_panic() {
    let code = thumb();
    let plain = ebl(&[
        ebl_header(
            0x4000,
            &aat(APP_ADDRESS_TABLE_TYPE, EMBER_PLATFORM_CORTEXM3, 24),
        ),
        ebl_tag(EBLTAG_METADATA, b"m"),
        ebl_program(EBLTAG_ERASEPROG, 0x4080, &code[..32]),
        ebl_program(EBLTAG_MFGPROG, 0x0804_0800, &[0x5a; 4]),
    ]);
    let encrypted = encrypted_ebl(true);
    for file in [&plain, &encrypted] {
        assert_eq!(classify(file).format.format, FileFormat::SilabsEbl);
        for end in 0..file.len() {
            assert!(
                mcu::parse_container(&file[..end], Layout::Ebl).is_err(),
                "prefix {end}"
            );
        }
        sweep(file, Layout::Ebl);
    }
}

// Nordic nRF5 DFU init packets (pc-nrfutil v6.1.7 dfu-cc.proto): protobuf
// keys are `field << 3 | wire type`, varints in 7-bit groups.

fn pb_varint_value(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let group = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            bytes.push(group);
            return bytes;
        }
        bytes.push(group | 0x80);
    }
}

/// A varint field (wire type 0).
fn pb_varint(field: u64, value: u64) -> Vec<u8> {
    let mut bytes = pb_varint_value(field << 3);
    bytes.extend(pb_varint_value(value));
    bytes
}

/// A length-delimited field (wire type 2).
fn pb_bytes(field: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = pb_varint_value(field << 3 | 2);
    bytes.extend(pb_varint_value(value.len() as u64));
    bytes.extend_from_slice(value);
    bytes
}

/// `Hash`: hash_type (1) SHA256, hash (2).
fn pb_hash(hash: &[u8]) -> Vec<u8> {
    [pb_varint(1, 3), pb_bytes(2, hash)].concat()
}

/// `InitCommand` for an application of `app_size` bytes: type (4)
/// APPLICATION, app_size (7), hash (8), plus `extra` fields.
fn pb_application(app_size: u64, extra: &[Vec<u8>]) -> Vec<u8> {
    let mut init = [
        pb_varint(4, 0),
        pb_varint(7, app_size),
        pb_bytes(8, &pb_hash(&[0x33; 32])),
    ]
    .concat();
    for field in extra {
        init.extend_from_slice(field);
    }
    init
}

/// `Packet.command` (1): `Command` with op_code (1) INIT and init (2).
fn pb_packet(init: &[u8]) -> Vec<u8> {
    pb_bytes(1, &[pb_varint(1, 1), pb_bytes(2, init)].concat())
}

#[test]
fn nordic_signed_init_packet_from_protoc_is_metadata_only() {
    let file = fixture("nordic-init-signed.dat");
    assert_eq!(mcu_layout(&file), Some(Layout::NordicInitPacket));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::NordicInitPacket);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("nRF DFU init packet")
    );
    assert!(p.format.confidence < 1.0);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
    assert!(p.candidates.is_empty());
    assert!(p.slices.is_empty());
    assert!(has_note(
        &p,
        "nRF DFU init packet: signed command (ECDSA_P256_SHA256, 64 B signature; not \
         verified); firmware type APPLICATION, 5484 B"
    ));
    assert!(has_note(
        &p,
        "SHA256 hash of the firmware image (32 B) present; not verified"
    ));
    assert!(has_note(&p, "metadata-only; ISA analysis was not applied"));
    assert_eq!(metadata_text(&p, "nordic_fw_type"), "APPLICATION");
    assert_eq!(metadata_text(&p, "nordic_fw_version"), "1");
    assert_eq!(metadata_text(&p, "nordic_hw_version"), "52");
    assert_eq!(metadata_text(&p, "nordic_sd_req"), "0x0100, 0x0101");
    assert_eq!(metadata_text(&p, "nordic_app_size"), "5484");
    assert_eq!(metadata_text(&p, "nordic_hash_type"), "SHA256");
    assert_eq!(metadata_text(&p, "nordic_is_debug"), "false");
    assert_eq!(
        metadata_text(&p, "nordic_boot_validation_0"),
        "VALIDATE_GENERATED_CRC; 0 B"
    );
    assert_eq!(
        metadata_text(&p, "nordic_signature"),
        "ECDSA_P256_SHA256; 64 B; not verified"
    );
    // pc-nrfutil stores the SHA-256 of the image in reverse byte order.
    let mut digest = Sha256::digest(thumb()).to_vec();
    digest.reverse();
    assert_eq!(metadata_text(&p, "nordic_hash"), hex::encode_upper(&digest));
}

#[test]
fn nordic_unsigned_softdevice_bootloader_packet_from_protoc() {
    let p = classify(&fixture("nordic-init-unsigned.dat"));
    assert_eq!(p.format.format, FileFormat::NordicInitPacket);
    assert!(has_note(
        &p,
        "nRF DFU init packet: unsigned command; firmware type SOFTDEVICE_BOOTLOADER, 177440 B"
    ));
    assert_eq!(metadata_text(&p, "nordic_sd_req"), "0xFFFE");
    assert_eq!(metadata_text(&p, "nordic_sd_size"), "152864");
    assert_eq!(metadata_text(&p, "nordic_bl_size"), "24576");
    assert_eq!(metadata_text(&p, "nordic_fw_version"), "4294967295");
    assert_eq!(metadata_text(&p, "nordic_is_debug"), "true");
    assert_eq!(
        metadata_text(&p, "nordic_boot_validation_1"),
        "NO_VALIDATION; 0 B"
    );
    assert_eq!(metadata_text(&p, "nordic_signature"), "none");
}

#[test]
fn nordic_packets_built_from_the_wire_layout_follow_the_bootloader_rules() {
    // Fields in any order, sd_req (3) unpacked: still a packet.
    let reordered = pb_packet(
        &[
            pb_bytes(8, &pb_hash(&[0x44; 32])),
            pb_varint(3, 0x0100),
            pb_varint(7, 4096),
            pb_varint(3, 0x0101),
        ]
        .concat(),
    );
    let p = classify(&reordered);
    assert_eq!(p.format.format, FileFormat::NordicInitPacket);
    assert_eq!(metadata_text(&p, "nordic_sd_req"), "0x0100, 0x0101");
    let message = |data: &[u8]| parse_error(data, Layout::NordicInitPacket);
    let good_init = pb_application(4096, &[]);
    let both = [
        pb_packet(&good_init),
        pb_bytes(
            2,
            &[
                pb_bytes(1, &[pb_varint(1, 1), pb_bytes(2, &good_init)].concat()),
                pb_varint(2, 0),
                pb_bytes(3, &[0x5a; 64]),
            ]
            .concat(),
        ),
    ]
    .concat();
    assert!(
        message(&both).contains("Ambiguous Nordic init packet: both command and signed_command")
    );
    let no_hash = pb_packet(&[pb_varint(4, 0), pb_varint(7, 4096)].concat());
    assert!(message(&no_hash).contains("Missing Nordic init packet firmware hash"));
    let no_size = pb_packet(&[pb_varint(4, 0), pb_bytes(8, &pb_hash(&[0x33; 32]))].concat());
    assert!(
        message(&no_size).contains("Missing Nordic init packet firmware size for type APPLICATION")
    );
    let unknown_field = pb_packet(&pb_application(4096, &[pb_varint(11, 1)]));
    assert!(message(&unknown_field).contains("Unknown Nordic init packet InitCommand field 11"));
    let unknown_type = pb_packet(&[pb_varint(4, 5), pb_varint(7, 1)].concat());
    assert!(message(&unknown_type).contains("Unknown Nordic init packet type 5"));
    let long_hash = pb_packet(&[pb_varint(7, 1), pb_bytes(8, &pb_hash(&[0x33; 33]))].concat());
    assert!(message(&long_hash).contains("Invalid Nordic init packet hash at 0x"));
    let duplicate = pb_packet(&pb_application(4096, &[pb_varint(7, 8192)]));
    assert!(message(&duplicate).contains("Duplicate Nordic init packet app_size"));
    let reset = pb_bytes(1, &[pb_varint(1, 0), pb_bytes(2, &good_init)].concat());
    assert!(message(&reset).contains("Unsupported Nordic DFU command op_code 0"));
    let wide = pb_packet(&pb_application(4096, &[pb_varint(1, 1 << 32)]));
    assert!(message(&wide).contains("Invalid Nordic init packet fw_version 4294967296"));
    let bad_wire = pb_packet(&pb_application(4096, &[pb_bytes(2, &[1])]));
    assert!(message(&bad_wire).contains("Invalid Nordic init packet hw_version at 0x"));
    let missing_signature = pb_bytes(
        2,
        &[
            pb_bytes(1, &[pb_varint(1, 1), pb_bytes(2, &good_init)].concat()),
            pb_varint(2, 0),
        ]
        .concat(),
    );
    assert!(
        message(&missing_signature).contains("Missing Nordic init packet SignedCommand.signature")
    );
    // The bootloader takes at most 512 B; larger inputs are not packets.
    let oversized = pb_packet(&pb_application(4096, &[pb_bytes(10, &vec![0; 600])]));
    assert!(message(&oversized).contains("at most 512 B"));
    assert_eq!(mcu_layout(&oversized), None);
    for rejected in [&both, &no_hash, &no_size, &unknown_field, &reset] {
        assert_eq!(mcu_layout(rejected), None);
    }
}

#[test]
fn nordic_truncations_are_not_packets_and_mutations_do_not_panic() {
    for name in ["nordic-init-signed.dat", "nordic-init-unsigned.dat"] {
        let file = fixture(name);
        for end in 0..file.len() {
            assert!(
                mcu::parse_container(&file[..end], Layout::NordicInitPacket).is_err(),
                "{name} prefix {end}"
            );
            assert_ne!(mcu_layout(&file[..end]), Some(Layout::NordicInitPacket));
        }
        sweep(&file, Layout::NordicInitPacket);
    }
}

/// A stored ZIP of `(name, contents)` members: local headers, the central
/// directory and the end record (APPNOTE 4.3.7, 4.3.12, 4.3.16).
fn stored_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let push_u16 = |out: &mut Vec<u8>, value: u16| out.extend_from_slice(&value.to_le_bytes());
    let push_u32 = |out: &mut Vec<u8>, value: u32| out.extend_from_slice(&value.to_le_bytes());
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, contents) in members {
        let offset = out.len() as u32;
        let crc = crc32(contents);
        let size = contents.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut out, 20); // version needed
        push_u16(&mut out, 0); // flags
        push_u16(&mut out, 0); // method: stored
        push_u16(&mut out, 0); // last mod time
        push_u16(&mut out, 0x21); // last mod date: 1980-01-01
        push_u32(&mut out, crc);
        push_u32(&mut out, size); // compressed size
        push_u32(&mut out, size); // uncompressed size
        push_u16(&mut out, name.len() as u16);
        push_u16(&mut out, 0); // extra field length
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(contents);
        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, 20); // version made by
        push_u16(&mut central, 20); // version needed
        push_u16(&mut central, 0); // flags
        push_u16(&mut central, 0); // method
        push_u16(&mut central, 0); // time
        push_u16(&mut central, 0x21); // date
        push_u32(&mut central, crc);
        push_u32(&mut central, size);
        push_u32(&mut central, size);
        push_u16(&mut central, name.len() as u16);
        push_u16(&mut central, 0); // extra
        push_u16(&mut central, 0); // comment
        push_u16(&mut central, 0); // disk number
        push_u16(&mut central, 0); // internal attributes
        push_u32(&mut central, 0); // external attributes
        push_u32(&mut central, offset); // local header offset
        central.extend_from_slice(name.as_bytes());
    }
    let directory_offset = out.len() as u32;
    let directory_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut out, 0); // disk
    push_u16(&mut out, 0); // directory disk
    push_u16(&mut out, members.len() as u16);
    push_u16(&mut out, members.len() as u16);
    push_u32(&mut out, directory_size);
    push_u32(&mut out, directory_offset);
    push_u16(&mut out, 0); // comment length
    out
}

#[test]
fn nordic_dfu_zip_lists_its_init_packet_member() {
    let manifest =
        br#"{"manifest": {"application": {"bin_file": "app.bin", "dat_file": "app.dat"}}}"#;
    let packet = fixture("nordic-init-signed.dat");
    let archive = stored_zip(&[
        ("manifest.json", manifest),
        ("app.bin", &thumb()),
        ("app.dat", &packet),
    ]);
    let p = classify(&archive);
    assert_eq!(p.format.format, FileFormat::Zip);
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("Nordic DFU package")
    );
    let member = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("app.dat"))
        .expect("the init packet is a recognized member");
    assert_eq!(
        member.variant.as_ref().map(|v| v.name.as_str()),
        Some("nRF DFU init packet")
    );
    assert!(matches!(member.isa, Isa::Unknown(_)));
    // The raw application image is not a recognized format, so it is not
    // listed.
    assert!(p
        .slices
        .iter()
        .all(|s| s.label.as_deref() != Some("app.bin")));
}
