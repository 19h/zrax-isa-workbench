//! The detection report: its outcome is the payload of `detect_payload`, a
//! refusal keeps its reason and candidates, the code-model reading counts
//! windows, a boot marker is reported whether or not it changed the answer,
//! and a container's members carry file ranges, destination addresses and
//! their decoded bytes.

use std::path::Path;

use zrax::formats::checksum::crc32;
use zrax::report::{
    member_bytes, AbstainReason, BootMarkerKind, DeclaredTarget, DetectionReport, MemberKind,
    Outcome,
};
use zrax::{
    detect_payload, detect_report, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa,
};

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .expect("fixture is in the repository")
}

/// RISC-V code (`tests/fixtures/transforms`), repeated to several windows.
fn riscv_code() -> Vec<u8> {
    read("tests/fixtures/transforms/riscv64.text.bin").repeat(4)
}

/// Thumb (ARMv7E-M) code (`tests/fixtures/mcu`).
fn thumb_code() -> Vec<u8> {
    read("tests/fixtures/mcu/thumbv7em.text.bin")
}

/// Bytes of a 64-bit linear congruential generator (Knuth's MMIX
/// constants): deterministic noise that is neither code nor padding.
fn noise(size: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    (0..size)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

/// A 64-byte ELF header: 32-bit class, big-endian data, version 1,
/// executable, machine 8 (MIPS).
fn elf_mips_be() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 1;
    data[5] = 2;
    data[6] = 1;
    data[16..18].copy_from_slice(&2u16.to_be_bytes());
    data[18..20].copy_from_slice(&8u16.to_be_bytes());
    data
}

/// One gzip member (RFC 1952): fixed header, DEFLATE data, CRC-32, size.
fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
    member.extend_from_slice(&crc32(payload).to_le_bytes());
    member.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    member
}

const UIMAGE_ENTRY: u32 = 0x8000_8000;
const UIMAGE_HEADER_SIZE: usize = 64;

/// uImage: magic, header CRC (computed with the field zeroed), timestamp,
/// data size, load address, entry point, data CRC, OS 5 (Linux),
/// architecture 5 (MIPS), type 2 (kernel), compression 1 (gzip), name; then
/// the payload.
fn uimage_gzip_mips(payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; UIMAGE_HEADER_SIZE];
    data[0..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    data[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    data[16..20].copy_from_slice(&UIMAGE_ENTRY.to_be_bytes());
    data[20..24].copy_from_slice(&UIMAGE_ENTRY.to_be_bytes());
    data[24..28].copy_from_slice(&crc32(payload).to_be_bytes());
    data[0x1c] = 5;
    data[0x1d] = 5;
    data[0x1e] = 2;
    data[0x1f] = 1;
    data[0x20..0x26].copy_from_slice(b"kernel");
    let header_crc = crc32(&data);
    data[4..8].copy_from_slice(&header_crc.to_be_bytes());
    data.extend_from_slice(payload);
    data
}

const UF2_MAGIC_START0: u32 = 0x0A32_4655;
const UF2_MAGIC_START1: u32 = 0x9E5D_5157;
const UF2_MAGIC_END: u32 = 0x0AB1_6F30;
const UF2_FLAG_FAMILY_ID_PRESENT: u32 = 0x0000_2000;
const UF2_PAYLOAD: usize = 256;
const UF2_BLOCK: usize = 512;
/// RP2350 datasheet Table 469: a Secure Arm image.
const RP2350_ARM_S: u32 = 0xe48b_ff59;
const UF2_ADDRESS: u32 = 0x1000_0000;

/// `code` as UF2 blocks of 256 payload bytes from `UF2_ADDRESS`: both start
/// magics, the family flag, target address, payload size, block number,
/// block count, the family ID, the payload and the end magic.
fn uf2_arm(code: &[u8]) -> Vec<u8> {
    let chunks: Vec<&[u8]> = code.chunks(UF2_PAYLOAD).collect();
    let mut file = Vec::new();
    for (number, chunk) in chunks.iter().enumerate() {
        let mut block = vec![0u8; UF2_BLOCK];
        let mut put = |at: usize, value: u32| {
            block[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        put(0, UF2_MAGIC_START0);
        put(4, UF2_MAGIC_START1);
        put(8, UF2_FLAG_FAMILY_ID_PRESENT);
        put(12, UF2_ADDRESS + (number * UF2_PAYLOAD) as u32);
        put(16, chunk.len() as u32);
        put(20, number as u32);
        put(24, chunks.len() as u32);
        put(28, RP2350_ARM_S);
        put(508, UF2_MAGIC_END);
        block[32..32 + chunk.len()].copy_from_slice(chunk);
        file.extend(block);
    }
    file
}

/// A Cortex-M vector table: initial stack pointer in SRAM, reset handler,
/// NMI, HardFault, MemManage, BusFault and UsageFault handlers (Thumb bit
/// set), four reserved words, SVCall, DebugMonitor, one reserved word,
/// PendSV and SysTick.
fn vector_table() -> Vec<u8> {
    let words: [u32; 16] = [
        0x2004_0000,
        0x0800_0041,
        0x0800_0201,
        0x0800_0203,
        0x0800_0205,
        0x0800_0207,
        0x0800_0209,
        0,
        0,
        0,
        0,
        0x0800_020B,
        0x0800_020D,
        0,
        0x0800_020F,
        0x0800_0211,
    ];
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// An STM8 interrupt vector table (RM0016): 32 entries of the `INT` opcode
/// 0x82 and a 24-bit big-endian handler address in flash, here all 0x8080,
/// the first byte after the table; then `filler` bytes of flash.
fn stm8_image(filler: usize) -> Vec<u8> {
    let mut image: Vec<u8> = [0x82, 0x00, 0x80, 0x80].repeat(32);
    image.extend(std::iter::repeat(0x81).take(filler));
    image
}

fn report(data: &[u8]) -> DetectionReport {
    detect_report(data, &ClassifierOptions::new())
}

fn decided(report: &DetectionReport) -> &DetectionPayload {
    match &report.outcome {
        Outcome::Decided(payload) => payload,
        Outcome::Abstained(abstention) => panic!("abstained: {}", abstention.message),
    }
}

fn refusal(report: &DetectionReport) -> (AbstainReason, usize) {
    match &report.outcome {
        Outcome::Abstained(abstention) => (abstention.reason, abstention.candidates.len()),
        Outcome::Decided(payload) => panic!("decided {:?}", payload.primary.isa),
    }
}

#[test]
fn a_decided_outcome_is_the_payload_of_detect_payload() {
    let inputs = [
        riscv_code(),
        elf_mips_be(),
        uimage_gzip_mips(&gzip(&elf_mips_be())),
        uf2_arm(&thumb_code()),
    ];
    for data in &inputs {
        let payload = detect_payload(data, &ClassifierOptions::new()).expect("classifies");
        assert_eq!(
            serde_json::to_string(decided(&report(data))).expect("serializes"),
            serde_json::to_string(&payload).expect("serializes")
        );
    }
}

#[test]
fn a_raw_code_reading_counts_the_windows_of_the_family_it_decided() {
    // A whole number of windows, so that no short tail window is in play.
    let mut code = riscv_code();
    code.truncate(code.len() / 1024 * 1024);
    let found = report(&code);
    assert_eq!(decided(&found).primary.isa, Isa::RiscV64);
    let reading = found.reading.expect("the code model read the input");
    assert_eq!(reading.family, Some("riscv"));
    assert!(reading.family_windows >= 1);
    assert!(reading.family_windows <= reading.code_windows);
    assert!(reading.code_windows <= reading.informative_windows);
    assert_eq!(reading.informative_windows, code.len() / 1024);
    assert!(reading.code_share > 0.5 && reading.code_share <= 1.0);
    assert_eq!((reading.transform, reading.rescanned), (None, false));
    assert_eq!(reading.trials, 1);
    assert_eq!(reading.budget, ClassifierOptions::new().max_scan_bytes);
    assert_eq!(found.boot_marker, None);
    assert_eq!(found.layout, None);
}

#[test]
fn a_reading_after_a_transform_names_the_transform() {
    let mut swapped = riscv_code();
    for pair in swapped.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    let found = report(&swapped);
    assert_eq!(decided(&found).primary.isa, Isa::RiscV64);
    let reading = found.reading.expect("the code model read the input");
    assert_eq!(reading.family, Some("riscv"));
    assert!(reading.transform.is_some());
    assert!(reading.trials > 1);
}

#[test]
fn refusals_keep_their_reason() {
    assert_eq!(refusal(&report(&[0x13; 10])), (AbstainReason::TooSmall, 0));

    let padding = report(&vec![0u8; 64 * 1024]);
    assert_eq!(refusal(&padding), (AbstainReason::Inconclusive, 0));
    let reading = padding.reading.expect("the code model read the input");
    assert_eq!((reading.family, reading.informative_windows), (None, 0));

    let random = report(&noise(64 * 1024));
    assert_eq!(refusal(&random).0, AbstainReason::Inconclusive);
    let reading = random.reading.expect("the code model read the input");
    assert_eq!(reading.informative_windows, 64);
    assert_eq!(reading.family_windows, 0);
}

#[test]
fn a_container_that_does_not_parse_is_a_format_refusal_without_a_reading() {
    let mut image = uimage_gzip_mips(&gzip(&elf_mips_be()));
    let last = image.len() - 1;
    image[last] ^= 0xFF;
    let found = report(&image);
    assert_eq!(refusal(&found), (AbstainReason::Format, 0));
    assert_eq!(found.reading, None);
    assert_eq!(found.layout, None);
}

#[test]
fn a_cortex_m_vector_table_is_reported_when_the_code_model_agrees() {
    let mut image = vector_table();
    image.extend(thumb_code());
    let found = report(&image);
    let payload = decided(&found);
    assert_eq!(payload.primary.isa, Isa::Arm);
    assert!(payload
        .notes
        .iter()
        .all(|note| !note.message.contains("vector table")));
    let marker = found.boot_marker.expect("the table is a boot marker");
    assert_eq!(
        (marker.kind, marker.isa),
        (BootMarkerKind::CortexMVectorTable, Isa::Arm)
    );
}

#[test]
fn an_stm8_vector_table_is_a_boot_marker() {
    let found = report(&stm8_image(128));
    assert_eq!(decided(&found).primary.isa, Isa::Stm8);
    let marker = found.boot_marker.expect("the table is a boot marker");
    assert_eq!(
        (marker.kind, marker.isa),
        (BootMarkerKind::Stm8VectorTable, Isa::Stm8)
    );
}

#[test]
fn a_child_member_carries_its_stored_range_codec_and_decoded_bytes() {
    let kernel = elf_mips_be();
    let stored = gzip(&kernel);
    let image = uimage_gzip_mips(&stored);
    let found = report(&image);
    let layout = found.layout.expect("a uImage has members");
    assert_eq!(layout.format, FileFormat::UImage);
    assert_eq!(layout.entry, Some(u64::from(UIMAGE_ENTRY)));
    assert_eq!((layout.members.len(), layout.omitted), (1, 0));
    let member = &layout.members[0];
    assert_eq!((member.index, member.kind), (0, MemberKind::Child));
    assert_eq!(member.offset, UIMAGE_HEADER_SIZE as u64);
    assert_eq!(member.stored_size, stored.len() as u64);
    assert_eq!(member.size, kernel.len() as u64);
    assert_eq!(member.transform, Some("gzip"));
    assert_eq!(member.address, None);
    assert!(member.available && !member.opaque);
    assert_eq!(member_bytes(&image, 0).expect("extracts"), kernel);
}

#[test]
fn a_load_section_carries_its_destination_address_and_the_declared_target() {
    let code = thumb_code();
    let file = uf2_arm(&code);
    let found = report(&file);
    assert_eq!(found.reading, None);
    let layout = found.layout.expect("a UF2 file has a load section");
    assert_eq!(layout.format, FileFormat::Uf2);
    assert_eq!(
        layout.target,
        Some(DeclaredTarget {
            isa: Isa::Arm,
            bits: 32,
            endianness: Some(Endianness::Little),
        })
    );
    assert_eq!(layout.members.len(), 1);
    let section = &layout.members[0];
    assert_eq!(section.kind, MemberKind::Section);
    assert_eq!(section.address, Some(u64::from(UF2_ADDRESS)));
    assert_eq!(
        (section.offset, section.stored_size),
        (0, file.len() as u64)
    );
    assert_eq!(section.size, code.len() as u64);
    assert_eq!(member_bytes(&file, 0).expect("extracts"), code);
}

#[test]
fn member_bytes_refuses_inputs_without_members_and_indices_outside_them() {
    assert!(member_bytes(&riscv_code(), 0).is_err());
    let image = uimage_gzip_mips(&gzip(&elf_mips_be()));
    assert!(member_bytes(&image, 1).is_err());
    assert!(member_bytes(&image, usize::MAX).is_err());
}

#[test]
fn reports_of_truncated_and_mutated_inputs_are_bounded() {
    let inputs = [
        uimage_gzip_mips(&gzip(&elf_mips_be())),
        uf2_arm(&thumb_code()[..512]),
        stm8_image(64),
    ];
    for data in &inputs {
        for end in 0..data.len() {
            let found = report(&data[..end]);
            for member in found.layout.iter().flat_map(|layout| &layout.members) {
                assert!(member.offset + member.stored_size <= end as u64);
            }
        }
        for at in 0..data.len() {
            let mut mutated = data.clone();
            mutated[at] ^= 0xFF;
            let found = report(&mutated);
            if let Some(layout) = &found.layout {
                for member in &layout.members {
                    let _ = member_bytes(&mutated, member.index);
                }
            }
        }
    }
}
