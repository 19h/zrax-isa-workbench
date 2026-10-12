//! Raw-dump transforms: byte swaps, lane interleaving and NAND spare
//! removal recover code that a reader or programmer stored out of execution
//! order, only when the stored bytes are inconclusive, and never turn noise
//! into a confident result.

use zrax::formats::checksum::crc32;
use zrax::heuristics;
use zrax::transform::{self, Transform};
use zrax::{
    detect_interleaved, detect_payload, ClassifierError, ClassifierOptions, DetectionPayload,
    Endianness, FileFormat, Isa, MetadataValue,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transforms");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

fn transform_name(payload: &DetectionPayload) -> Option<String> {
    payload
        .metadata
        .iter()
        .find_map(|m| match (&m.key, &m.value) {
            (zrax::MetadataKey::Custom(k), MetadataValue::String(v))
                if k == "transform_applied" =>
            {
                Some(v.clone())
            }
            _ => None,
        })
}

/// The even bytes of `code`, then its odd bytes: two 8-bit memories of a
/// 16-bit bus dumped one after the other.
fn split_lanes(code: &[u8]) -> Vec<u8> {
    let even: Vec<u8> = code.iter().step_by(2).copied().collect();
    let odd: Vec<u8> = code.iter().skip(1).step_by(2).copied().collect();
    [even, odd].concat()
}

#[test]
fn fixtures_classify_in_execution_order() {
    for (name, isa) in [
        ("aarch64.text.bin", Isa::AArch64),
        ("riscv64.text.bin", Isa::RiscV64),
    ] {
        let p = detect_payload(&fixture(name), &ClassifierOptions::new()).unwrap();
        assert_eq!(p.primary.isa, isa, "{name}");
        assert_eq!(transform_name(&p), None, "{name}");
    }
}

#[test]
fn byte_swapped_code_is_recovered_with_the_transform_recorded() {
    let code = fixture("aarch64.text.bin");
    let swapped = Transform::Swap16.apply(&code).unwrap();
    let p = detect_payload(&swapped, &ClassifierOptions::new()).unwrap();
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::AArch64, Endianness::Little)
    );
    assert_eq!(p.format.format, FileFormat::Raw);
    assert_eq!(transform_name(&p).as_deref(), Some("16-bit byte swap"));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("not in execution order")));
}

#[test]
fn split_lane_dumps_are_interleaved() {
    let code = fixture("riscv64.text.bin");
    let p = detect_payload(&split_lanes(&code), &ClassifierOptions::new()).unwrap();
    assert_eq!(p.primary.isa, Isa::RiscV64);
    assert_eq!(transform_name(&p).as_deref(), Some("2-lane interleave"));
}

#[test]
fn separately_dumped_lanes_are_interleaved_by_the_api() {
    let code = fixture("aarch64.text.bin");
    let even: Vec<u8> = code.iter().step_by(2).copied().collect();
    let odd: Vec<u8> = code.iter().skip(1).step_by(2).copied().collect();
    let p = detect_interleaved(&[&even, &odd], &ClassifierOptions::new()).unwrap();
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.starts_with("Interleaved from 2 byte lanes")));
    assert!(detect_interleaved(&[&even, &odd[1..]], &ClassifierOptions::new()).is_err());
}

#[test]
fn fast_mode_and_nested_inputs_do_not_search_transforms() {
    let swapped = Transform::Swap16
        .apply(&fixture("aarch64.text.bin"))
        .unwrap();
    let fast = ClassifierOptions {
        min_confidence: 0.3,
        ..ClassifierOptions::fast()
    };
    if let Ok(p) = detect_payload(&swapped, &fast) {
        assert_eq!(transform_name(&p), None);
    }
}

#[test]
fn noise_stays_inconclusive_after_every_transform() {
    for (seed, len) in [
        (1u64, 4096usize),
        (7, 16 * 1024),
        (99, 64 * 1024),
        (12345, 2048 * 4 + 64 * 4),
    ] {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let noise: Vec<u8> = (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        assert!(
            matches!(
                detect_payload(&noise, &ClassifierOptions::new()),
                Err(ClassifierError::HeuristicInconclusive { .. })
            ),
            "noise {seed}/{len}"
        );
    }
}

#[test]
fn one_trial_matches_the_plain_analysis() {
    let code = fixture("riscv64.text.bin");
    let options = ClassifierOptions::new();
    let plain = heuristics::analyze_detailed(&code, &options).0.unwrap();
    let single = heuristics::analyze_detailed_with_trials(&code, &options, 1)
        .0
        .unwrap();
    assert_eq!(
        (plain.isa, plain.confidence),
        (single.isa, single.confidence)
    );
    let many = heuristics::analyze_detailed_with_trials(&code, &options, 1 << 20)
        .0
        .unwrap();
    assert!(many.confidence <= plain.confidence);
}

/// uImage header (big-endian): magic, header CRC, size, load/entry, data
/// CRC, OS Linux, architecture AArch64 (22), kernel, no compression.
fn uimage(payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    data[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    data[24..28].copy_from_slice(&crc32(payload).to_be_bytes());
    data[0x1c..0x20].copy_from_slice(&[5, 22, 2, 0]);
    let header_crc = crc32(&data);
    data[4..8].copy_from_slice(&header_crc.to_be_bytes());
    data.extend_from_slice(payload);
    data
}

/// A NAND read: every 2048 data bytes followed by 64 spare bytes (bad-block
/// marker 0xFF, then ECC-like bytes).
fn with_spare(image: &[u8]) -> Vec<u8> {
    let mut padded = image.to_vec();
    padded.resize((image.len() + 2047) / 2048 * 2048, 0xff);
    let mut dump = Vec::new();
    for (i, page) in padded.chunks(2048).enumerate() {
        dump.extend_from_slice(page);
        dump.push(0xff);
        dump.extend((1..64).map(|j| (i * 31 + j * 7) as u8));
    }
    dump
}

#[test]
fn a_nand_dump_of_a_container_parses_after_spare_removal() {
    let image = uimage(&fixture("aarch64.text.bin"));
    let dump = with_spare(&image);
    assert!(detect_payload(
        &dump,
        &ClassifierOptions {
            try_transforms: false,
            ..ClassifierOptions::new()
        }
    )
    .is_err());
    let p = detect_payload(&dump, &ClassifierOptions::new()).unwrap();
    assert_eq!(p.format.format, FileFormat::UImage);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(
        transform_name(&p).as_deref(),
        Some("NAND spare removal (2048+64 B pages)")
    );
    let slice = &p.slices[0];
    // The kernel starts at 64 in the image and spans three pages of the dump.
    assert_eq!(slice.offset, 64);
    assert_eq!(slice.decoded.as_ref().unwrap().offset, 64);
    assert!(slice.size > slice.decoded.as_ref().unwrap().size);
}

#[test]
fn every_candidate_transform_is_bounded_and_invertible_in_length() {
    let code = fixture("aarch64.text.bin");
    for &t in transform::CANDIDATES {
        if let Some(out) = t.apply(&code) {
            assert!(out.len() <= code.len(), "{}", t.name());
        }
    }
}
