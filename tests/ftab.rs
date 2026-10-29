//! FTAB bounds, diagnostics, placeholders and independent nested classification.

use zrax::formats::{container::Kind, detect_format, ftab, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, FileFormat, Isa};

struct Entry<'a> {
    tag: &'a [u8; 4],
    payload: &'a [u8],
}

fn entry<'a>(tag: &'a [u8; 4], payload: &'a [u8]) -> Entry<'a> {
    Entry { tag, payload }
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Header: generation 1, valid all-ones, zero nonce/reserved words; magic at
/// 0x20, count at 0x28. Sixteen-byte records hold tag, absolute byte offset,
/// byte size and a zero reserved word. Payloads start immediately after the
/// table and are individually aligned to four bytes.
fn image(magic: &[u8; 8], entries: &[Entry<'_>]) -> Vec<u8> {
    let mut data = vec![0; 0x30 + entries.len() * 16];
    put_u32(&mut data, 0, 1);
    put_u32(&mut data, 4, u32::MAX);
    data[0x20..0x28].copy_from_slice(magic);
    put_u32(&mut data, 0x28, u32::try_from(entries.len()).unwrap());
    for (index, entry) in entries.iter().enumerate() {
        let tag = entry.tag;
        let payload = entry.payload;
        let record = 0x30 + index * 16;
        data[record..record + 4].copy_from_slice(tag);
        let offset = u32::try_from(data.len()).unwrap();
        put_u32(&mut data, record + 4, offset);
        put_u32(&mut data, record + 8, u32::try_from(payload.len()).unwrap());
        data.extend_from_slice(payload);
        data.resize((data.len() + 3) & !3, 0);
    }
    data
}

#[test]
fn both_magics_classify_payload_bytes_and_keep_the_container_format() {
    let payload = include_bytes!("fixtures/apple/kernel.macho");
    for magic in [b"rkosftab", b"RKOSFTAB"] {
        let data = image(magic, &[entry(b"krnl", payload)]);
        assert!(matches!(
            detect_format(&data),
            DetectedFormat::Container { kind: Kind::Ftab }
        ));
        let result = detect_payload(&data, &ClassifierOptions::new()).unwrap();
        assert_eq!(result.format.format, FileFormat::Ftab);
        assert_eq!(result.primary.isa, Isa::AArch64);
        let child = result
            .slices
            .iter()
            .find(|child| child.label.as_deref() == Some("krnl"))
            .unwrap();
        assert_eq!(child.offset, 0x40);
        assert_eq!(child.size, payload.len() as u64);
    }
}

#[test]
fn empty_tables_and_placeholder_offsets_do_not_become_code() {
    let empty = image(b"rkosftab", &[]);
    let mut placeholder = image(b"rkosftab", &[entry(b"rkos", b"")]);
    put_u32(&mut placeholder, 0x34, u32::MAX);
    for data in [empty, placeholder] {
        let result = detect_payload(&data, &ClassifierOptions::new()).unwrap();
        assert!(matches!(result.primary.isa, Isa::Unknown(_)));
        assert_eq!(result.primary.confidence, 0.0);
        assert!(result.slices.is_empty());
    }
}

#[test]
fn manifests_are_opaque_and_unverified_even_with_executable_bytes() {
    let payload = include_bytes!("fixtures/apple/kernel.macho");
    let mut data = image(b"rkosftab", &[]);
    put_u32(&mut data, 0x10, 0x30);
    put_u32(&mut data, 0x14, u32::try_from(payload.len()).unwrap());
    data.extend_from_slice(payload);
    let parsed = ftab::parse_container(&data).unwrap();
    assert!(parsed.children[0].opaque);
    assert!(parsed
        .notes
        .iter()
        .any(|note| note.contains("signature not verified")));
    let result = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert!(matches!(result.primary.isa, Isa::Unknown(_)));
}

#[test]
fn members_can_be_nested_ftab_or_compressed_images() {
    let payload = include_bytes!("fixtures/apple/krnl.bvx2.im4p");
    let inner = image(b"RKOSFTAB", &[entry(b"krnl", payload)]);
    let data = image(b"rkosftab", &[entry(b"nest", &inner)]);
    let result = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert_eq!(result.format.format, FileFormat::Ftab);
    assert_eq!(result.primary.isa, Isa::AArch64);
}

#[test]
fn duplicate_tags_overlaps_alignment_and_reserved_words_are_diagnostics() {
    let mut data = image(
        b"rkosftab",
        &[entry(b"same", &[1; 16]), entry(b"same", &[2; 4])],
    );
    // Entry 1 starts inside entry 0 and is deliberately unaligned.
    put_u32(&mut data, 0x44, 0x51);
    put_u32(&mut data, 0x18, 1);
    put_u32(&mut data, 0x4c, 2);
    // The original entry 1 now lies after the occupied extent: padding only.
    data[0x60..].fill(0);
    let parsed = ftab::parse_container(&data).unwrap();
    for needle in [
        "Duplicate FTAB tag",
        "overlap",
        "not 4-byte aligned",
        "reserved word",
    ] {
        assert!(
            parsed.notes.iter().any(|note| note.contains(needle)),
            "{needle}: {:?}",
            parsed.notes
        );
    }
}

#[test]
fn every_truncation_of_an_occupied_image_is_rejected() {
    let data = image(b"rkosftab", &[entry(b"test", &[1; 16])]);
    for end in 0..data.len() {
        assert!(
            ftab::parse_container(&data[..end]).is_err(),
            "end 0x{end:X}"
        );
    }
    assert!(ftab::detect(&data[..0x28]));
    assert!(detect_payload(&data[..0x28], &ClassifierOptions::new())
        .unwrap_err()
        .to_string()
        .starts_with("FTAB parse error:"));
}

#[test]
fn invalid_counts_ranges_and_trailers_are_rejected() {
    let original = image(b"rkosftab", &[entry(b"test", &[1; 16])]);
    for (offset, value) in [
        (0x28, u32::MAX),
        (0x34, u32::MAX),
        (0x38, u32::MAX),
        (0x34, 0x30),
        (0x14, 1000),
    ] {
        let mut data = original.clone();
        put_u32(&mut data, offset, value);
        assert!(ftab::parse_container(&data).is_err(), "field 0x{offset:X}");
    }
    let mut trailer = original.clone();
    trailer.push(1);
    assert!(ftab::parse_container(&trailer).is_err());
    let mut wrong_case = original;
    wrong_case[0x20] = b'R';
    assert!(!ftab::detect(&wrong_case));
    assert!(ftab::parse_container(&wrong_case).is_err());
}

#[test]
fn mutations_and_resource_limits_are_bounded() {
    let original = image(b"rkosftab", &[entry(b"test", &[1; 16])]);
    for offset in 0..original.len() {
        for value in [0, 0xff, original[offset] ^ 0x80] {
            let mut data = original.clone();
            data[offset] = value;
            let _ = ftab::parse_container(&data);
        }
    }
    let mut data = vec![0; 0x30 + 4097 * 16];
    data[0x20..0x28].copy_from_slice(b"rkosftab");
    put_u32(&mut data, 0x28, 4097);
    assert!(ftab::parse_container(&data)
        .unwrap_err()
        .to_string()
        .contains("limit 4096"));
}
