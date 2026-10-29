//! UARP structural recognition, packed metadata TLVs and nested firmware.

use zrax::formats::{container::Kind, detect_format, uarp, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, FileFormat, Isa};

struct Entry<'a> {
    tag: &'a [u8; 4],
    payload: &'a [u8],
}

fn entry<'a>(tag: &'a [u8; 4], payload: &'a [u8]) -> Entry<'a> {
    Entry { tag, payload }
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

/// A packed TLV: type 0x1234, big-endian byte length, then value, without
/// alignment padding. A three-byte value exercises the unaligned next TLV.
fn tlv() -> Vec<u8> {
    let mut data = vec![0, 0, 0x12, 0x34, 0, 0, 0, 3, 1, 2, 3];
    data.extend_from_slice(&[0, 0, 0x12, 0x35, 0, 0, 0, 0]);
    data
}

/// Binary plist: raw object bytes, one-byte offsets/references, root 0,
/// then an offset table and 32-byte trailer (six reserved bytes, widths,
/// big-endian object count/root/table offset). Objects here fit below 256 B.
fn binary_plist(objects: &[&[u8]]) -> Vec<u8> {
    let mut data = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for object in objects {
        offsets.push(u8::try_from(data.len()).unwrap());
        data.extend_from_slice(object);
    }
    let table = data.len();
    data.extend_from_slice(&offsets);
    data.extend_from_slice(&[0; 6]);
    data.extend_from_slice(&[1, 1]);
    data.extend_from_slice(&u64::try_from(objects.len()).unwrap().to_be_bytes());
    data.extend_from_slice(&0u64.to_be_bytes());
    data.extend_from_slice(&u64::try_from(table).unwrap().to_be_bytes());
    data
}

#[test]
fn property_list_members_and_trailers_remain_opaque() {
    // Array of bool, integer, real, date, data, ASCII, UTF-16 and UID.
    let plist = binary_plist(&[
        &[0xa8, 1, 2, 3, 4, 5, 6, 7, 8],
        &[0x09],
        &[0x10, 5],
        &[0x22, 0, 0, 0, 0],
        &[0x33, 0, 0, 0, 0, 0, 0, 0, 0],
        &[0x42, 1, 2],
        &[0x51, b'a'],
        &[0x61, 0, b'b'],
        &[0x80, 1],
    ]);
    let mut data = image(&[entry(b"TMAP", &plist), entry(b"CTAB", &[0; 16])], &[]);
    data.extend_from_slice(&plist);
    let parsed = uarp::parse_container(&data).unwrap();
    assert_eq!(parsed.children.len(), 3);
    assert!(parsed.children.iter().all(|child| child.opaque));
    assert!(uarp::detect(&data));
    for end in 0..plist.len() {
        let data = image(&[entry(b"TMAP", &plist[..end])], &[]);
        // Partial magic alone is not evidence of a property list.
        if end >= 8 {
            assert!(uarp::parse_container(&data).is_err(), "plist prefix {end}");
        }
    }
    for offset in 0..plist.len() {
        for value in [0, 0xff, plist[offset] ^ 0x80] {
            let mut mutated = plist.clone();
            mutated[offset] = value;
            let _ = uarp::parse_container(&image(&[entry(b"TMAP", &mutated)], &[]));
        }
    }
    let bad_reference = binary_plist(&[&[0xa1, 2], &[0x09]]);
    assert!(uarp::parse_container(&image(&[entry(b"TMAP", &bad_reference)], &[])).is_err());
    let cyclic = binary_plist(&[&[0xa1, 0]]);
    assert!(uarp::parse_container(&image(&[entry(b"TMAP", &cyclic)], &[])).is_ok());
}

/// UARP format version 3, fixed 44-byte header, four-part version 1.2.3.4;
/// table immediately follows. Each 40-byte record holds a raw tag, version
/// 5.6.7.8, absolute metadata and payload byte ranges. Identical metadata is
/// stored independently at the global level and for each payload.
fn image(entries: &[Entry<'_>], metadata: &[u8]) -> Vec<u8> {
    let table_end = 44 + entries.len() * 40;
    let mut data = vec![0; table_end];
    put_u32(&mut data, 0, 3);
    put_u32(&mut data, 4, 44);
    for index in 0..4 {
        put_u32(&mut data, 12 + 4 * index, u32::try_from(index + 1).unwrap());
    }
    put_u32(&mut data, 28, u32::try_from(table_end).unwrap());
    put_u32(&mut data, 32, u32::try_from(metadata.len()).unwrap());
    put_u32(&mut data, 36, 44);
    put_u32(&mut data, 40, u32::try_from(entries.len() * 40).unwrap());
    data.extend_from_slice(metadata);
    for (index, entry) in entries.iter().enumerate() {
        let tag = entry.tag;
        let payload = entry.payload;
        let record = 44 + index * 40;
        put_u32(&mut data, record, 40);
        data[record + 4..record + 8].copy_from_slice(tag);
        for version_index in 0..4 {
            put_u32(
                &mut data,
                record + 8 + version_index * 4,
                u32::try_from(version_index + 5).unwrap(),
            );
        }
        let offset = u32::try_from(data.len()).unwrap();
        put_u32(&mut data, record + 24, offset);
        put_u32(
            &mut data,
            record + 28,
            u32::try_from(metadata.len()).unwrap(),
        );
        data.extend_from_slice(metadata);
        let offset = u32::try_from(data.len()).unwrap();
        put_u32(&mut data, record + 32, offset);
        put_u32(
            &mut data,
            record + 36,
            u32::try_from(payload.len()).unwrap(),
        );
        data.extend_from_slice(payload);
    }
    let size = u32::try_from(data.len()).unwrap();
    put_u32(&mut data, 8, size);
    data
}

#[test]
fn complete_structure_is_weak_evidence_and_payload_supplies_the_isa() {
    let payload = include_bytes!("fixtures/apple/kernel.macho");
    let data = image(&[entry(b"CODE", payload)], &tlv());
    assert!(uarp::detect(&data));
    assert!(matches!(
        detect_format(&data),
        DetectedFormat::Container { kind: Kind::Uarp }
    ));
    assert!(Kind::Uarp.is_weak());
    let result = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert_eq!(result.format.format, FileFormat::Uarp);
    assert_eq!(result.primary.isa, Isa::AArch64);
    let child = result
        .slices
        .iter()
        .find(|child| child.label.as_deref() == Some("CODE"))
        .unwrap();
    assert_eq!(child.offset, 44 + 40 + 2 * 19);
    assert_eq!(child.size, payload.len() as u64);
    assert_eq!(
        uarp::parse_container(&data)
            .unwrap()
            .metadata
            .iter()
            .filter(|entry| entry.label.starts_with("TLV"))
            .count(),
        4
    );
}

#[test]
fn header_and_metadata_never_become_code_for_empty_payloads() {
    let mut data = image(&[entry(b"NONE", b"")], &tlv());
    // Empty payloads ignore their unused byte offset.
    put_u32(&mut data, 44 + 32, u32::MAX);
    let result = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert_eq!(result.format.format, FileFormat::Uarp);
    assert!(matches!(result.primary.isa, Isa::Unknown(_)));
    assert_eq!(result.primary.confidence, 0.0);
    assert!(result.slices.is_empty());
    // A header with zero payload records has insufficient structural evidence.
    assert!(!uarp::detect(&image(&[], &[])));
}

#[test]
fn nested_img4_and_ftab_members_classify_independently() {
    let im4p = include_bytes!("fixtures/apple/krnl.bvx2.im4p");
    let mut ftab = vec![0; 0x40];
    ftab[0x20..0x28].copy_from_slice(b"rkosftab");
    ftab[0x28..0x2c].copy_from_slice(&1u32.to_le_bytes());
    ftab[0x30..0x34].copy_from_slice(b"krnl");
    ftab[0x34..0x38].copy_from_slice(&0x40u32.to_le_bytes());
    ftab[0x38..0x3c].copy_from_slice(&u32::try_from(im4p.len()).unwrap().to_le_bytes());
    ftab.extend_from_slice(im4p);
    let data = image(&[entry(b"FTAB", &ftab), entry(b"IM4P", im4p)], &[]);
    let result = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert_eq!(result.format.format, FileFormat::Uarp);
    assert_eq!(result.primary.isa, Isa::AArch64);
    for label in ["FTAB", "IM4P"] {
        assert_eq!(
            result
                .slices
                .iter()
                .find(|child| child.label.as_deref() == Some(label))
                .unwrap()
                .isa,
            Isa::AArch64
        );
    }
}

#[test]
fn every_truncation_is_rejected_and_never_detected_as_uarp() {
    let data = image(&[entry(b"CODE", &[1; 16])], &tlv());
    for end in 0..data.len() {
        assert!(
            uarp::parse_container(&data[..end]).is_err(),
            "end 0x{end:X}"
        );
        assert!(!uarp::detect(&data[..end]));
    }
}

#[test]
fn corrupt_fields_regions_and_tlvs_are_rejected() {
    let original = image(&[entry(b"CODE", &[1; 16])], &tlv());
    for (offset, value) in [
        (4, 40),
        (8, 43),
        (8, u32::MAX),
        (36, 4),
        (40, 41),
        (40, u32::MAX),
        (44, 44),
        (44 + 32, 0),
        (44 + 36, u32::MAX),
        (84 + 4, u32::MAX),
        (32, 7),
        (44 + 28, 7),
    ] {
        let mut data = original.clone();
        put_u32(&mut data, offset, value);
        assert!(
            uarp::parse_container(&data).is_err(),
            "field 0x{offset:X} = 0x{value:X}"
        );
        assert!(!uarp::detect(&data));
    }
    // Even when physical bytes exist, a payload cannot extend beyond the
    // declared super-binary extent.
    let mut short = original.clone();
    put_u32(&mut short, 8, u32::try_from(original.len() - 1).unwrap());
    assert!(uarp::parse_container(&short).is_err());
    let mut trailer = original;
    trailer.push(1);
    assert!(uarp::parse_container(&trailer).is_err());
    *trailer.last_mut().unwrap() = 0xff;
    assert!(uarp::parse_container(&trailer).is_ok());
}

#[test]
fn byte_mutations_and_excessive_counts_are_bounded() {
    let original = image(&[entry(b"CODE", &[1; 16])], &tlv());
    for offset in 0..original.len() {
        for value in [0, 0xff, original[offset] ^ 0x80] {
            let mut data = original.clone();
            data[offset] = value;
            let _ = uarp::parse_container(&data);
            let _ = uarp::detect(&data);
        }
    }
    let mut data = vec![0; 44 + 4097 * 40];
    let len = u32::try_from(data.len()).unwrap();
    put_u32(&mut data, 4, 44);
    put_u32(&mut data, 8, len);
    put_u32(&mut data, 36, 44);
    put_u32(&mut data, 40, 4097 * 40);
    assert!(uarp::parse_container(&data)
        .unwrap_err()
        .to_string()
        .contains("limit 4096"));
    let tlvs = [0; 8 * 4097];
    let data = image(&[entry(b"CODE", &[1; 4])], &tlvs);
    assert!(uarp::parse_container(&data)
        .unwrap_err()
        .to_string()
        .contains("TLV count"));
}

#[test]
#[ignore = "requires a locally supplied UARP_FIXTURE; no firmware is committed"]
fn external_uarp_fixture_preserves_exact_member_ranges() {
    let path = std::env::var_os("UARP_FIXTURE").expect("set UARP_FIXTURE");
    let data = std::fs::read(path).unwrap();
    let parsed = uarp::parse_container(&data).unwrap();
    assert!(!parsed.children.is_empty());
    assert!(uarp::detect(&data));
    for child in parsed.children {
        assert_eq!(
            &*child.data,
            &data[child.offset..child.offset + child.stored_size]
        );
        if zrax::formats::ftab::detect(&child.data) {
            let table = zrax::formats::ftab::parse_container(&child.data).unwrap();
            assert!(!table.children.is_empty());
            for member in table.children {
                assert_eq!(
                    &*member.data,
                    &child.data[member.offset..member.offset + member.stored_size]
                );
            }
        }
    }
    let result = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert_eq!(result.format.format, FileFormat::Uarp);
}
