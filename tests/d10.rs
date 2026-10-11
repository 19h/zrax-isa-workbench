use zrax::{
    detect_bytes, detect_payload,
    formats::{self, d10},
    ClassificationSource, ClassifierError, ClassifierOptions, Endianness, FileFormat,
    HumanFormatter, Isa, JsonFormatter, MetadataKey, MetadataValue, PayloadFormatter,
};
use std::path::Path;

// Independent bitwise checksum writer, rather than the parser's table routine.
fn finish(mut data: Vec<u8>) -> Vec<u8> {
    let mut crc = 0xffffu16;
    for &b in &data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x8408 } else { 0 };
        }
    }
    data.extend_from_slice(&(crc ^ 0xffff).to_le_bytes());
    data
}

fn record(out: &mut Vec<u8>, section: u8, block: u8, address: u32, bytes: &[u8]) {
    out.extend_from_slice(&[section, block]);
    out.extend_from_slice(&address.to_be_bytes());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn encode(bytes: &mut [u8]) {
    let key = hex::decode("4191e5094ea2fa226bc31f4b98f45484d53599cd2286ee267fe7538fec58c80869d94d91f66ae22a930b87d340bc3c8cfd7d0155ca4ed62ea72fbb179420b0109121b5199e32ca32bb53ef5be884249425c569dd7216be36cf77239f3ce89818b9691da146fab23ae39b57e3904c0c9c4d0dd1651adea63ef7bf8b27e4b08020").unwrap();
    for (i, b) in bytes.iter_mut().enumerate() {
        *b ^= key[i % 128];
    }
}

fn code() -> Vec<u8> {
    [
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75,
        0xf0, 0x48, 0x8b, 0x45, 0xf8, 0x48, 0x03, 0x45, 0xf0, 0x66, 0x0f, 0x38, 0xdc, 0xc1, 0x48,
        0x89, 0xec, 0x5d, 0xc3,
    ]
    .repeat(512)
}

fn firmware(cpu: &[u8], encrypted: bool, dsp: &[u8]) -> Vec<u8> {
    let mut data = b"2504B     000243".to_vec();
    for section in 0..5 {
        record(
            &mut data,
            section,
            0,
            0x10_0000 + u32::from(section) * 0x4_0000,
            if section == 1 { dsp } else { &[] },
        );
        record(
            &mut data,
            section,
            1,
            0x10_0000 + u32::from(section) * 0x4_0000 + 0x3_ffea,
            b"ardv10DSP2504B\0\0\0\0\0\0\0\0\0",
        );
    }
    let mut cpu = cpu.to_vec();
    if encrypted {
        encode(&mut cpu);
    }
    record(&mut data, 5, 0, 0x38_0100, &cpu);
    let mut vectors = vec![0xff; if encrypted { 272 } else { 128 }];
    if encrypted {
        vectors[127] = 0;
        vectors[128..256].copy_from_slice(&(0..128).collect::<Vec<u8>>());
        encode(&mut vectors[128..256]);
    }
    record(&mut data, 5, 1, 0x3f_ff80, &vectors);
    finish(data)
}

fn fix_crc(data: &mut Vec<u8>) {
    data.truncate(data.len() - 2);
    *data = finish(std::mem::take(data));
}

#[test]
fn checksum_matches_reference_check_value() {
    assert_eq!(d10::checksum(b"123456789"), 0x906e);
}

#[test]
fn plain_records_preserve_addresses_offsets_and_empty_slots() {
    let data = firmware(&code(), false, &[]);
    assert!(matches!(
        formats::detect_format(&data),
        formats::DetectedFormat::D10
    ));
    let f = d10::parse_container(&data).unwrap();
    assert_eq!(f.revision, "2504B     000243");
    assert!(!f.cpu_encrypted);
    assert_eq!(f.blocks.len(), 12);
    assert_eq!(f.block(0, 0).unwrap().offset, 26);
    assert!(f.block(3, 0).unwrap().data.is_empty());
    assert_eq!(f.block(5, 0).unwrap().flash_address, 0x380100);
    assert_eq!(f.cpu_code().as_ref(), code());
    assert_eq!(f.cpu_vectors().as_ref(), vec![0xff; 128]);
    assert_eq!(d10::parse(&data).unwrap().metadata.section_count, Some(12));
    assert_eq!(f.metadata().len(), 15);
}

#[test]
fn encrypted_code_and_vector_tail_match_reference_key() {
    let code: Vec<u8> = (0..1027).map(|i| i as u8).collect();
    let data = firmware(&code, true, &[]);
    let f = d10::parse_container(&data).unwrap();
    assert!(f.cpu_encrypted);
    assert_eq!(f.cpu_code().as_ref(), code);
    let vectors = f.cpu_vectors();
    assert_eq!(&vectors[..127], &[0xff; 127]);
    assert_eq!(vectors[127], 0);
    assert_eq!(&vectors[128..256], &(0..128).collect::<Vec<u8>>());
    assert_eq!(&vectors[256..], &[0xff; 16]);
    assert_ne!(f.block(5, 0).unwrap().data, f.cpu_code().as_ref());
}

#[test]
fn cpu_classification_candidates_and_extensions_ignore_container_encoding() {
    let code = code();
    let raw = detect_bytes(&code).unwrap();
    assert_eq!(raw.primary.isa, Isa::X86_64);
    let mut plain_json = None;
    for encrypted in [false, true] {
        let data = firmware(&code, encrypted, &[]);
        let p = detect_bytes(&data).unwrap();
        assert_eq!(p.format.format, FileFormat::D10);
        assert_eq!(p.primary.isa, raw.primary.isa);
        assert_eq!(p.primary.confidence, raw.primary.confidence);
        assert_eq!(p.primary.source, ClassificationSource::Combined);
        assert_eq!(p.primary.endianness, Endianness::Little);
        assert_eq!(
            serde_json::to_value(&p.candidates).unwrap(),
            serde_json::to_value(&raw.candidates).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&p.extensions).unwrap(),
            serde_json::to_value(&raw.extensions).unwrap()
        );
        assert_eq!(p.slices[0].label.as_deref(), Some("CPU 5:0"));
        assert_eq!(
            &data[p.slices[0].offset as usize..][..p.slices[0].size as usize],
            d10::parse_container(&data)
                .unwrap()
                .block(5, 0)
                .unwrap()
                .data
        );
        assert!(p
            .metadata
            .iter()
            .any(|m| matches!(m.key, MetadataKey::CodeSize)
                && matches!(m.value, MetadataValue::Integer(n) if n == code.len() as u64)));
        let value = serde_json::to_value(&p.extensions).unwrap();
        if encrypted {
            assert_eq!(Some(value), plain_json);
        } else {
            plain_json = Some(value);
        }
    }
}

#[test]
fn dsp_payload_has_separate_label_range_and_architecture() {
    let data = firmware(&vec![0; 4096], false, &code());
    let p = detect_bytes(&data).unwrap();
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    assert_eq!(p.primary.confidence, 0.0);
    assert!(p.candidates.is_empty());
    assert_eq!(p.slices.len(), 2);
    assert_eq!(p.slices[1].label.as_deref(), Some("DSP 1:0"));
    assert_eq!(p.slices[1].isa, Isa::X86_64);
    let f = d10::parse_container(&data).unwrap();
    assert_eq!(p.slices[1].offset, f.block(1, 0).unwrap().offset as u64);
    let json: serde_json::Value =
        serde_json::from_str(&JsonFormatter::new().format_payload(&p, Path::new("test.D10")))
            .unwrap();
    assert_eq!(json["slices"][1]["label"], "DSP 1:0");
    assert_eq!(json["slices"][1]["isa"], "x86_64");
    assert!(HumanFormatter::new()
        .format_payload(&p, Path::new("test.D10"))
        .contains(&format!("DSP 1:0: {}", Isa::X86_64)));
}

#[test]
fn corrupt_crc_is_an_error_without_raw_fallback() {
    let mut data = firmware(&code(), false, &[]);
    let last = data.len() - 1;
    data[last] ^= 1;
    assert!(d10::detect(&data));
    assert!(matches!(
        detect_bytes(&data),
        Err(ClassifierError::InvalidChecksum { .. })
    ));
}

#[test]
fn duplicate_and_invalid_record_ids_are_rejected() {
    for (section, block, expected) in [(0, 0, "Duplicate"), (6, 0, "Invalid"), (0, 2, "Invalid")] {
        let mut data = firmware(&code(), false, &[]);
        // Record 0:0 is empty; next header begins at 26.
        data[26] = section;
        data[27] = block;
        fix_crc(&mut data);
        assert!(d10::parse_container(&data)
            .unwrap_err()
            .to_string()
            .contains(expected));
    }
}

#[test]
fn oversized_payload_and_flash_range_are_rejected() {
    let mut data = firmware(&code(), false, &[]);
    data[22..26].copy_from_slice(&u32::MAX.to_be_bytes());
    fix_crc(&mut data);
    assert!(d10::parse_container(&data)
        .unwrap_err()
        .to_string()
        .contains("Truncated payload"));
    let mut data = firmware(&code(), false, &[]);
    data[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
    fix_crc(&mut data);
    assert!(d10::parse_container(&data)
        .unwrap_err()
        .to_string()
        .contains("Flash range"));
}

#[test]
fn truncated_headers_and_payloads_never_panic() {
    let data = firmware(&code(), true, &[]);
    for size in (0..160).chain([data.len() - 3, data.len() - 1]) {
        assert!(d10::parse_container(&data[..size]).is_err());
    }
    let mut trailing = data[..data.len() - 2].to_vec();
    trailing.push(1);
    assert!(d10::parse_container(&finish(trailing))
        .unwrap_err()
        .to_string()
        .contains("Truncated record header"));
}

#[test]
fn missing_cpu_and_short_vector_records_are_rejected() {
    let mut header = b"2504B     000243".to_vec();
    record(&mut header, 0, 0, 0x200000, &[]);
    assert!(d10::parse_container(&finish(header))
        .unwrap_err()
        .to_string()
        .contains("Missing CPU"));
    for (length, encrypted) in [(127, false), (128, true), (255, true)] {
        let mut data = b"2504B     000243".to_vec();
        record(&mut data, 5, 0, 0x380100, &code());
        let mut vectors = vec![0xff; length];
        if encrypted {
            vectors[127] = 0;
        }
        record(&mut data, 5, 1, 0x3fff80, &vectors);
        assert!(d10::parse_container(&finish(data))
            .unwrap_err()
            .to_string()
            .contains("shorter"));
    }
}

#[test]
fn records_can_be_reordered_without_changing_payloads() {
    let data = firmware(&code(), true, &[]);
    let f = d10::parse_container(&data).unwrap();
    let mut out = data[..16].to_vec();
    for b in f.blocks.iter().rev() {
        record(&mut out, b.section, b.block, b.flash_address, b.data);
    }
    let reordered = finish(out);
    assert!(d10::detect(&reordered));
    let g = d10::parse_container(&reordered).unwrap();
    assert_eq!(g.cpu_code(), f.cpu_code());
    assert_eq!(g.cpu_vectors(), f.cpu_vectors());
}

#[test]
fn disabling_extensions_applies_to_cpu_and_dsp() {
    let data = firmware(&code(), true, &code());
    let p = detect_payload(
        &data,
        &ClassifierOptions {
            detect_extensions: false,
            ..ClassifierOptions::new()
        },
    )
    .unwrap();
    assert!(p.extensions.is_empty());
    assert!(p.slices.iter().all(|s| s.extensions.is_empty()));
}

#[test]
fn revision_text_alone_is_not_a_d10_signature() {
    assert!(!d10::detect(b"2504B     000243 text follows"));
    assert!(!d10::detect(b"2504B     000243"));
}

#[test]
#[ignore = "Requires D10_FIXTURE and D10_REFERENCE_DIR generated by the supplied Python extractor"]
fn supplied_extractor_matches_every_component_byte() {
    let fixture = std::env::var("D10_FIXTURE").unwrap();
    let directory = std::env::var("D10_REFERENCE_DIR").unwrap();
    let data = std::fs::read(&fixture).unwrap();
    let f = d10::parse_container(&data).unwrap();
    for block in &f.blocks {
        let expected = std::fs::read(Path::new(&directory).join(format!("{}-{}.bin", block.section, block.block))).unwrap();
        let decoded = match (block.section, block.block) {
            (5, 0) => f.cpu_code(), (5, 1) => f.cpu_vectors(),
            _ => std::borrow::Cow::Borrowed(block.data),
        };
        assert_eq!(decoded.as_ref(), expected, "Record {}:{}", block.section, block.block);
    }
    let p = detect_bytes(&data).unwrap();
    assert_eq!(p.primary.isa, Isa::Rx);
    assert_eq!(p.slices.iter().map(|s| s.isa).collect::<Vec<_>>(), vec![Isa::Rx, Isa::Blackfin, Isa::Blackfin]);
    println!("{}: {} B, revision {}, CPU encoded {}, all {} reference records match", fixture, data.len(), f.revision, f.cpu_encrypted, f.blocks.len());
}
