//! C55x boot-table behavior, address units and malformed-input regressions.
use zrax::formats::{self, ti_c55x, DetectedFormat};
use zrax::{
    classify_bytes_with_options, detect_payload, ClassificationSource, ClassifierOptions,
    Endianness, FileFormat, Isa, MetadataKey, MetadataValue,
};

// Two records from the SPRABL7D Table 2 layout: one word at word address 0x7e
// with nonzero padding, then four words at 0x100 with two padding words.
// The odd byte entry 0x201 maps to file offset 0x19, not word address 0x201.
fn table() -> Vec<u8> {
    vec![
        0x09, 0xaa, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7e, 0x1c,
        0xce, 0x20, 0x20, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x46, 0xb3, 0xe6, 0x00, 0x00, 0x98,
        0xe6, 0x8a, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00,
    ]
}

#[test]
fn ti_c55x_table_uses_word_loads_byte_entry_and_per_record_padding() {
    let data = table();
    let c = ti_c55x::parse_container(&data).unwrap();
    assert_eq!(c.entry_point, 0x201);
    assert_eq!(c.image_size, 38);
    assert!(c.register_configs.is_empty());
    assert_eq!(
        c.sections
            .iter()
            .map(|s| (s.offset, s.word_address, s.data.len()))
            .collect::<Vec<_>>(),
        [(14, 0x7e, 2), (24, 0x100, 8)]
    );
    assert_eq!(c.entry_file_offset(), Some(25));
    assert_eq!(c.sections[0].data, &[0x1c, 0xce]);
    assert_eq!(c.sections[1].data, &data[24..32]);
    assert!(matches!(
        formats::detect_format(&data),
        DetectedFormat::TiC55xBoot
    ));
    let r = formats::parse_detected(&data, &DetectedFormat::TiC55xBoot).unwrap();
    assert_eq!(r.isa, Isa::TiC5500);
    assert_eq!(r.bitwidth, 16);
    assert_eq!(r.endianness, Endianness::Big);
    assert_eq!(r.metadata.code_size, None); // The format does not distinguish code/data.
}

#[test]
fn ti_c55x_public_apis_preserve_format_and_metadata_in_all_modes() {
    for options in [
        ClassifierOptions::fast(),
        ClassifierOptions::new(),
        ClassifierOptions::thorough(),
    ] {
        let p = detect_payload(&table(), &options).unwrap();
        let r = classify_bytes_with_options(&table(), &options).unwrap();
        assert_eq!(p.format.format, FileFormat::TiC55xBoot);
        assert_eq!(r.format, p.format.format);
        assert_eq!(r.isa, p.primary.isa);
        assert_eq!(p.primary.source, ClassificationSource::FileFormat);
        assert!(p.primary.variant.is_none()); // No exact device is encoded.
        assert!(p.candidates.is_empty());
        assert!(p.metadata.iter().any(|m| m.key == MetadataKey::EntryPoint
            && matches!(m.value, MetadataValue::Address(0x201))));
        assert!(p
            .metadata
            .iter()
            .any(|m| m.key == MetadataKey::SectionCount
                && matches!(m.value, MetadataValue::Integer(2))));
        assert!(p
            .metadata
            .iter()
            .any(|m| m.label == "Entry point file offset (B)"
                && matches!(m.value, MetadataValue::Address(25))));
        let serialized = serde_json::to_value(&p).unwrap();
        assert_eq!(serialized["format"]["format"], "tic55xboot");
        assert_eq!(serialized["primary"]["isa"], "ti_c5500");
    }
}

#[test]
fn ti_c55x_register_configuration_and_delays_shift_record_offsets() {
    let mut data = table();
    data[6..8].copy_from_slice(&2u16.to_be_bytes());
    data.splice(8..8, [0x1c, 0x8c, 0x00, 0x01, 0xff, 0xff, 0x01, 0x00]);
    let c = ti_c55x::parse_container(&data).unwrap();
    assert_eq!(c.register_configs, &[0x1c, 0x8c, 0, 1, 0xff, 0xff, 1, 0]);
    assert_eq!(c.entry_file_offset(), Some(33));
    assert_eq!(c.sections[0].offset, 22);
}

#[test]
fn ti_c55x_every_truncation_and_signature_only_input_is_rejected() {
    let data = table();
    for end in 0..data.len() {
        assert!(
            ti_c55x::parse_container(&data[..end]).is_err(),
            "accepted prefix {end}"
        );
        assert!(!ti_c55x::detect(&data[..end]), "recognized prefix {end}");
    }
    assert!(!ti_c55x::detect(&[0x09, 0xaa]));
    assert!(!ti_c55x::detect(&[0x09, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0]));
    let mut swapped = data;
    for pair in swapped.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    assert!(!ti_c55x::detect(&swapped));
}

#[test]
fn ti_c55x_rejects_invalid_addresses_lengths_and_records() {
    for (offset, bytes) in [
        (2, vec![0x01, 0x00, 0x00, 0x00]),  // beyond 24-bit byte PC
        (10, vec![0x00, 0x80, 0x00, 0x00]), // beyond 23-bit word destination
        (20, vec![0x00, 0x7f, 0xff, 0xfe]), // four-word range crosses limit
        (6, vec![0xff, 0xff]),              // impossible register count for this file
        (18, vec![0xff, 0xff]),             // impossible payload count for this file
        (36, vec![0x00, 0x01]),             // missing terminator
    ] {
        let mut data = table();
        data[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(
            ti_c55x::parse_container(&data).is_err(),
            "accepted corruption at {offset}"
        );
        assert!(!ti_c55x::detect(&data));
    }
}

#[test]
fn ti_c55x_padding_tails_rom_entry_and_last_overlapping_write() {
    let mut data = table();
    data.extend([0xff, 0xff, 0, 0]);
    assert_eq!(ti_c55x::parse_container(&data).unwrap().image_size, 38);
    data.push(0x42);
    assert!(ti_c55x::parse_container(&data).is_err());

    let mut data = table();
    data[2..6].copy_from_slice(&0xff0000u32.to_be_bytes());
    assert!(ti_c55x::parse_container(&data)
        .unwrap()
        .entry_file_offset()
        .is_none());
    // First and second section now both load the entry byte; the later write wins.
    data[2..6].copy_from_slice(&0xfdu32.to_be_bytes());
    data[20..24].copy_from_slice(&0x7eu32.to_be_bytes());
    assert_eq!(
        ti_c55x::parse_container(&data).unwrap().entry_file_offset(),
        Some(25)
    );
}

#[test]
fn ti_c55x_maximum_word_count_and_last_address_are_bounded() {
    let mut data = vec![0x09, 0xaa, 0, 0, 0, 0xfc, 0, 0];
    data.extend([0xff, 0xff, 0, 0, 0, 0x7e]);
    data.resize(8 + 131082, 0x20); // count 65535, address + data padded to 65540 words
    data.extend([0, 0]);
    let c = ti_c55x::parse_container(&data).unwrap();
    assert_eq!(c.sections[0].data.len(), 131070);
    let mut data = table();
    data[10..14].copy_from_slice(&0x7fffffu32.to_be_bytes());
    assert!(ti_c55x::parse_container(&data).is_ok()); // final word, exactly in range
}

#[cfg(feature = "wasm")]
#[test]
fn ti_c55x_wasm_json_uses_the_same_parser() {
    let p: serde_json::Value = serde_json::from_str(&zrax::wasm::classify(&table())).unwrap();
    assert_eq!(p["format"]["format"], "tic55xboot");
    assert_eq!(p["primary"]["isa"], "ti_c5500");
    assert_eq!(p["primary"]["source"], "file_format");
}

#[test]
fn ti_c55x_reported_firmware_regression_when_supplied() {
    // The supplied firmware is not redistributed in the source tree.
    let Some(path) = std::env::var_os("TI_C55X_FIXTURE") else {
        return;
    };
    let data = std::fs::read(path).unwrap();
    assert_eq!(data.len(), 185864);
    let c = ti_c55x::parse_container(&data).unwrap();
    assert_eq!(c.sections.len(), 15);
    assert_eq!(c.entry_point, 0x4c665);
    assert_eq!(c.entry_file_offset(), Some(0x29207));
    assert_eq!(c.image_size, data.len());
    assert_eq!(c.sections[5].data.len(), 131070);
    assert_eq!(c.sections[6].word_address, 0x17fff);
    assert_eq!(
        detect_payload(&data, &ClassifierOptions::new())
            .unwrap()
            .primary
            .isa,
        Isa::TiC5500
    );
}
