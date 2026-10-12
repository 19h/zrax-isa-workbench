//! Fixtures are built independently from the documented wire layouts.
use zrax::formats::{self, ti};
use zrax::types::{FileFormat, Isa};
use zrax::{detect_payload as detect, ClassifierOptions};

fn u32s(values: &[u32], le: bool) -> Vec<u8> {
    values
        .iter()
        .flat_map(|v| if le { v.to_le_bytes() } else { v.to_be_bytes() })
        .collect()
}
fn rprc(le: bool, entry: u32, bytes: &[u8]) -> Vec<u8> {
    let mut v = u32s(
        &[
            0x43525052,
            entry,
            0,
            1,
            1,
            entry,
            0,
            bytes.len() as u32,
            0,
            0,
        ],
        le,
    );
    v.extend(bytes);
    v
}
fn words(values: &[u16], le: bool) -> Vec<u8> {
    values
        .iter()
        .flat_map(|v| if le { v.to_le_bytes() } else { v.to_be_bytes() })
        .collect()
}
fn c28(le: bool) -> Vec<u8> {
    // Addresses are two 16-bit words, most significant word first, even in SCI8.
    let mut v = words(
        &[
            0x08aa, 0, 0, 0, 0, 0, 0, 0, 0, 0x003f, 0x0000, 3, 0x003f, 0x0000,
        ],
        le,
    );
    v.extend(words(&[0x1234, 0x5678, 0x9abc, 0], le));
    v
}
fn assert_format(v: &[u8], f: FileFormat) {
    let p = detect(v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, f);
    assert_eq!(zrax::classify_bytes(v).unwrap().format, f);
}

#[test]
fn rprc_both_orders_sections_and_truncation() {
    for le in [true, false] {
        let v = rprc(le, 0x80000000, &[1, 2, 3, 4, 5]);
        let c = ti::parse_container(&v, ti::Variant::Rprc).unwrap();
        assert_eq!(c.sections[0].address, 0x80000000);
        assert_eq!(c.sections[0].data.as_ref(), &[1, 2, 3, 4, 5]);
        assert_eq!(c.entry, Some(0x80000000));
        assert_format(&v, FileFormat::TiRprc);
        for end in 0..v.len() {
            assert!(
                ti::parse_container(&v[..end], ti::Variant::Rprc).is_err(),
                "{end}"
            );
        }
        let mut corrupt = v.clone();
        corrupt[12..16].copy_from_slice(&[255; 4]);
        assert!(ti::parse_container(&corrupt, ti::Variant::Rprc).is_err());
    }
}

#[test]
fn multicore_offsets_order_and_each_core() {
    for le in [true, false] {
        let a = rprc(le, 0x1000, &[1, 2, 3, 4]);
        let b = rprc(le, 0x2000, &[5, 6, 7, 8]);
        let mut v = u32s(
            &[
                0x5254534d,
                2,
                55,
                0,
                7,
                (40 + a.len()) as u32,
                4,
                40,
                0,
                0x444e454d,
            ],
            le,
        );
        v.extend(a);
        v.extend(b);
        let c = ti::parse_container(&v, ti::Variant::Multicore).unwrap();
        assert_eq!(c.children.len(), 2);
        assert_eq!(c.children[0].label, "Core 7");
        assert_format(&v, FileFormat::TiMulticore);
        let p = detect(&v, &ClassifierOptions::default()).unwrap();
        assert_eq!(p.slices.len(), 2);
        let mut bad = v.clone();
        bad[28..32].copy_from_slice(&u32s(&[16], le));
        assert!(ti::parse_container(&bad, ti::Variant::Multicore).is_err());
        let mut duplicate = v.clone();
        duplicate[20..24].copy_from_slice(&v[28..32]);
        assert!(ti::parse_container(&duplicate, ti::Variant::Multicore).is_err());
    }
}

#[test]
fn c28_word_counts_and_word_address_units() {
    for le in [true, false] {
        let v = c28(le);
        let c = ti::parse_container(&v, ti::Variant::C28xBoot).unwrap();
        assert_eq!(c.sections[0].address, 0x3f0000);
        assert_eq!(c.sections[0].data.len(), 6);
        assert_eq!(c.classification().isa, Isa::TiC28x);
        assert_format(&v, FileFormat::TiBoot);
        for end in 0..v.len() {
            assert!(ti::parse_container(&v[..end], ti::Variant::C28xBoot).is_err());
        }
    }
}

#[test]
fn c54_parallel_and_serial() {
    for registers in [2, 4] {
        let mut v = words(&[0x10aa], false);
        v.extend(words(&vec![0; registers], false));
        v.extend(words(&[0, 0x1000, 2, 0, 0x1000, 0x1234, 0x5678, 0], false));
        let c = ti::parse_container(&v, ti::Variant::C54xBoot).unwrap();
        assert_eq!(c.classification().isa, Isa::TiC5400);
        assert_eq!(c.entry, Some(0x1000));
        assert_eq!(c.sections[0].data.len(), 4);
        assert_format(&v, FileFormat::TiBoot);
    }
}

#[test]
fn overlapping_c28_and_c54_layouts_remain_unknown() {
    let v = words(
        &[
            0x08aa, 0, 0, 0, 0x1000, 7, 0, 0x1000, 0, 0, 0x2000, 1, 0, 0x2000, 0xaaaa, 0,
        ],
        false,
    );
    assert!(ti::parse_container(&v, ti::Variant::C28xBoot).is_ok());
    assert!(ti::parse_container(&v, ti::Variant::C54xBoot).is_ok());
    let p = detect(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, FileFormat::TiBoot);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

#[test]
fn ti_vendor_generated_multicore_and_signing_oracles() {
    let app = include_bytes!("fixtures/ti/vendor.appimage");
    let c = ti::parse_container(app, ti::Variant::Multicore).unwrap();
    assert_eq!(c.children.len(), 2);
    assert_eq!(c.children[0].label, "Core 4");
    assert_eq!(c.children[1].offset, 84);
    assert_format(app, FileFormat::TiMulticore);
    let elf = include_bytes!("fixtures/ti/vendor.mcelf");
    let c = ti::parse_container(elf, ti::Variant::Mcelf).unwrap();
    assert_eq!(c.children.len(), 2);
    assert_format(elf, FileFormat::TiMcelf);
    assert!(detect(&elf[..elf.len() - 1], &ClassifierOptions::default()).is_err());
    let mut encoded = elf.to_vec();
    let at = encoded
        .windows(10)
        .position(|s| s == b"otfaConfig")
        .unwrap();
    encoded[at + 12] = 1;
    assert!(
        ti::parse_container(&encoded, ti::Variant::Mcelf)
            .unwrap()
            .opaque
    );
    let p = detect(&encoded, &ClassifierOptions::default()).unwrap();
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    let empty = include_bytes!("fixtures/ti/vendor.mcelf_xip");
    assert!(
        ti::parse_container(empty, ti::Variant::Mcelf)
            .unwrap()
            .opaque
    );
    assert_format(empty, FileFormat::TiMcelf);
    let signed = include_bytes!("fixtures/ti/vendor.signed");
    let c = ti::parse_container(signed, ti::Variant::X509).unwrap();
    assert_eq!(c.children[0].data, app);
    let p = detect(signed, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, FileFormat::TiX509);
    for end in 0..signed.len() {
        assert!(ti::parse_container(&signed[..end], ti::Variant::X509).is_err());
    }
}

#[test]
fn unkeyed_boot_tables_require_full_structure() {
    let mut v = u32s(&[0x1000, 4, 0x1000], true);
    v.extend([1, 2, 3, 4]);
    v.extend([0; 4]);
    assert_format(&v, FileFormat::TiBoot);
    let mut c55 = u32s(&[0x1000, 1], false);
    c55.extend([0x1c, 0, 0x12, 0x34]);
    c55.extend(u32s(&[4, 0x1000], false));
    c55.extend([1, 2, 3, 4]);
    c55.extend([0; 4]);
    assert_format(&c55, FileFormat::TiBoot);
    for len in 0..80 {
        assert!(matches!(
            formats::detect_format(&vec![0; len]),
            formats::DetectedFormat::Raw
        ));
    }
}

#[test]
fn ais_all_documented_file_commands() {
    let mut v = u32s(&[0x41504954, 0x58535903, 0x58535901, 0x8000, 3], true);
    v.extend([1, 2, 3, 0]);
    v.extend(u32s(
        &[
            0x5853590a, 0x9000, 0xffff0000, 2, 0x12345678, 0x58535902, 0, 0, 0x58535904,
            0x58535905, 0x8000, 0x58535963, 0x5853590d, 0x00020001, 7, 8, 0x58535907, 0, 0x9000, 1,
            0, 0x58535906, 0x8000,
        ],
        true,
    ));
    let c = ti::parse_container(&v, ti::Variant::Ais).unwrap();
    assert_eq!(c.sections.len(), 1);
    assert_eq!(c.sections[0].data.as_ref(), &[1, 2, 3]);
    assert_eq!(c.entry, Some(0x8000));
    assert_format(&v, FileFormat::TiAis);
    for end in 0..v.len() {
        assert!(ti::parse_container(&v[..end], ti::Variant::Ais).is_err());
    }
    let mut bad = v.clone();
    bad[4..8].copy_from_slice(&[255; 4]);
    assert!(ti::parse_container(&bad, ti::Variant::Ais).is_err());
}

fn oad(id: &[u8; 8]) -> Vec<u8> {
    let mut v = vec![0xff; 44];
    v[..8].copy_from_slice(id);
    v[12] = 3;
    v[13] = 1;
    v[18] = 1;
    v[24..28].copy_from_slice(&64u32.to_le_bytes());
    v[28..32].copy_from_slice(&0x1000u32.to_le_bytes());
    v[40..42].copy_from_slice(&44u16.to_le_bytes());
    v.extend([1, 0xff, 0xff, 0xff]);
    v.extend(20u32.to_le_bytes());
    v.extend(0x1000u32.to_le_bytes());
    v.extend([1, 2, 3, 4, 5, 6, 7, 8]);
    v
}
#[test]
fn oad_ids_segment_bounds_and_metadata_only() {
    for id in [
        b"CC26x2R1",
        b"CC13x2R1",
        b"CC13x4  ",
        b"CC26x3  ",
        b"CC26x4  ",
        b"OAD IMG ",
        b"CC23x0R2",
    ] {
        let v = oad(id);
        let c = ti::parse_container(&v, ti::Variant::Oad).unwrap();
        assert_eq!(
            c.classification().isa,
            if id == b"OAD IMG " {
                Isa::Unknown(0)
            } else {
                Isa::Arm
            }
        );
        assert_eq!(c.sections[0].offset, 56);
        assert_format(&v, FileFormat::TiOad);
        for end in 0..v.len() {
            assert!(ti::parse_container(&v[..end], ti::Variant::Oad).is_err());
        }
    }
    let mut bad = oad(b"CC26x2R1");
    bad[48..52].copy_from_slice(&0u32.to_le_bytes());
    assert!(ti::parse_container(&bad, ti::Variant::Oad).is_err());
}

#[test]
fn oad_host_and_user_data_do_not_inherit_radio_isa() {
    for kind in [0x10, 0x20, 0x40, 0xff] {
        let mut v = oad(b"CC26x2R1");
        v[18] = kind;
        let c = ti::parse_container(&v, ti::Variant::Oad).unwrap();
        assert!(matches!(c.classification().isa, Isa::Unknown(_)));
        if kind != 0x20 {
            assert!(c.opaque);
            assert!(detect(&v, &ClassifierOptions::default())
                .unwrap()
                .candidates
                .is_empty());
        }
    }
}

#[test]
fn nesting_budget_does_not_classify_wrapper_bytes() {
    for depth in [1, 6, 7, 10] {
        let mut v = coff(2, 0x9d, true, &[1, 2, 3, 4]);
        for _ in 0..depth {
            let body = seq(&[
                integer(1),
                integer(16),
                integer(0),
                der(4, &[0, 0, 0x10, 0]),
                integer(v.len() as u32),
            ]);
            let mut next = ti_certificate(1, body, false);
            next.extend(v);
            v = next;
        }
        let p = detect(&v, &ClassifierOptions::default()).unwrap();
        if depth <= 6 {
            assert_eq!(p.primary.isa, Isa::TiC28x);
        } else {
            assert!(matches!(p.primary.isa, Isa::Unknown(_)));
            assert!(p.candidates.is_empty());
        }
    }
}

#[test]
fn ambiguous_rprc_layouts_do_not_invent_load_ranges() {
    let mut v = u32s(&[0x43525052, 0x1000, 0, 1, 1, 0, 0x1000, 4, 0, 0, 0], true);
    v.extend([0; 4]);
    let c = ti::parse_container(&v, ti::Variant::Rprc).unwrap();
    assert!(c.opaque);
    assert!(c.sections.is_empty());
    assert!(detect(&v, &ClassifierOptions::default())
        .unwrap()
        .candidates
        .is_empty());
}

#[test]
fn multicore_and_archive_extensions_keep_per_component_evidence() {
    let unit = &[
        0xc5, 0xfc, 0x10, 0x07, 0xc4, 0xe2, 0x75, 0xb8, 0x06, 0xc5, 0xed, 0xfe, 0xd9, 0xc5, 0xfc,
        0x11, 0x07, 0x48, 0x83, 0xc7, 0x20, 0xff, 0xc9, 0x75, 0xe5, 0xc5, 0xf8, 0x77, 0xc3,
    ];
    let plain = coff(0, 0x14c, true, &[0x90; 64]);
    let vector = coff(0, 0x14c, true, &unit.repeat(64));
    let options = ClassifierOptions {
        detect_extensions: true,
        ..Default::default()
    };
    let expected = detect(&plain, &options).unwrap();
    let second = detect(&vector, &options).unwrap();
    assert!(second.extensions.iter().any(|e| e.name == "AVX"));
    let a = rprc(true, 0x1000, &plain);
    let b = rprc(true, 0x2000, &vector);
    let mut image = u32s(
        &[
            0x5254534d,
            2,
            55,
            0,
            4,
            40,
            14,
            (40 + a.len()) as u32,
            0,
            0x444e454d,
        ],
        true,
    );
    image.extend(a);
    image.extend(b);
    let mut archive = b"!<arch>\n".to_vec();
    ar_member(&mut archive, "plain.obj/", &plain);
    ar_member(&mut archive, "vector.obj/", &vector);
    for v in [&image, &archive] {
        let p = detect(v, &options).unwrap();
        assert_eq!(p.primary.isa, Isa::X86);
        assert_eq!(
            serde_json::to_value(&p.extensions).unwrap(),
            serde_json::to_value(&expected.extensions).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&p.slices[1].extensions).unwrap(),
            serde_json::to_value(&second.extensions).unwrap()
        );
        assert!(p.slices[1]
            .extensions
            .iter()
            .all(|e| e.source == zrax::ExtensionSource::CodePattern));
    }
}

#[test]
fn gp_image_no_architecture_from_address() {
    let mut v = u32s(&[16, 0x80000000], true);
    v.extend([0x42; 16]);
    let c = ti::parse_container(&v, ti::Variant::GpImage).unwrap();
    assert!(matches!(c.classification().isa, Isa::Unknown(_)));
    assert_format(&v, FileFormat::TiImage);
}

#[test]
fn mcuboot_encryption_and_tlv_bounds() {
    let mut v = vec![0; 32];
    v[..4].copy_from_slice(&0x96f3b83du32.to_le_bytes());
    v[8..10].copy_from_slice(&32u16.to_le_bytes());
    v[12..16].copy_from_slice(&4u32.to_le_bytes());
    v[16..20].copy_from_slice(&4u32.to_le_bytes());
    v.extend([0x42; 4]);
    v.extend([7, 0x69, 8, 0, 0x10, 0, 0, 0]);
    let c = ti::parse_container(&v, ti::Variant::Mcuboot).unwrap();
    assert!(c.opaque);
    let p = detect(&v, &ClassifierOptions::default()).unwrap();
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_format(&v, FileFormat::Mcuboot);
    let mut bad = v.clone();
    bad[38..40].copy_from_slice(&100u16.to_le_bytes());
    assert!(ti::parse_container(&bad, ti::Variant::Mcuboot).is_err());
}

#[test]
fn ti_ascii_hex_addresses_and_encoded_boot_table() {
    let v = b"\x02$A00001000, 01 02 03 04\n$A00002000, AB CD\x03";
    let c = ti::parse_container(v, ti::Variant::AsciiHex).unwrap();
    assert_eq!(c.sections.len(), 2);
    assert_eq!(c.sections[1].address, 0x2000);
    assert_format(v, FileFormat::TiAsciiHex);
    let boot = c28(false);
    let mut text = b"\x02\n".to_vec();
    for b in boot {
        text.extend(format!("{b:02X} ").as_bytes());
    }
    text.push(3);
    let p = detect(&text, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.primary.isa, Isa::TiC28x);
    assert_eq!(p.format.format, FileFormat::TiAsciiHex);
}

#[test]
fn tagged_ascii_checksum_and_byte_word_tags() {
    let body = "90000B1234*567";
    let sum = body.bytes().map(u16::from).fold(0u16, u16::wrapping_add);
    let v = format!("K0000fixtureF\n{body}{:04X}F\n:\n", 0u16.wrapping_sub(sum));
    let c = ti::parse_container(v.as_bytes(), ti::Variant::Tagged).unwrap();
    assert_eq!(c.sections[0].data.as_ref(), &[0x12, 0x34, 0x56]);
    assert_format(v.as_bytes(), FileFormat::TiTagged);
    let bad = v.replacen("B1234", "B1235", 1);
    assert!(ti::parse_container(bad.as_bytes(), ti::Variant::Tagged).is_err());
}

fn tek(kind: u8, addr: u32, bytes: &[u8]) -> String {
    let body = format!(
        "8{addr:08X}{}",
        bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
    );
    let prefix = format!("{:02X}{kind:X}", body.len() + 5);
    let sum = prefix
        .bytes()
        .chain(body.bytes())
        .map(|b| (b as char).to_digit(16).unwrap())
        .sum::<u32>() as u8;
    format!("%{prefix}{sum:02X}{body}\n")
}
#[test]
fn extended_tektronix_checksum_length_and_entry() {
    let v = format!("{}{}", tek(6, 0x1000, &[1, 2, 3]), tek(8, 0x1000, &[]));
    let c = ti::parse_container(v.as_bytes(), ti::Variant::Tektronix).unwrap();
    assert_eq!(c.entry, Some(0x1000));
    assert_eq!(c.sections[0].data.as_ref(), &[1, 2, 3]);
    assert_format(v.as_bytes(), FileFormat::TiTekHex);
    let bad = v.replacen("010203", "010204", 1);
    assert!(ti::parse_container(bad.as_bytes(), ti::Variant::Tektronix).is_err());
}

#[test]
fn deterministic_noise_does_not_panic_or_match_weak_ti_formats() {
    let mut state = 0x12ab34cdu32;
    for len in 0..512 {
        let v: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        assert!(ti::detect_weak(&v).is_none());
        for kind in ti::Variant::ALL {
            let _ = ti::parse_container(&v, *kind);
        }
    }
}

#[test]
fn byte_mutations_counts_and_truncations_are_bounded() {
    for (v, kind) in [
        (rprc(true, 0x1000, &[1, 2, 3, 4]), ti::Variant::Rprc),
        (oad(b"CC26x2R1"), ti::Variant::Oad),
        (mcelf(true, false), ti::Variant::Mcelf),
        (
            include_bytes!("fixtures/ti/vendor.signed").to_vec(),
            ti::Variant::X509,
        ),
        (
            include_bytes!("fixtures/ti/vendor.appimage").to_vec(),
            ti::Variant::Multicore,
        ),
    ] {
        for i in 0..v.len() {
            for value in [0, 0xff] {
                let mut m = v.clone();
                m[i] = value;
                let _ = ti::parse_container(&m, kind);
                let _ = formats::detect_format(&m);
            }
        }
    }
    let mut v = rprc(true, 0xfffffff0, &[0; 32]);
    assert!(ti::parse_container(&v, ti::Variant::Rprc).is_err());
    v[12..16].copy_from_slice(&0u32.to_le_bytes());
    v.truncate(20);
    assert_format(&v, FileFormat::TiRprc);
    let mut v = u32s(&[0x41504954, 0x585359ff], true);
    assert!(detect(&v, &ClassifierOptions::default()).is_err());
    v = u32s(&[0x41504954, 0x58535906, 0x1000], true);
    assert_format(&v, FileFormat::TiAis);
}

fn coff(version: u16, target: u16, le: bool, payload: &[u8]) -> Vec<u8> {
    let header = if version == 0 { 20 } else { 22 };
    let section = if version == 2 { 48 } else { 40 };
    let raw = header + 28 + section;
    let mut v = words(&[if version == 0 { target } else { 0xc0 + version }, 1], le);
    v.extend(u32s(&[0, 0, 0], le));
    v.extend(words(&[28, 0x0102], le));
    if version != 0 {
        v.extend(words(&[target], le));
    }
    v.extend(words(&[0x108, 0], le));
    v.extend(u32s(&[0, 0, 0, 0x1000, 0x1000, 0x2000], le));
    let mut sh = vec![0; section];
    sh[..5].copy_from_slice(b".text");
    let unit = match target {
        0x93 => 4,
        0x98 | 0x9d => 2,
        _ => 1,
    };
    sh[16..20].copy_from_slice(&u32s(&[(payload.len() / unit) as u32], le));
    sh[20..24].copy_from_slice(&u32s(&[raw as u32], le));
    v.extend(sh);
    v.extend(payload);
    v
}
#[test]
fn ti_coff_all_versions_targets_host_orders_and_word_lengths() {
    for version in [0, 1, 2] {
        for le in [true, false] {
            for (target, isa) in [
                (0x93, Isa::TiC3x),
                (0x97, Isa::Arm),
                (0x98, Isa::TiC5400),
                (0x99, Isa::TiC6000),
                (0x9c, Isa::TiC5500),
                (0x9d, Isa::TiC28x),
                (0xa0, Isa::Msp430),
                (0xa1, Isa::TiC5500),
            ] {
                let v = coff(version, target, le, &[1, 2, 3, 4]);
                assert!(
                    formats::coff::detect(&v).is_some(),
                    "v{version} target {target:X} le {le}"
                );
                let r = formats::coff::parse(&v).unwrap();
                assert_eq!(r.isa, isa);
                assert_eq!(r.endianness, zrax::Endianness::Little);
                assert_eq!(r.metadata.entry_point, Some(0x1000));
                assert_eq!(r.metadata.section_count, Some(1));
                assert_format(&v, FileFormat::Coff);
                assert!(formats::coff::detect(&v[..v.len() - 1]).is_none());
            }
        }
    }
}

fn ar_member(v: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut h = [b' '; 60];
    h[..name.len()].copy_from_slice(name.as_bytes());
    let s = data.len().to_string();
    h[48..48 + s.len()].copy_from_slice(s.as_bytes());
    h[58..].copy_from_slice(b"`\n");
    v.extend(h);
    v.extend(data);
    if v.len() % 2 != 0 {
        v.push(b'\n');
    }
}
#[test]
fn ti_archives_resolve_gnu_and_bsd_names_and_classify_each_member() {
    let a = coff(2, 0x9d, true, &[1, 2, 3, 4]);
    let b = coff(0, 0x99, false, &[5, 6, 7, 8]);
    let mut v = b"!<arch>\n".to_vec();
    ar_member(&mut v, "/", &[0; 4]);
    ar_member(&mut v, "//", b"long_ti_object.obj/\n");
    ar_member(&mut v, "/0", &a);
    let mut body = b"dsp.obj".to_vec();
    body.extend(b);
    ar_member(&mut v, "#1/7", &body);
    let p = detect(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.primary.isa, Isa::TiC28x);
    assert_eq!(p.slices.len(), 2);
    assert_eq!(p.slices[0].label.as_deref(), Some("long_ti_object.obj"));
    assert_eq!(p.slices[1].isa, Isa::TiC6000);
    assert!(formats::ar::parse_members(&v[..v.len() - 2]).is_err());
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if body.len() < 128 {
        v.push(body.len() as u8);
    } else if body.len() < 256 {
        v.extend([0x81, body.len() as u8]);
    } else {
        v.extend([0x82, (body.len() >> 8) as u8, body.len() as u8]);
    }
    v.extend(body);
    v
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}
fn integer(n: u32) -> Vec<u8> {
    let b = n.to_be_bytes();
    let start = b.iter().position(|b| *b != 0).unwrap_or(3);
    let mut v = b[start..].to_vec();
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    der(2, &v)
}
fn ti_certificate(extension: u8, body: Vec<u8>, encrypted: bool) -> Vec<u8> {
    let oid = der(6, &[0x2b, 6, 1, 4, 1, 0x82, 0x26, 1, extension]);
    let mut extensions = vec![seq(&[oid, der(4, &body)])];
    if encrypted {
        extensions.push(seq(&[
            der(6, &[0x2b, 6, 1, 4, 1, 0x82, 0x26, 1, 4]),
            der(4, &seq(&[])),
        ]));
    }
    let algo = seq(&[
        der(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 0x0b]),
        der(5, &[]),
    ]);
    let validity = seq(&[der(0x17, b"261011000000Z"), der(0x17, b"271011000000Z")]);
    let tbs = seq(&[
        der(0xa0, &integer(2)),
        integer(1),
        algo.clone(),
        seq(&[]),
        validity,
        seq(&[]),
        seq(&[algo.clone(), der(3, &[0, 0])]),
        der(0xa3, &seq(&extensions)),
    ]);
    seq(&[tbs, algo, der(3, &[0, 1, 2, 3])])
}
#[test]
fn x509_ti_oid_boundaries_encryption_and_nested_images() {
    let payload = coff(2, 0x9d, true, &[1, 2, 3, 4]);
    for encrypted in [false, true] {
        let mut v = ti_certificate(
            1,
            seq(&[
                integer(1),
                integer(16),
                integer(0),
                der(4, &[0x80, 0, 0, 0]),
                integer(payload.len() as u32),
            ]),
            encrypted,
        );
        v.extend(&payload);
        let c = ti::parse_container(&v, ti::Variant::X509).unwrap();
        assert_eq!(c.opaque, encrypted);
        let p = detect(&v, &ClassifierOptions::default()).unwrap();
        assert_eq!(p.format.format, FileFormat::TiX509);
        if encrypted {
            assert!(matches!(p.primary.isa, Isa::Unknown(_)));
            assert!(p.candidates.is_empty());
        } else {
            assert_eq!(p.primary.isa, Isa::TiC28x);
            assert_eq!(p.slices[0].isa, Isa::TiC28x);
        }
        for end in 0..v.len() {
            assert!(ti::parse_container(&v[..end], ti::Variant::X509).is_err());
        }
        let mut wrong = v.clone();
        let at = wrong
            .windows(9)
            .position(|w| w == [0x2b, 6, 1, 4, 1, 0x82, 0x26, 1, 1])
            .unwrap();
        wrong[at + 6] = 0x27;
        assert!(ti::parse_container(&wrong, ti::Variant::X509).is_err());
    }
}
#[test]
fn x509_combined_components_and_integrity_length() {
    let payload = coff(2, 0x99, true, &[1, 2, 3, 4]);
    let component = seq(&[
        integer(1),
        integer(16),
        integer(0),
        der(4, &[0x80, 0, 0, 0]),
        integer(payload.len() as u32),
        der(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3]),
        der(4, &[0; 64]),
    ]);
    let mut v = ti_certificate(
        9,
        seq(&[integer(payload.len() as u32), integer(1), component]),
        false,
    );
    v.extend(payload);
    assert_format(&v, FileFormat::TiX509);
    let p = detect(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.primary.isa, Isa::TiC6000);
}

#[test]
fn c3x_c4x_tables_and_c32_data_widths() {
    for width in [8, 16, 32] {
        let c31 = u32s(&[width, 0, 1, 0x1000, 0x12345678, 0], true);
        let p = detect(&c31, &ClassifierOptions::default()).unwrap();
        assert_eq!(p.primary.isa, Isa::TiC3x);
        let c4 = u32s(
            &[
                width, 0, 0, 1, 0x1000, 0x12345678, 0, 0x2000, 0x3000, 0x4000,
            ],
            true,
        );
        assert!(ti::parse_container(&c4, ti::Variant::C4xBoot).is_ok());
        assert_format(&c4, FileFormat::TiBoot);
        for (type_bits, octets) in [(0, 1), (1, 2), (3, 4)] {
            let mut c32 = u32s(&[width, 0, 0, 0, 2, 0x1000, (type_bits << 24) | 0x64], true);
            c32.extend(vec![0x12; 2 * octets]);
            c32.extend([0; 4]);
            let c = ti::parse_container(&c32, ti::Variant::C32Boot).unwrap();
            assert_eq!(c.sections[0].data.len(), 2 * octets);
            assert_format(&c32, FileFormat::TiBoot);
        }
    }
}

#[test]
fn radar_metaimage_roles_and_crc_trailer() {
    let a = rprc(true, 0x1000, &[1, 2, 3, 4]);
    let b = rprc(true, 0x2000, &[5, 6, 7, 8]);
    let size = 128 + a.len() + b.len();
    let mut v = u32s(
        &[
            0x5254534d,
            2,
            37,
            0,
            0,
            size as u32,
            1,
            0x35510000,
            128,
            0,
            0,
            a.len() as u32,
            0,
            0,
            1,
            0xd5510000,
            (128 + a.len()) as u32,
            0,
            0,
            b.len() as u32,
            0,
            0,
            0,
            0x444e454d,
        ],
        true,
    );
    v.resize(128, 0);
    v.extend(a);
    v.extend(b);
    let p = detect(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.slices[0].isa, Isa::Arm);
    assert_eq!(p.slices[1].isa, Isa::TiC6000);
    assert_format(&v, FileFormat::TiMulticore);
    v.extend([1, 2, 3, 4]);
    assert!(ti::parse_container(&v, ti::Variant::Multicore).is_ok());
}
#[test]
fn secure_ais_excludes_ciphertext() {
    let mut v = u32s(&[0x41504954, 0x58535920], true);
    v.extend([0x42; 32]);
    v.extend(u32s(&[0x58535921, 0x1000, 4], true));
    v.extend([0x33; 16]);
    v.extend(u32s(&[0x58535906, 0x1000], true));
    v.extend([0x55; 32]);
    let c = ti::parse_container(&v, ti::Variant::Ais).unwrap();
    assert!(c.opaque);
    assert!(c.payload().unwrap().is_empty());
    let p = detect(&v, &ClassifierOptions::default()).unwrap();
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_format(&v, FileFormat::TiAis);
}

#[test]
fn omap_configuration_header_and_gp_image() {
    let mut v = vec![0; 512];
    v[..4].copy_from_slice(&64u32.to_le_bytes());
    v[4..8].copy_from_slice(&12u32.to_le_bytes());
    v[20..30].copy_from_slice(b"CHSETTINGS");
    v[32..64].fill(255);
    v[64..68].copy_from_slice(&0xc0c0c0c1u32.to_le_bytes());
    v.extend(u32s(&[16, 0x402f0400], true));
    v.extend([0x12; 16]);
    assert_format(&v, FileFormat::TiImage);
    assert_eq!(
        detect(&v, &ClassifierOptions::default())
            .unwrap()
            .primary
            .isa,
        Isa::Arm
    );
    let mut bad = v.clone();
    bad[4..8].copy_from_slice(&512u32.to_le_bytes());
    assert!(ti::parse_container(&bad, ti::Variant::OmapImage).is_err());
}

fn note(kind: u32, name: &[u8], desc: &[u8], le: bool) -> Vec<u8> {
    let mut v = u32s(&[name.len() as u32, desc.len() as u32, kind], le);
    v.extend(name);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v.extend(desc);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}
fn mcelf(is64: bool, le: bool) -> Vec<u8> {
    let h = if is64 { 64 } else { 52 };
    let ph = if is64 { 56 } else { 32 };
    let noff = h + ph * 2;
    let mut desc = u32s(&[4], le);
    if is64 {
        desc.extend(if le {
            0x1_0000_1000u64.to_le_bytes()
        } else {
            0x1_0000_1000u64.to_be_bytes()
        });
    } else {
        desc.extend(u32s(&[0x1000], le));
    }
    let mut notes = note(0xaaaa5555, b"Texas Instruments ", &[], le);
    notes.extend(note(0xbbbb7777, b"Segment Map ", &[4], le));
    notes.extend(note(0xcccc9999, b"Entry Points ", &desc, le));
    let code_offset = noff + notes.len();
    let mut v = vec![0; noff];
    v[..4].copy_from_slice(b"\x7fELF");
    v[4] = if is64 { 2 } else { 1 };
    v[5] = if le { 1 } else { 2 };
    v[6] = 1;
    v[16..20].copy_from_slice(&words(&[2, 40], le));
    v[20..24].copy_from_slice(&u32s(&[1], le));
    if is64 {
        v[32..40].copy_from_slice(&(h as u64).to_le_bytes()); // overwrite for BE below
        if !le {
            v[32..40].copy_from_slice(&(h as u64).to_be_bytes());
        }
        v[52..58].copy_from_slice(&words(&[64, 56, 2], le));
        let put = |v: &mut Vec<u8>, at: usize, n: u64| {
            v[at..at + 8].copy_from_slice(&if le { n.to_le_bytes() } else { n.to_be_bytes() })
        };
        v[h..h + 8].copy_from_slice(&u32s(&[4, 0], le));
        put(&mut v, h + 8, noff as u64);
        put(&mut v, h + 32, notes.len() as u64);
        put(&mut v, h + 40, notes.len() as u64);
        v[h + ph..h + ph + 8].copy_from_slice(&u32s(&[1, 5], le));
        put(&mut v, h + ph + 8, code_offset as u64);
        put(&mut v, h + ph + 24, 0x1_0000_1000);
        put(&mut v, h + ph + 32, 4);
        put(&mut v, h + ph + 40, 4);
    } else {
        v[28..32].copy_from_slice(&u32s(&[h as u32], le));
        v[40..46].copy_from_slice(&words(&[52, 32, 2], le));
        v[h..h + ph].copy_from_slice(&u32s(
            &[
                4,
                noff as u32,
                0,
                0,
                notes.len() as u32,
                notes.len() as u32,
                0,
                4,
            ],
            le,
        ));
        v[h + ph..h + ph * 2].copy_from_slice(&u32s(
            &[1, code_offset as u32, 0x1000, 0x1000, 4, 4, 5, 4],
            le,
        ));
    }
    v.extend(notes);
    v.extend([1, 2, 3, 4]);
    v
}
#[test]
fn mcelf_32_and_64_preserves_core_map_and_full_width_entry() {
    for is64 in [false, true] {
        for le in [true, false] {
            let v = mcelf(is64, le);
            let c = ti::parse_container(&v, ti::Variant::Mcelf).unwrap();
            assert_eq!(c.children[0].label, "Core 4 code segment");
            assert_eq!(c.children[0].data, &[1, 2, 3, 4]);
            if is64 {
                assert!(c.notes.iter().any(|n| n.contains("0x100001000")));
            }
            assert_format(&v, FileFormat::TiMcelf);
            let mut bad = v.clone();
            let at = bad.windows(12).position(|w| w == b"Segment Map ").unwrap();
            bad[at + 12] = 255;
            // An unknown platform-specific core ID remains metadata, not an ARM claim.
            assert!(ti::parse_container(&bad, ti::Variant::Mcelf).is_ok());
        }
    }
}

#[test]
fn legacy_c55_padding_and_radar_rprc_layout() {
    let mut v = u32s(&[0x1001, 0, 3, 0x1001], false);
    v.extend([0, 1, 2, 3]);
    v.extend([0; 4]);
    let c = ti::parse_container(&v, ti::Variant::C55xLegacy).unwrap();
    assert_eq!(c.sections[0].data.as_ref(), &[1, 2, 3]);
    let mut radar = u32s(&[0x43525052, 0x1000, 0, 1, 1, 0, 0x1000, 4, 0, 0, 0], true);
    radar.extend([1, 2, 3, 4]);
    let c = ti::parse_container(&radar, ti::Variant::Rprc).unwrap();
    assert_eq!(c.sections[0].offset, 44);
    assert_eq!(c.sections[0].data.as_ref(), &[1, 2, 3, 4]);
}

#[test]
fn fip_uuid_ranges_nested_images_and_non_code_components() {
    let image = coff(2, 0x9d, true, &[1, 2, 3, 4]);
    let mut v = u32s(&[0xaa640001, 12345678], true);
    v.extend(0u64.to_le_bytes());
    v.extend([
        0xd6, 0xd0, 0xee, 0xa7, 0xfc, 0xea, 0xd5, 0x4b, 0x97, 0x82, 0x99, 0x34, 0xf2, 0x34, 0xb6,
        0xe4,
    ]);
    for n in [96, image.len() as u64, 0] {
        v.extend(n.to_le_bytes());
    }
    v.extend([0; 16]);
    for n in [96 + image.len() as u64, 0, 0] {
        v.extend(n.to_le_bytes());
    }
    v.extend(image);
    let c = ti::parse_container(&v, ti::Variant::Fip).unwrap();
    assert_eq!(c.children[0].label, "BL33");
    assert_format(&v, FileFormat::Fip);
    assert_eq!(
        detect(&v, &ClassifierOptions::default())
            .unwrap()
            .primary
            .isa,
        Isa::TiC28x
    );
    for end in 0..v.len() {
        assert!(ti::parse_container(&v[..end], ti::Variant::Fip).is_err());
    }
    let mut bad = v.clone();
    bad[32..40].copy_from_slice(&16u64.to_le_bytes());
    assert!(ti::parse_container(&bad, ti::Variant::Fip).is_err());
}

#[test]
fn ccs_data_samples_header_override_and_unknown_word_width() {
    for (kind, data) in [
        (1, "0x1234\n0x5678"),
        (2, "-12\n34"),
        (3, "-12345678\n12345678"),
        (4, "1.25\n-3e-2"),
    ] {
        let v = format!("1651 {kind} 800 1 2\n{data}\n");
        let c = ti::parse_container(v.as_bytes(), ti::Variant::CcsData).unwrap();
        assert!(c.opaque);
        assert_format(v.as_bytes(), FileFormat::TiData);
        assert!(matches!(
            detect(v.as_bytes(), &ClassifierOptions::default())
                .unwrap()
                .primary
                .isa,
            Isa::Unknown(_)
        ));
    }
    assert_format(b"1651 1 0 0 0\n0xabcd\n", FileFormat::TiData);
    assert!(ti::parse_container(b"1651 1 0 0 2\n0xffff\n", ti::Variant::CcsData).is_err());
}

#[test]
fn mcelf_data_and_otfa_are_excluded_from_code_analysis() {
    let mut v = mcelf(false, true);
    v[52 + 32 + 24..52 + 32 + 28].copy_from_slice(&4u32.to_le_bytes());
    let c = ti::parse_container(&v, ti::Variant::Mcelf).unwrap();
    assert!(c.opaque);
    assert!(matches!(
        detect(&v, &ClassifierOptions::default())
            .unwrap()
            .primary
            .isa,
        Isa::Unknown(_)
    ));
    let mut bad = mcelf(false, true);
    let at = bad
        .windows(18)
        .position(|w| w == b"Texas Instruments ")
        .unwrap();
    bad[at] = b'X';
    assert!(!matches!(
        formats::detect_format(&bad),
        formats::DetectedFormat::Ti {
            variant: ti::Variant::Mcelf
        }
    ));
}
