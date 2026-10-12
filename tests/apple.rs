//! Apple images: Image4 files (`IMG4`, `IM4P`, `IM4M`, `IM4R`) written by
//! img4tool and built by hand in DER, with stored, LZFSE, LZSS, encrypted
//! and malformed payloads; and dyld shared cache headers of several
//! versions and architectures, with image listing, split-cache notes,
//! truncation and mutation sweeps.

use zrax::formats::apple::{self, Layout};
use zrax::formats::checksum::adler32;
use zrax::formats::container::Container;
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa, MetadataValue,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    apple::parse_container(data, layout).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    apple::parse_container(data, layout)
        .expect_err("is rejected")
        .to_string()
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
        .unwrap_or_else(|| panic!("metadata {key}: {:?}", payload.metadata))
        .to_string()
}

fn has_note(payload: &DetectionPayload, needle: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(needle))
}

fn assert_note(payload: &DetectionPayload, needle: &str) {
    assert!(
        has_note(payload, needle),
        "missing note {needle:?}: {:#?}",
        payload.notes
    );
}

/// Offset of the first occurrence of `needle` in `data`.
fn position(data: &[u8], needle: &[u8]) -> usize {
    data.windows(needle.len())
        .position(|w| w == needle)
        .expect("needle is present")
}

// DER encoding (ITU-T X.690), as Image4 uses it.

/// Definite length: short form below 128 B, otherwise the long form with
/// the fewest octets.
fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let octets: Vec<u8> = len
        .to_be_bytes()
        .into_iter()
        .skip_while(|&b| b == 0)
        .collect();
    let mut out = vec![0x80 | octets.len() as u8];
    out.extend_from_slice(&octets);
    out
}

/// Identifier octets, length octets, contents.
fn der(identifier: &[u8], contents: &[u8]) -> Vec<u8> {
    let mut out = identifier.to_vec();
    out.extend(der_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

/// Universal SEQUENCE (`0x30`) of the concatenated items.
fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    der(&[0x30], &items.concat())
}

/// Universal SET (`0x31`) of the concatenated items.
fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
    der(&[0x31], &items.concat())
}

fn ia5(text: &str) -> Vec<u8> {
    der(&[0x16], text.as_bytes())
}

fn octet_string(bytes: &[u8]) -> Vec<u8> {
    der(&[0x04], bytes)
}

/// Unsigned big-endian INTEGER contents with a leading zero octet when
/// the top bit is set.
fn integer(value: u64) -> Vec<u8> {
    let mut contents: Vec<u8> = value
        .to_be_bytes()
        .into_iter()
        .skip_while(|&b| b == 0)
        .collect();
    if contents.first().map_or(true, |&b| b & 0x80 != 0) {
        contents.insert(0, 0);
    }
    der(&[0x02], &contents)
}

/// Context-specific constructed `[n]` holding `inner`.
fn context(n: u8, inner: &[u8]) -> Vec<u8> {
    der(&[0xa0 | n], inner)
}

/// PRIVATE, constructed, high-tag-number identifier: `0xFF`, then the
/// four-character code read as a big-endian u32 in base-128 octets, the
/// continuation bit set on all but the last.
fn private_tag(fourcc: &[u8; 4]) -> Vec<u8> {
    let mut number = u32::from_be_bytes(*fourcc);
    let mut groups = vec![(number & 0x7f) as u8];
    number >>= 7;
    while number != 0 {
        groups.push(0x80 | (number & 0x7f) as u8);
        number >>= 7;
    }
    groups.push(0xff);
    groups.reverse();
    groups
}

/// An Image4 property: `[PRIVATE code] SEQUENCE { IA5String code, value }`.
fn property(fourcc: &[u8; 4], value: Vec<u8>) -> Vec<u8> {
    let name = std::str::from_utf8(fourcc).expect("ASCII code");
    der(&private_tag(fourcc), &sequence(&[ia5(name), value]))
}

/// `IM4P ::= SEQUENCE { "IM4P", type, description, OCTET STRING payload,
/// optional keybag, compression info and PAYP }`.
fn im4p(fourcc: &str, description: &str, payload: &[u8], optional: &[Vec<u8>]) -> Vec<u8> {
    let mut items = vec![
        ia5("IM4P"),
        ia5(fourcc),
        ia5(description),
        octet_string(payload),
    ];
    items.extend_from_slice(optional);
    sequence(&items)
}

/// Keybag `OCTET STRING` holding `SEQUENCE OF SEQUENCE { INTEGER type,
/// OCTET STRING iv (16 B), OCTET STRING key (32 B) }`: production (1) and
/// development (2) entries with placeholder bytes.
fn keybag() -> Vec<u8> {
    let entry = |kind: u64| {
        sequence(&[
            integer(kind),
            octet_string(&[0x11; 16]),
            octet_string(&[0x22; 32]),
        ])
    };
    octet_string(&sequence(&[entry(1), entry(2)]))
}

/// Compression info `SEQUENCE { INTEGER algorithm, INTEGER decoded size }`.
fn compression(algorithm: u64, size: u64) -> Vec<u8> {
    sequence(&[integer(algorithm), integer(size)])
}

/// `[0] EXPLICIT SEQUENCE { "PAYP", SET { properties } }` with two
/// placeholder properties.
fn payp() -> Vec<u8> {
    let set = der_set(&[
        property(b"test", integer(1)),
        property(b"zrax", octet_string(b"x")),
    ]);
    context(0, &sequence(&[ia5("PAYP"), set]))
}

/// `IMG4 ::= SEQUENCE { "IMG4", IM4P, [0] IM4M OPTIONAL, [1] IM4R OPTIONAL }`.
fn img4(payload: &[u8], manifest: Option<&[u8]>, restore_info: Option<&[u8]>) -> Vec<u8> {
    let mut items = vec![ia5("IMG4"), payload.to_vec()];
    if let Some(manifest) = manifest {
        items.push(context(0, manifest));
    }
    if let Some(restore_info) = restore_info {
        items.push(context(1, restore_info));
    }
    sequence(&items)
}

/// The complete 35-byte IM4R of the `PyIMG4` test fixtures
/// (`tests/bin/IM4R`, commit `80491329`): `SET { [BNCN] SEQUENCE { "BNCN",
/// OCTET STRING nonce (8 B) } }`.
const PYIMG4_IM4R: [u8; 35] = [
    0x30, 0x21, 0x16, 0x04, 0x49, 0x4d, 0x34, 0x52, 0x31, 0x19, 0xff, 0x84, 0x92, 0xb9, 0x86, 0x4e,
    0x12, 0x30, 0x10, 0x16, 0x04, 0x42, 0x4e, 0x43, 0x4e, 0x04, 0x08, 0x7c, 0xd2, 0xc2, 0xe8, 0xae,
    0xbb, 0x56, 0x5f,
];

// Mach-O headers (xnu `EXTERNAL_HEADERS/mach-o/loader.h`).

const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;
const CPU_TYPE_POWERPC: u32 = 18;
const CPU_SUBTYPE_ARM_V7: u32 = 9;
const MH_DYLIB: u32 = 6;
const LC_UUID: u32 = 0x1b;

/// `mach_header_64` (magic `0xFEEDFACF`, little-endian) with one 24-byte
/// `LC_UUID` command: 56 B.
fn macho64(cputype: u32) -> Vec<u8> {
    let mut header = Vec::new();
    for field in [0xfeed_facf, cputype, 0, MH_DYLIB, 1, 24, 0, 0] {
        header.extend_from_slice(&u32::to_le_bytes(field));
    }
    header.extend_from_slice(&LC_UUID.to_le_bytes());
    header.extend_from_slice(&24u32.to_le_bytes());
    header.extend_from_slice(&[0xab; 16]);
    header
}

/// `mach_header` (magic `0xFEEDFACE`) in either byte order with one
/// `LC_UUID` command: 52 B.
fn macho32(cputype: u32, cpusubtype: u32, big_endian: bool) -> Vec<u8> {
    let word = |v: u32| {
        if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let mut header = Vec::new();
    for field in [
        0xfeed_face,
        cputype,
        cpusubtype,
        MH_DYLIB,
        1,
        24,
        0,
        LC_UUID,
        24,
    ] {
        header.extend_from_slice(&word(field));
    }
    header.extend_from_slice(&[0xcd; 16]);
    header
}

// Apple LZSS (`complzss`): 0x180-byte big-endian header, then Okumura LZSS.

const COMP_HEADER_SIZE: usize = 0x180;

/// An all-literal LZSS stream: each flag byte `0xFF` (or fewer low bits for
/// the last group) announces up to eight literal bytes.
fn lzss_literals(bytes: &[u8]) -> Vec<u8> {
    let mut stream = Vec::new();
    for group in bytes.chunks(8) {
        stream.push(((1u16 << group.len()) - 1) as u8);
        stream.extend_from_slice(group);
    }
    stream
}

/// A raw LZVN stream (no `bvxn` block header): `lrg_l` opcodes (`0xE0`,
/// then the literal count minus 16) for 16 to 271 literals, `sml_l`
/// (`0xE0 | count`) for fewer, then the 8-byte end-of-stream opcode
/// `06 00 00 00 00 00 00 00`.
fn lzvn_literals(bytes: &[u8]) -> Vec<u8> {
    let mut stream = Vec::new();
    for run in bytes.chunks(271) {
        if run.len() >= 16 {
            stream.extend_from_slice(&[0xe0, (run.len() - 16) as u8]);
        } else {
            stream.push(0xe0 | run.len() as u8);
        }
        stream.extend_from_slice(run);
    }
    stream.extend_from_slice(&[0x06, 0, 0, 0, 0, 0, 0, 0]);
    stream
}

/// `comp` header with `compress_type` (`lzss` or `lzvn`): Adler-32 of the
/// decoded data, decoded size, stored size, `prelinkVersion` 1, zeros to
/// 0x180; then the stored stream.
fn comp_image(compress_type: &[u8; 4], decoded: &[u8], stream: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; COMP_HEADER_SIZE];
    image[..4].copy_from_slice(b"comp");
    image[4..8].copy_from_slice(compress_type);
    image[8..12].copy_from_slice(&adler32(decoded).to_be_bytes());
    image[12..16].copy_from_slice(&(decoded.len() as u32).to_be_bytes());
    image[16..20].copy_from_slice(&(stream.len() as u32).to_be_bytes());
    image[20..24].copy_from_slice(&1u32.to_be_bytes());
    image.extend_from_slice(stream);
    image
}

/// A `complzss` image of `decoded`.
fn complzss(decoded: &[u8]) -> Vec<u8> {
    comp_image(b"lzss", decoded, &lzss_literals(decoded))
}

#[test]
fn property_tags_match_the_published_encodings() {
    assert_eq!(private_tag(b"MANB"), [0xff, 0x84, 0xea, 0x85, 0x9c, 0x42]);
    assert_eq!(private_tag(b"BNCN"), [0xff, 0x84, 0x92, 0xb9, 0x86, 0x4e]);
    assert_eq!(private_tag(b"krnl"), [0xff, 0x86, 0xdb, 0xc9, 0xdc, 0x6c]);
    assert_eq!(&PYIMG4_IM4R[10..16], private_tag(b"BNCN").as_slice());
}

#[test]
fn img4tool_payloads_decode_to_the_kernel_macho() {
    let kernel = fixture("apple/kernel.macho");
    let cases: [(&str, &[u8], Option<&str>); 3] = [
        ("apple/krnl.im4p", &kernel[..8], None),
        ("apple/krnl.bvx2.im4p", b"bvx2", Some("LZFSE")),
        ("apple/krnl.complzss.im4p", b"complzss", Some("Apple LZSS")),
    ];
    for (name, start, transform) in cases {
        let file = fixture(name);
        assert!(
            matches!(detect_format(&file), DetectedFormat::Container { .. }),
            "{name}"
        );
        let c = parse(&file, Layout::Im4p);
        assert_eq!(c.format, FileFormat::Im4p, "{name}");
        assert_eq!(c.consumed, file.len(), "{name}");
        assert!(c.target.is_none(), "{name}: Image4 names no ISA");
        let [payload] = c.children.as_slice() else {
            panic!("{name}: {:?}", c.children);
        };
        assert_eq!(payload.label, "krnl", "{name}");
        assert_eq!(payload.data.as_ref(), kernel.as_slice(), "{name}");
        assert_eq!(payload.transform, transform, "{name}");
        assert!(!payload.opaque, "{name}");
        // The stored range is the whole OCTET STRING contents; only the
        // LZFSE payload is followed by its compression info.
        assert_eq!(payload.offset, position(&file, start), "{name}");
        let after = &file[payload.offset + payload.stored_size..];
        let expected_after = match transform {
            Some("LZFSE") => compression(1, kernel.len() as u64),
            _ => Vec::new(),
        };
        assert_eq!(after, expected_after.as_slice(), "{name}");

        let p = classify(&file);
        assert_eq!(p.format.format, FileFormat::Im4p, "{name}");
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
            (Isa::AArch64, 64, Endianness::Little),
            "{name}"
        );
        let [slice] = p.slices.as_slice() else {
            panic!("{name}: {:?}", p.slices);
        };
        assert_eq!(slice.label.as_deref(), Some("krnl"));
        assert_eq!(slice.isa, Isa::AArch64);
        assert_eq!(slice.offset, payload.offset as u64);
        assert_eq!(
            slice
                .decoded
                .as_ref()
                .map(|d| (d.transform.as_str(), d.size)),
            transform.map(|t| (t, kernel.len() as u64)),
            "{name}"
        );
        assert_note(&p, "Primary ISA selected from krnl");
        assert_note(&p, "Type krnl is the KernelCache (xnu img4/firmware.h)");
        assert_note(&p, "Image4 fields name no ISA");
        assert_eq!(metadata_text(&p, "apple_im4p_type"), "krnl");
        assert_eq!(
            metadata_text(&p, "apple_im4p_description"),
            "zrax synthetic kernelcache"
        );
    }

    let lzfse = classify(&fixture("apple/krnl.bvx2.im4p"));
    assert_eq!(
        metadata_text(&lzfse, "apple_im4p_compression_algorithm"),
        "1"
    );
    assert_eq!(metadata_text(&lzfse, "apple_im4p_decoded_size"), "8192");
    assert_note(&lzfse, "decoded size matches the compression info");
    let lzss = classify(&fixture("apple/krnl.complzss.im4p"));
    assert_note(&lzss, "complzss header; Apple LZSS");
    assert_note(&lzss, "Adler-32 verified");
}

#[test]
fn img4tool_img4_reports_manifest_and_nonce_without_verifying() {
    let file = fixture("apple/krnl.img4");
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Img4);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.slices.len(), 1, "the manifest is metadata, not a slice");
    assert_eq!(p.slices[0].label.as_deref(), Some("krnl"));
    assert_note(
        &p,
        "Image4 file: IM4P payload; IM4M manifest; IM4R restore info",
    );
    assert_note(
        &p,
        "IM4M manifest version 0: 1 image entry; signature (256 B) and certificate chain (8 B) present; not verified",
    );
    assert_eq!(metadata_text(&p, "apple_im4m_images"), "krnl");
    assert_eq!(metadata_text(&p, "apple_im4m_properties"), "CHIP, BORD");
    assert_eq!(metadata_text(&p, "apple_im4m_chip"), "0x8030");
    assert_eq!(metadata_text(&p, "apple_im4m_board"), "0xC");
    // img4tool stores the generator 0x1122334455667788 little-endian.
    assert_eq!(metadata_text(&p, "apple_im4r_nonce"), "8877665544332211");
    let manifest = fixture("apple/synthetic.im4m");
    assert_eq!(
        metadata_text(&p, "apple_im4m_offset"),
        format!("0x{:X}", position(&file, &manifest))
    );
}

#[test]
fn standalone_manifest_and_restore_info_are_metadata_only() {
    let manifest = fixture("apple/synthetic.im4m");
    assert_eq!(apple::detect(&manifest), Some(Layout::Im4m));
    let p = classify(&manifest);
    assert_eq!(p.format.format, FileFormat::Img4);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.slices.is_empty());
    assert!(
        p.candidates.is_empty(),
        "a manifest never reaches the code model"
    );
    assert_note(&p, "Standalone Image4 manifest (IM4M); metadata only");
    assert_note(&p, "not verified");

    assert_eq!(apple::detect(&PYIMG4_IM4R), Some(Layout::Im4r));
    let p = classify(&PYIMG4_IM4R);
    assert_eq!(p.format.format, FileFormat::Img4);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert_note(&p, "IM4R restore info: BNCN");
    assert_eq!(metadata_text(&p, "apple_im4r_nonce"), "7CD2C2E8AEBB565F");
}

#[test]
fn hand_built_img4_with_manifest_and_restore_info() {
    let manp = property(
        b"MANP",
        der_set(&[
            property(b"CHIP", integer(0x8101)),
            property(b"ECID", integer(0x0012_3456_789a_bcde)),
        ]),
    );
    let image_group = property(
        b"ibot",
        der_set(&[property(b"DGST", octet_string(&[0; 48]))]),
    );
    let manb = property(b"MANB", der_set(&[manp, image_group]));
    // An unsigned manifest leaves out the signature and certificate chain.
    let manifest = sequence(&[ia5("IM4M"), integer(0), der_set(&[manb])]);
    let payload = im4p("ibot", "iBoot-0000.0.0", &macho64(CPU_TYPE_ARM64), &[]);
    let file = img4(&payload, Some(&manifest), Some(&PYIMG4_IM4R));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Img4);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.slices[0].label.as_deref(), Some("ibot"));
    assert_note(&p, "IM4M manifest version 0: 1 image entry; no signature");
    assert_note(&p, "IM4P type ibot; description \"iBoot-0000.0.0\"");
    assert!(
        !has_note(&p, "KernelCache"),
        "only krnl's meaning is confirmed"
    );
    assert_eq!(metadata_text(&p, "apple_im4m_chip"), "0x8101");
    assert!(
        metadata(&p, "apple_im4m_ecid").is_none(),
        "the device ECID is not reported"
    );
    assert_eq!(metadata_text(&p, "apple_im4r_nonce"), "7CD2C2E8AEBB565F");

    // IMG4 without the optional parts.
    let bare = img4(&payload, None, None);
    let p = classify(&bare);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_note(
        &p,
        "Image4 file: IM4P payload; no IM4M manifest; no IM4R restore info",
    );
}

#[test]
fn encrypted_payloads_stay_opaque() {
    // The ciphertext stand-in is a valid complzss image of a Mach-O, so any
    // attempt to decode or classify it would show.
    let ciphertext = complzss(&macho64(CPU_TYPE_ARM64));
    let file = im4p("krnl", "", &ciphertext, &[keybag(), compression(1, 56)]);
    let c = parse(&file, Layout::Im4p);
    let [payload] = c.children.as_slice() else {
        panic!("{:?}", c.children);
    };
    assert!(payload.opaque);
    assert_eq!(payload.transform, None);
    assert_eq!(payload.offset, position(&file, b"complzss"));
    assert_eq!(payload.stored_size, ciphertext.len());

    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Im4p);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
    assert_note(
        &p,
        "krnl payload: encrypted; keybag present (2 keybags: production, development); not decrypted",
    );
    assert_note(&p, "describes the plaintext");
    assert_note(&p, "IM4P type krnl; empty description");
    assert_eq!(
        metadata_text(&p, "apple_im4p_keybags"),
        "2 keybags: production, development"
    );
}

#[test]
fn compression_info_must_match_the_decoded_payload() {
    let stream = fixture("compressed/payload.elf.lzfse");
    let decoded_size = fixture("compressed/payload.elf").len() as u64;
    let file = im4p("rkrn", "test", &stream, &[compression(1, decoded_size)]);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Im4p);
    assert_eq!(p.primary.isa, Isa::X86_64, "from the decoded ELF");
    assert_eq!(p.slices[0].label.as_deref(), Some("rkrn"));
    assert_eq!(
        p.slices[0].decoded.as_ref().map(|d| d.size),
        Some(decoded_size)
    );

    let rejected = [
        (
            compression(1, decoded_size + 44),
            "compression info declares 300 B; not used",
        ),
        (compression(1, decoded_size - 1), "does not decode as LZFSE"),
        (
            compression(2, decoded_size),
            "unsupported compression algorithm 2; not decoded",
        ),
        (
            compression(1, u64::MAX),
            "beyond the 64 MiB extraction limit",
        ),
    ];
    for (info, reason) in rejected {
        let file = im4p("rkrn", "test", &stream, &[info]);
        let c = parse(&file, Layout::Im4p);
        assert!(c.children[0].opaque, "{reason}");
        let p = classify(&file);
        assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{reason}");
        assert!(p.candidates.is_empty(), "{reason}");
        assert_note(&p, reason);
    }

    // Without compression info, a payload that starts with an LZFSE block
    // magic is still decoded, and the note says the size was not declared.
    let p = classify(&im4p("rkrn", "test", &stream, &[]));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_note(
        &p,
        "no compression info, so the decoded size is not declared",
    );
}

#[test]
fn complzss_payloads_verify_adler32_and_list_an_appended_image() {
    let kernel = macho64(CPU_TYPE_ARM64);
    let compressed = complzss(&kernel);
    // Bytes after the compressed stream: an appended x86-64 Mach-O stands in
    // for the appended images real kernelcaches carry.
    let trailer = macho64(CPU_TYPE_X86_64);
    let mut payload = compressed.clone();
    payload.extend_from_slice(&trailer);
    let file = im4p("krnl", "", &payload, &[]);
    let c = parse(&file, Layout::Im4p);
    let [image, appended] = c.children.as_slice() else {
        panic!("{:?}", c.children);
    };
    let start = position(&file, b"complzss");
    assert_eq!(
        (image.offset, image.stored_size, image.transform),
        (start, compressed.len(), Some("Apple LZSS"))
    );
    assert_eq!(image.data.as_ref(), kernel.as_slice());
    assert_eq!(appended.label, "krnl trailer");
    assert_eq!(
        (appended.offset, appended.stored_size),
        (start + compressed.len(), trailer.len())
    );

    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.slices.len(), 2);
    assert_eq!(p.slices[1].label.as_deref(), Some("krnl trailer"));
    assert_eq!(
        p.slices[1].isa,
        Isa::X86_64,
        "classified from its own header"
    );
    assert_note(&p, "B follow the compressed stream");

    // A wrong Adler-32 makes the payload opaque instead of trusted.
    let mut corrupt = compressed.clone();
    corrupt[8] ^= 0x01;
    let p = classify(&im4p("krnl", "", &corrupt, &[]));
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert_note(&p, "krnl payload: does not decode as Apple LZSS");
}

#[test]
fn complzvn_payloads_decode_as_raw_lzvn() {
    let kernel = macho64(CPU_TYPE_ARM64);
    let compressed = comp_image(b"lzvn", &kernel, &lzvn_literals(&kernel));
    let file = im4p("krnl", "", &compressed, &[]);
    let c = parse(&file, Layout::Im4p);
    let [image] = c.children.as_slice() else {
        panic!("{:?}", c.children);
    };
    assert_eq!(image.data.as_ref(), kernel.as_slice());
    assert_eq!(image.transform, Some("Apple LZSS"));
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_note(&p, "complzvn header; Apple LZSS");
}

#[test]
fn stored_payloads_and_payload_properties() {
    let file = im4p("sepi", "", &macho64(CPU_TYPE_ARM64), &[payp()]);
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.slices[0].label.as_deref(), Some("sepi"));
    assert!(p.slices[0].decoded.is_none());
    assert_note(
        &p,
        "IM4P payload properties (PAYP): test, zrax; meaning not interpreted",
    );
}

#[test]
fn raw_code_payloads_reach_the_code_model() {
    // Bare AArch64 instructions without a header, as raw boot stages carry.
    let code = fixture("transforms/aarch64.text.bin");
    let file = im4p("ibot", "", &code, &[]);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::Im4p);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(!p.candidates.is_empty(), "ranked by the code model");
    assert_eq!(p.slices[0].label.as_deref(), Some("ibot"));
    assert_eq!(p.slices[0].size, code.len() as u64);
}

#[test]
fn every_der_length_form_is_detected() {
    let payload = [0x5a; 120];
    let short = im4p("krnl", "", &payload[..8], &[]);
    assert_eq!(short[1] & 0x80, 0, "short form");
    let one = im4p("krnl", "", &payload, &[]);
    assert_eq!(one[1], 0x81);
    let two = im4p("krnl", "", &[0u8; 300], &[]);
    assert_eq!(two[1], 0x82);
    for file in [&short, &one, &two] {
        assert_eq!(apple::detect(file), Some(Layout::Im4p));
    }
    // A four-octet length is accepted even where a shorter one would do.
    let mut four = vec![0x30, 0x84, 0, 0, 0, (one.len() - 3) as u8];
    four.extend_from_slice(&one[3..]);
    assert_eq!(apple::detect(&four), Some(Layout::Im4p));
    assert_eq!(
        parse(&four, Layout::Im4p).children[0].data.as_ref(),
        payload.as_slice()
    );

    // Other DER documents are not Image4.
    assert_eq!(apple::detect(&sequence(&[ia5("IM4X")])), None);
    assert_eq!(apple::detect(&sequence(&[octet_string(b"IM4P")])), None);
    assert_eq!(apple::detect(&der_set(&[ia5("IM4P")])), None);
}

#[test]
fn malformed_der_is_an_error_naming_the_offset() {
    let good = im4p("krnl", "", &macho64(CPU_TYPE_ARM64), &[]);

    let mut indefinite = good.clone();
    indefinite[1] = 0x80;
    assert_eq!(
        parse_error(&indefinite, Layout::Im4p),
        "Apple image parse error: Invalid indefinite DER length at 0x0"
    );

    let mut five_octets = vec![0x30, 0x85, 0, 0, 0, 0, good.len() as u8 - 3];
    five_octets.extend_from_slice(&good[3..]);
    assert!(parse_error(&five_octets, Layout::Im4p).contains("Unsupported 5-octet DER length"));

    let truncated = &good[..good.len() - 1];
    assert!(parse_error(truncated, Layout::Im4p).contains("Truncated DER element at 0x0"));

    let mut trailing = good.clone();
    trailing.extend_from_slice(b"junk");
    assert_eq!(
        parse_error(&trailing, Layout::Im4p),
        format!(
            "Apple image parse error: Unexpected 4 B after the IM4P SEQUENCE at 0x{:X}",
            good.len()
        )
    );
    // Erased-flash padding after the image is accepted.
    let mut padded = good.clone();
    padded.extend_from_slice(&[0xff; 16]);
    assert_eq!(parse(&padded, Layout::Im4p).consumed, good.len());

    let bad_type = im4p("kernel", "", b"data", &[]);
    assert!(parse_error(&bad_type, Layout::Im4p).contains("Invalid IM4P type"));

    let extra = im4p("krnl", "", b"data", &[integer(7)]);
    assert!(parse_error(&extra, Layout::Im4p).contains("Unknown IM4P element 0x02"));

    let twice = im4p("krnl", "", b"data", &[compression(1, 4), compression(1, 4)]);
    assert!(parse_error(&twice, Layout::Im4p).contains("Duplicate IM4P element 0x30"));
    let payload = im4p("krnl", "", b"data", &[]);
    let manifest = sequence(&[
        ia5("IM4M"),
        integer(0),
        der_set(&[property(b"MANB", der_set(&[]))]),
    ]);
    let doubled = sequence(&[
        ia5("IMG4"),
        payload,
        context(0, &manifest),
        context(0, &manifest),
    ]);
    assert!(parse_error(&doubled, Layout::Img4).contains("Duplicate IMG4 element 0xA0"));
    let missing = sequence(&[ia5("IM4P"), ia5("krnl")]);
    assert!(parse_error(&missing, Layout::Im4p).contains("Missing IM4P elements at 0x0"));

    let short_iv = octet_string(&sequence(&[sequence(&[
        integer(1),
        octet_string(&[0; 8]),
        octet_string(&[0; 32]),
    ])]));
    let bad_keybag = im4p("krnl", "", b"data", &[short_iv]);
    assert!(parse_error(&bad_keybag, Layout::Im4p).contains("Invalid IM4P keybag entry"));

    // Element inside its parent: a payload that claims more than the IM4P.
    let mut overlong = good.clone();
    let payload_length = position(&overlong, &[0x04, 0x38]);
    overlong[payload_length + 1] = 0x7f;
    assert!(parse_error(&overlong, Layout::Im4p).contains("Truncated DER element"));

    // A property tag must repeat its code in the name.
    let wrong_name = der(
        &private_tag(b"BNCN"),
        &sequence(&[ia5("BNCH"), octet_string(&[0; 8])]),
    );
    let restore_info = sequence(&[ia5("IM4R"), der_set(&[wrong_name])]);
    assert!(parse_error(&restore_info, Layout::Im4r).contains("the name does not repeat the tag"));

    // A manifest body must be a single MANB property.
    let not_manb = sequence(&[
        ia5("IM4M"),
        integer(0),
        der_set(&[property(b"MANP", der_set(&[]))]),
    ]);
    assert!(parse_error(&not_manb, Layout::Im4m).contains("Missing IM4M MANB property"));

    // An IMG4 must open with its own magic and hold an IM4P.
    assert!(parse_error(&good, Layout::Img4).contains("Missing IMG4 magic"));
    let no_payload = sequence(&[ia5("IMG4"), octet_string(b"data")]);
    assert!(parse_error(&no_payload, Layout::Img4).contains("Invalid IM4P"));
}

// dyld shared caches (dyld-1378 `include/mach-o/dyld_cache_format.h`).

/// Unslid address of file offset 0 in `dyld_cache`.
const CACHE_ADDRESS: u64 = 0x1_8000_0000;

/// Address of images that live in another cache file.
const OTHER_FILE_ADDRESS: u64 = 0x2_0000_0000;

/// Header sizes (`mappingOffset`) written by dyld-1378, dyld-519.2.2 and
/// dyld-97.1.
const HEADER_1378: usize = 0x228;
const HEADER_519: usize = 0x98;
const HEADER_97: usize = 0x28;

/// One `dyld_cache_image_info` entry and the bytes at its address.
struct CacheImage<'a> {
    path: &'a str,
    /// Mach-O header stored in this file, or `None` for an image in
    /// another cache file.
    macho: Option<Vec<u8>>,
}

fn put_u32(data: &mut [u8], at: usize, value: u32, big_endian: bool) {
    let bytes = if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    data[at..at + 4].copy_from_slice(&bytes);
}

fn put_u64(data: &mut [u8], at: usize, value: u64, big_endian: bool) {
    let bytes = if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    data[at..at + 8].copy_from_slice(&bytes);
}

/// A dyld shared cache file:
/// - 0x000 magic: `dyld_v1`, spaces, the right-aligned token, NUL at 15;
/// - 0x010 `mappingOffset` = `header_size`, 0x014 `mappingCount` = 1;
/// - images at `imagesOffset`/`imagesCount` (0x1C0/0x1C4) when the header
///   reaches `imagesCount`, else at the old fields 0x018/0x01C;
/// - at `header_size`, one `dyld_cache_mapping_info` mapping the whole file
///   at [`CACHE_ADDRESS`], `r-x`;
/// - then the 32-byte `dyld_cache_image_info` entries (address, mtime,
///   inode, `pathFileOffset`), the NUL-terminated paths, and the Mach-O
///   headers, each on a 0x100 boundary.
fn dyld_cache(token: &str, header_size: usize, big_endian: bool, images: &[CacheImage]) -> Vec<u8> {
    let mut magic = format!("dyld_v1{token:>8}").into_bytes();
    assert_eq!(magic.len(), 15, "token {token} fits the magic");
    magic.push(0);
    let mapping_offset = header_size;
    let table_offset = mapping_offset + 32;
    let paths_offset = table_offset + 32 * images.len();
    let paths_size: usize = images.iter().map(|i| i.path.len() + 1).sum();
    let image_area = (paths_offset + paths_size + 0xff) & !0xff;
    let file_size = image_area + 0x100 * images.len();
    let mut file = vec![0u8; file_size.max(header_size)];
    file[..16].copy_from_slice(&magic);
    put_u32(&mut file, 0x10, mapping_offset as u32, big_endian);
    put_u32(&mut file, 0x14, 1, big_endian);
    let (images_offset_field, images_count_field) = if header_size >= 0x1c4 {
        (0x1c0, 0x1c4)
    } else {
        (0x18, 0x1c)
    };
    put_u32(
        &mut file,
        images_offset_field,
        table_offset as u32,
        big_endian,
    );
    put_u32(
        &mut file,
        images_count_field,
        images.len() as u32,
        big_endian,
    );
    // dyld_cache_mapping_info: address, size, fileOffset, maxProt, initProt.
    put_u64(&mut file, mapping_offset, CACHE_ADDRESS, big_endian);
    let mapped_size = file.len() as u64;
    put_u64(&mut file, mapping_offset + 8, mapped_size, big_endian);
    put_u64(&mut file, mapping_offset + 16, 0, big_endian);
    put_u32(&mut file, mapping_offset + 24, 5, big_endian);
    put_u32(&mut file, mapping_offset + 28, 5, big_endian);
    let mut path_at = paths_offset;
    for (i, image) in images.iter().enumerate() {
        let entry = table_offset + 32 * i;
        let image_offset = image_area + 0x100 * i;
        let address = match &image.macho {
            Some(macho) => {
                file[image_offset..image_offset + macho.len()].copy_from_slice(macho);
                CACHE_ADDRESS + image_offset as u64
            }
            None => OTHER_FILE_ADDRESS + 0x1000 * i as u64,
        };
        put_u64(&mut file, entry, address, big_endian);
        put_u32(&mut file, entry + 0x18, path_at as u32, big_endian);
        file[path_at..path_at + image.path.len()].copy_from_slice(image.path.as_bytes());
        path_at += image.path.len() + 1;
    }
    file
}

/// An arm64e cache with a mapped `libSystem` and an unmapped `libobjc`,
/// UUID bytes 0x10..0x1F and platform 2 (iOS).
fn arm64e_cache() -> Vec<u8> {
    let mut file = dyld_cache(
        "arm64e",
        HEADER_1378,
        false,
        &[
            CacheImage {
                path: "/usr/lib/libSystem.B.dylib",
                macho: Some(macho64(CPU_TYPE_ARM64)),
            },
            CacheImage {
                path: "/usr/lib/libobjc.A.dylib",
                macho: None,
            },
        ],
    );
    for (i, b) in file[0x58..0x68].iter_mut().enumerate() {
        *b = 0x10 + i as u8;
    }
    put_u32(&mut file, 0xd8, 2, false);
    file
}

#[test]
fn arm64e_cache_names_aarch64_and_lists_mapped_images() {
    let file = arm64e_cache();
    assert_eq!(apple::detect(&file), Some(Layout::DyldCache));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::DyldCache);
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::AArch64, 64, Endianness::Little)
    );
    assert_eq!(p.primary.confidence, 1.0);
    let [slice] = p.slices.as_slice() else {
        panic!("{:?}", p.slices);
    };
    assert_eq!(slice.label.as_deref(), Some("/usr/lib/libSystem.B.dylib"));
    assert_eq!(slice.isa, Isa::AArch64);
    assert_eq!(slice.size, 56, "Mach-O header and load commands");
    assert_eq!(slice.offset % 0x100, 0);
    assert_note(
        &p,
        "dyld shared cache; architecture token arm64e; 552 B little-endian header",
    );
    assert_note(&p, "arm64e: AArch64 with the pointer-authentication ABI");
    assert_note(
        &p,
        "2 images (imagesOffset); 2 read; Mach-O header in this file: 1, listed with header and load commands; Mach-O header not in this file (for example in a subcache file): 1",
    );
    assert_note(&p, "1 mapping");
    assert_eq!(metadata_text(&p, "apple_dyld_architecture"), "arm64e");
    assert_eq!(metadata_text(&p, "apple_dyld_image_count"), "2");
    assert_eq!(metadata_text(&p, "apple_dyld_platform"), "iOS");
    assert_eq!(
        metadata_text(&p, "apple_dyld_uuid"),
        "10111213-1415-1617-1819-1A1B1C1D1E1F"
    );
    assert!(metadata_text(&p, "apple_dyld_mapping_0").contains("max r-x; initial r-x"));
    let unmapped = p
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == "apple_dyld_unmapped_image_0"))
        .expect("unmapped image entry");
    assert_eq!(unmapped.label, "/usr/lib/libobjc.A.dylib");
    assert!(unmapped.value.to_string().contains("address 0x200001000"));
}

#[test]
fn architecture_tokens_name_the_target() {
    let cases = [
        ("arm64", Isa::AArch64, 64, Endianness::Little),
        ("arm64e", Isa::AArch64, 64, Endianness::Little),
        ("arm64_32", Isa::AArch64, 32, Endianness::Little),
        ("x86_64", Isa::X86_64, 64, Endianness::Little),
        ("x86_64h", Isa::X86_64, 64, Endianness::Little),
        ("i386", Isa::X86, 32, Endianness::Little),
        ("armv5", Isa::Arm, 32, Endianness::Little),
        ("armv6", Isa::Arm, 32, Endianness::Little),
        ("armv7", Isa::Arm, 32, Endianness::Little),
        ("armv7f", Isa::Arm, 32, Endianness::Little),
        ("armv7s", Isa::Arm, 32, Endianness::Little),
        ("armv7k", Isa::Arm, 32, Endianness::Little),
        ("ppc", Isa::Ppc, 32, Endianness::Big),
        ("ppc64", Isa::Ppc64, 64, Endianness::Big),
    ];
    for (token, isa, bits, endianness) in cases {
        let big_endian = endianness == Endianness::Big;
        let file = dyld_cache(token, HEADER_519, big_endian, &[]);
        let p = classify(&file);
        assert_eq!(p.format.format, FileFormat::DyldCache, "{token}");
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
            (isa, bits, endianness),
            "{token}"
        );
        assert_note(&p, "Header lists no images (imagesOffsetOld)");
        assert_eq!(metadata_text(&p, "apple_dyld_architecture"), token);
    }
    let p = classify(&dyld_cache("arm64_32", HEADER_519, false, &[]));
    assert_note(&p, "AArch64 instructions with 32-bit pointers (ILP32)");
    let p = classify(&dyld_cache("ppc", HEADER_97, true, &[]));
    assert_note(&p, "PowerPC cache; big-endian header and tables");
}

#[test]
fn older_headers_read_the_old_image_fields() {
    let file = dyld_cache(
        "armv7",
        HEADER_519,
        false,
        &[CacheImage {
            path: "/usr/lib/libSystem.B.dylib",
            macho: Some(macho32(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, false)),
        }],
    );
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].isa, Isa::Arm);
    assert_eq!(p.slices[0].size, 52);
    assert_note(
        &p,
        "1 image (imagesOffsetOld); 1 read; Mach-O header in this file: 1",
    );

    // dyld-97.1: a 0x28-byte big-endian PowerPC header.
    let file = dyld_cache(
        "ppc",
        HEADER_97,
        true,
        &[CacheImage {
            path: "/usr/lib/libSystem.B.dylib",
            macho: Some(macho32(CPU_TYPE_POWERPC, 0, true)),
        }],
    );
    let p = classify(&file);
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Ppc, Endianness::Big)
    );
    assert_eq!(p.slices.len(), 1);
    assert_eq!(
        (p.slices[0].isa, p.slices[0].endianness),
        (Isa::Ppc, Endianness::Big)
    );
    assert_note(&p, "40 B big-endian header");
    assert!(
        metadata(&p, "apple_dyld_uuid").is_none(),
        "dyld-97.1 has no UUID"
    );
}

#[test]
fn arm64_32_images_agree_with_the_token() {
    let file = dyld_cache(
        "arm64_32",
        HEADER_1378,
        false,
        &[CacheImage {
            path: "/usr/lib/libSystem.B.dylib",
            macho: Some(macho32(CPU_TYPE_ARM64_32, 1, false)),
        }],
    );
    let p = classify(&file);
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::AArch64, 32));
    assert_eq!((p.slices[0].isa, p.slices[0].bitwidth), (Isa::AArch64, 32));
    assert!(!has_note(&p, "container names"), "{:#?}", p.notes);
}

#[test]
fn unknown_tokens_take_the_isa_from_the_images() {
    // armv4t could be written by old builders but no reader lists it.
    let file = dyld_cache(
        "armv4t",
        HEADER_519,
        false,
        &[CacheImage {
            path: "/usr/lib/libfoo.dylib",
            macho: Some(macho32(CPU_TYPE_ARM, 5, false)),
        }],
    );
    let c = parse(&file, Layout::DyldCache);
    assert!(c.target.is_none());
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_note(&p, "Unknown architecture token armv4t");
    assert_note(&p, "Primary ISA selected from /usr/lib/libfoo.dylib");
}

#[test]
fn an_image_cputype_mismatch_is_a_note_not_an_override() {
    let file = dyld_cache(
        "arm64",
        HEADER_1378,
        false,
        &[CacheImage {
            path: "/usr/lib/libx86.dylib",
            macho: Some(macho64(CPU_TYPE_X86_64)),
        }],
    );
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::AArch64, "the magic's token wins");
    assert_eq!(
        p.slices[0].isa,
        Isa::X86_64,
        "the image keeps its own header"
    );
    assert_note(&p, "/usr/lib/libx86.dylib: container names");
}

#[test]
fn split_caches_name_their_subcache_and_symbol_files() {
    let mut file = arm64e_cache();
    // Two dyld_subcache_entry records (56 B: UUID, cacheVMOffset, fileSuffix)
    // appended at the end of the file.
    let entries = file.len();
    file.resize(entries + 2 * 56, 0);
    for (i, suffix) in [".01", ".02"].iter().enumerate() {
        let at = entries + 56 * i + 0x18;
        file[at..at + suffix.len()].copy_from_slice(suffix.as_bytes());
    }
    put_u32(&mut file, 0x188, entries as u32, false);
    put_u32(&mut file, 0x18c, 2, false);
    file[0x190..0x1a0].fill(0x5a);
    let p = classify(&file);
    assert_note(
        &p,
        "Split cache: 2 subcache files (.01, .02); their mappings and images are not in this file",
    );
    assert_note(
        &p,
        "Local symbols are in a separate .symbols file (UUID 5A5A5A5A-5A5A-5A5A-5A5A-5A5A5A5A5A5A)",
    );
    assert_eq!(metadata_text(&p, "apple_dyld_subcaches"), "2");

    // Headers that end at `cacheSubType` use 24-byte entries without a
    // suffix; the files are named `.1`, `.2`, ...
    let mut file = dyld_cache("arm64", 0x1c8, false, &[]);
    let entries = file.len();
    file.resize(entries + 3 * 24, 0);
    put_u32(&mut file, 0x188, entries as u32, false);
    put_u32(&mut file, 0x18c, 3, false);
    let p = classify(&file);
    assert_note(&p, "Split cache: 3 subcache files (.1, .2, .3)");
}

#[test]
fn code_signatures_and_local_symbols_are_noted_not_verified() {
    let mut file = arm64e_cache();
    let end = file.len() as u64;
    put_u64(&mut file, 0x28, end, false);
    put_u64(&mut file, 0x30, 0, false);
    put_u64(&mut file, 0x48, 0x4000, false);
    put_u64(&mut file, 0x50, 0x200, false);
    let p = classify(&file);
    assert_note(
        &p,
        &format!("Code signature at file 0x{end:X}, to the end of the file; not verified"),
    );
    assert_note(&p, "Local symbols at file 0x4000, 512 B");
}

#[test]
fn image_lists_are_bounded() {
    let paths: Vec<String> = (0..300).map(|i| format!("/usr/lib/lib{i}.dylib")).collect();
    let images: Vec<CacheImage> = paths
        .iter()
        .map(|path| CacheImage { path, macho: None })
        .collect();
    let file = dyld_cache("arm64", HEADER_1378, false, &images);
    let p = classify(&file);
    assert_note(
        &p,
        "300 images (imagesOffset); 256 read; Mach-O header in this file: 0, listed with header and load commands; Mach-O header not in this file (for example in a subcache file): 256; 44 not read (limit 256)",
    );
    let listed = p
        .metadata
        .iter()
        .filter(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k.starts_with("apple_dyld_unmapped_image_")))
        .count();
    assert_eq!(listed, 16);
}

#[test]
fn image_paths_need_a_first_mapping_at_file_offset_zero() {
    // No mappings at all: the header still names the target.
    let mut file = arm64e_cache();
    put_u32(&mut file, 0x14, 0, false);
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(p.slices.is_empty());
    assert_note(&p, "Header declares no mappings; this file maps no code");
    assert_note(
        &p,
        "2 images (imagesOffset); the first mapping does not start at file offset 0, so image paths are not read",
    );

    // dyld's `hasImagePath` reads paths only when the first mapping holds
    // the header at file offset 0.
    let mut file = arm64e_cache();
    put_u64(&mut file, HEADER_1378 + 16, 0x100, false);
    let p = classify(&file);
    assert!(p.slices.is_empty());
    assert_note(&p, "so image paths are not read");
}

#[test]
fn malformed_cache_headers_are_errors() {
    let good = arm64e_cache();
    let error = |mutate: &dyn Fn(&mut Vec<u8>)| {
        let mut file = good.clone();
        mutate(&mut file);
        parse_error(&file, Layout::DyldCache)
    };
    assert!(error(&|f| f[15] = b'!').contains("byte 15 is 0x21, expected NUL"));
    assert!(error(&|f| f[7..15].copy_from_slice(b"  arm 64"))
        .contains("Invalid dyld cache architecture token"));
    assert!(
        error(&|f| put_u32(f, 0x10, 0x20, false)).contains("Invalid dyld cache mappingOffset 0x20")
    );
    assert!(error(&|f| put_u32(f, 0x10, 0x800, false))
        .contains("Invalid dyld cache mappingOffset 0x800"));
    assert!(error(&|f| put_u32(f, 0x14, 21, false)).contains("Invalid dyld cache mappingCount 21"));
    assert!(error(&|f| put_u32(f, 0x1c4, 0x0100_0000, false))
        .contains("Truncated dyld cache image table"));
    assert!(error(&|f| put_u64(f, HEADER_1378 + 8, u64::MAX, false)).contains("overflows"));
    let path_field = 0x1c0;
    let table = u32::from_le_bytes(good[path_field..path_field + 4].try_into().unwrap()) as usize;
    assert!(error(&|f| put_u32(f, table + 0x18, 0x00ff_ffff, false))
        .contains("beyond the end of the file"));
    assert!(error(&|f| {
        let len = f.len();
        put_u32(f, table + 0x18, (len - 1) as u32, false);
        f[len - 1] = b'x';
    })
    .contains("no NUL"));
    assert!(parse_error(b"dyld_v1   arm64", Layout::DyldCache).contains("Truncated"));
}

#[test]
fn truncated_caches_never_list_bytes_beyond_the_file() {
    let file = arm64e_cache();
    for end in 0..file.len() {
        let prefix = &file[..end];
        match apple::parse_container(prefix, Layout::DyldCache) {
            Ok(c) => {
                for child in &c.children {
                    assert!(child.offset + child.stored_size <= end, "prefix {end}");
                }
                assert!(
                    c.notes
                        .iter()
                        .any(|n| n.contains("extending beyond the end")),
                    "prefix {end}: {:?}",
                    c.notes
                );
            }
            Err(e) => assert!(e.to_string().starts_with("Apple image parse error"), "{e}"),
        }
    }
}

#[test]
fn every_image4_prefix_is_an_error() {
    let files = [
        fixture("apple/krnl.im4p"),
        fixture("apple/krnl.bvx2.im4p"),
        fixture("apple/krnl.complzss.im4p"),
        fixture("apple/krnl.img4"),
        fixture("apple/synthetic.im4m"),
        PYIMG4_IM4R.to_vec(),
    ];
    for file in &files {
        let layout = apple::detect(file).expect("detected");
        for end in 0..file.len() {
            assert!(
                apple::parse_container(&file[..end], layout).is_err(),
                "{layout:?} prefix {end}"
            );
            if let Ok(p) = detect_payload(&file[..end], &ClassifierOptions::new()) {
                // Too short to carry the magic: not recognized as Image4.
                assert!(
                    !matches!(p.format.format, FileFormat::Img4 | FileFormat::Im4p),
                    "{layout:?} prefix {end}"
                );
            }
        }
    }
}

#[test]
fn apple_images_survive_byte_mutations() {
    let kernel = macho64(CPU_TYPE_ARM64);
    let mut files = vec![
        fixture("apple/krnl.bvx2.im4p"),
        fixture("apple/krnl.complzss.im4p"),
        fixture("apple/krnl.img4"),
        fixture("apple/synthetic.im4m"),
        PYIMG4_IM4R.to_vec(),
        im4p(
            "krnl",
            "",
            &complzss(&kernel),
            &[keybag(), compression(1, 56), payp()],
        ),
        arm64e_cache(),
        dyld_cache(
            "ppc",
            HEADER_97,
            true,
            &[CacheImage {
                path: "/usr/lib/libSystem.B.dylib",
                macho: Some(macho32(CPU_TYPE_POWERPC, 0, true)),
            }],
        ),
    ];
    // The stored fixture's 8 KiB payload is filler; mutate its DER header
    // and the start of the Mach-O.
    files.push(fixture("apple/krnl.im4p")[..0x80].to_vec());
    for file in &files {
        for i in 0..file.len() {
            for value in [0x00, 0xff, file[i] ^ 0x01, file[i] ^ 0x80] {
                let mut mutated = file.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}
