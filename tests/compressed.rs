//! Standalone compressed streams: every codec decodes the synthetic ELF
//! fixture, the decoded content supplies the ISA, corrupt or truncated
//! streams are errors rather than raw-code guesses, and streams that
//! decode past the extraction limit are classified from their prefix.

use zrax::formats::compressed::{self, Codec};
use zrax::{detect_payload, ClassifierOptions, Endianness, FileFormat, Isa, MetadataValue};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/compressed");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

/// Every committed fixture, its format and the codec that decodes it.
const STREAMS: &[(&str, FileFormat, Codec)] = &[
    ("payload.elf.gz", FileFormat::Gzip, Codec::Gzip),
    ("payload.elf.xz", FileFormat::Xz, Codec::Xz),
    ("payload.elf.bcj.xz", FileFormat::Xz, Codec::Xz),
    ("payload.elf.concat.xz", FileFormat::Xz, Codec::Xz),
    ("payload.elf.lzma", FileFormat::Lzma, Codec::Lzma),
    ("payload.elf.lz4", FileFormat::Lz4, Codec::Lz4),
    ("payload.elf.legacy.lz4", FileFormat::Lz4, Codec::Lz4Legacy),
    ("payload.elf.zst", FileFormat::Zstd, Codec::Zstd),
    ("payload.elf.bz2", FileFormat::Bzip2, Codec::Bzip2),
    ("payload.elf.lzo", FileFormat::Lzop, Codec::Lzop),
    ("payload.elf.lzfse", FileFormat::Lzfse, Codec::Lzfse),
];

fn metadata<'a>(payload: &'a zrax::DetectionPayload, key: &str) -> Option<&'a MetadataValue> {
    payload
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| &m.value)
}

#[test]
fn every_codec_decodes_the_fixture_payload_exactly() {
    let expected = fixture("payload.elf");
    for &(name, _, codec) in STREAMS {
        let stored = fixture(name);
        let decoded = compressed::decode(codec, &stored).unwrap_or_else(|e| panic!("{name}: {e}"));
        let copies = if name.contains("concat") { 2 } else { 1 };
        assert_eq!(decoded.data, expected.repeat(copies), "{name}");
        assert_eq!(decoded.consumed, Some(stored.len()), "{name}");
    }
}

#[test]
fn compressed_files_report_their_format_and_the_decoded_isa() {
    for &(name, format, _) in STREAMS {
        let payload = detect_payload(&fixture(name), &ClassifierOptions::new())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(payload.format.format, format, "{name}");
        assert_eq!(
            (
                payload.primary.isa,
                payload.primary.bitwidth,
                payload.primary.endianness
            ),
            (Isa::X86_64, 64, Endianness::Little),
            "{name}"
        );
        assert!(payload.slices.is_empty(), "{name}: an ELF has no slices");
        assert!(
            payload
                .notes
                .iter()
                .any(|n| n.message == "Decoded payload: ELF"),
            "{name}: {:?}",
            payload.notes
        );
        assert!(matches!(
            metadata(&payload, "compressed_content_format"),
            Some(MetadataValue::String(s)) if s == "ELF"
        ));
    }
}

#[test]
fn integrity_checks_are_reported_only_when_verified() {
    let gzip = detect_payload(&fixture("payload.elf.gz"), &ClassifierOptions::new()).unwrap();
    assert!(gzip
        .notes
        .iter()
        .any(|n| n.message.contains("CRC-32 verified")));
    let sha = detect_payload(&fixture("payload.elf.bcj.xz"), &ClassifierOptions::new()).unwrap();
    assert!(sha
        .notes
        .iter()
        .any(|n| n.message.contains("xz SHA-256 verified")));
    // lz4 -l writes no checksum; nothing may be claimed.
    let legacy = detect_payload(
        &fixture("payload.elf.legacy.lz4"),
        &ClassifierOptions::new(),
    )
    .unwrap();
    assert!(legacy
        .notes
        .iter()
        .any(|n| n.message.contains("no integrity check verified")));
}

#[test]
fn zlib_and_lzma_are_weak_and_need_a_complete_stream() {
    let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&fixture("payload.elf"), 9);
    let payload = detect_payload(&zlib, &ClassifierOptions::new()).unwrap();
    assert_eq!(payload.format.format, FileFormat::Zlib);
    assert_eq!(payload.primary.isa, Isa::X86_64);
    assert!(payload.format.confidence < 1.0);

    let lzma = fixture("payload.elf.lzma");
    assert!(matches!(
        zrax::formats::detect_format(&lzma),
        zrax::formats::DetectedFormat::Container { .. }
    ));
    // The range coder's final flush bytes are not all needed to decode, so
    // only a truncation into the coded data must lose recognition.
    assert!(matches!(
        zrax::formats::detect_format(&lzma[..lzma.len() / 2]),
        zrax::formats::DetectedFormat::Raw
    ));
}

#[test]
fn corrupt_strong_streams_are_errors() {
    for &(name, _, _) in STREAMS {
        let stored = fixture(name);
        // Flip a byte in the middle of the stored data (past every header).
        let mut corrupt = stored.clone();
        let middle = stored.len() / 2 + 8;
        corrupt[middle] ^= 0x55;
        match detect_payload(&corrupt, &ClassifierOptions::new()) {
            Err(_) => {}
            Ok(p) => assert_ne!(
                (p.format.format, p.primary.isa),
                (FileFormat::Raw, Isa::X86_64),
                "{name}"
            ),
        }
    }
}

#[test]
fn truncated_streams_never_claim_the_payload() {
    for &(name, format, _) in STREAMS {
        let stored = fixture(name);
        // The concatenated fixture's first half is itself a complete stream,
        // and LZMA-alone does not need the last bytes of its range coder.
        let complete_prefixes = match name {
            "payload.elf.concat.xz" => stored.len() / 2..stored.len() / 2 + 1,
            "payload.elf.lzma" => stored.len() - 4..stored.len(),
            _ => 0..0,
        };
        for end in (0..stored.len()).filter(|end| !complete_prefixes.contains(end)) {
            if let Ok(p) = detect_payload(&stored[..end], &ClassifierOptions::new()) {
                assert!(
                    !(p.format.format == format && p.primary.isa == Isa::X86_64),
                    "{name} prefix {end} still decoded"
                );
            }
        }
    }
}

#[test]
fn trailing_garbage_after_a_stream_is_rejected_but_padding_is_not() {
    let mut padded = fixture("payload.elf.gz");
    padded.extend_from_slice(&[0xff; 32]);
    assert_eq!(
        detect_payload(&padded, &ClassifierOptions::new())
            .unwrap()
            .primary
            .isa,
        Isa::X86_64
    );
    let mut garbage = fixture("payload.elf.gz");
    garbage.extend_from_slice(b"trailing");
    assert!(detect_payload(&garbage, &ClassifierOptions::new()).is_err());
}

#[test]
fn nested_compression_is_bounded_by_the_nesting_limit() {
    // gzip(gzip(...(ELF))) seven deep: the seventh level is not classified.
    let mut data = fixture("payload.elf");
    for _ in 0..7 {
        let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(&data, 6));
        member.extend_from_slice(&zrax::formats::checksum::crc32(&data).to_le_bytes());
        member.extend_from_slice(&(data.len() as u32).to_le_bytes());
        data = member;
    }
    let payload = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert_eq!(payload.format.format, FileFormat::Gzip);
    assert!(matches!(payload.primary.isa, Isa::Unknown(_)));
    assert!(payload
        .notes
        .iter()
        .any(|n| n.message.contains("nesting limit")));
}

/// Codecs that can stop at a limit, with their fixture.
const PREFIX_STREAMS: &[(&str, Codec)] = &[
    ("payload.elf.gz", Codec::Gzip),
    ("payload.elf.lzma", Codec::Lzma),
    ("payload.elf.lz4", Codec::Lz4),
    ("payload.elf.zst", Codec::Zstd),
    ("payload.elf.bz2", Codec::Bzip2),
];

#[test]
fn stream_prefixes_stop_at_the_limit() {
    let expected = fixture("payload.elf");
    for &(name, codec) in PREFIX_STREAMS {
        let prefix = compressed::decode_prefix(codec, &fixture(name), 100).unwrap();
        assert_eq!(prefix, expected[..100], "{name}");
        // A limit beyond the stream gives the whole payload.
        let whole = compressed::decode_prefix(codec, &fixture(name), 1 << 20).unwrap();
        assert_eq!(whole, expected, "{name}");
    }
    let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&expected, 6);
    assert_eq!(
        compressed::decode_prefix(Codec::Zlib, &zlib, 100).unwrap(),
        expected[..100]
    );
}

/// A gzip file of `members` members, each 1 MiB of zeros.
fn zero_gzip(members: usize) -> Vec<u8> {
    let zeros = vec![0u8; 1 << 20];
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(&zeros, 6));
    member.extend_from_slice(&zrax::formats::checksum::crc32(&zeros).to_le_bytes());
    member.extend_from_slice(&(zeros.len() as u32).to_le_bytes());
    member.repeat(members)
}

#[test]
fn streams_past_the_extraction_limit_are_classified_from_their_prefix() {
    let limit = zrax::formats::MAX_PAYLOAD;
    let stream = zero_gzip(limit / (1 << 20) + 1);
    let c = compressed::parse_container(&stream, Codec::Gzip).unwrap();
    assert_eq!(c.children.len(), 1);
    assert_eq!(c.children[0].data.len(), limit);
    assert!(c
        .notes
        .iter()
        .any(|n| n.contains("decoding stopped at the 64 MiB extraction limit")));

    // A stream within the limit with a bad CRC stays an error.
    let mut corrupt = zero_gzip(1);
    let crc_at = corrupt.len() - 8;
    corrupt[crc_at] ^= 1;
    assert!(compressed::parse_container(&corrupt, Codec::Gzip).is_err());
}

#[test]
fn byte_mutations_never_panic() {
    for &(name, _, _) in STREAMS {
        let stored = fixture(name);
        for i in 0..stored.len() {
            for value in [0x00, 0xff, stored[i] ^ 0x01] {
                let mut mutated = stored.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}
