//! String extraction: run rules per encoding, UTF-8 well-formedness, UTF-16
//! parity, clipping, tags, output order and independence from chunk
//! boundaries.

use zrax::strings::{
    extract, Encoding, Encodings, FoundString, Options, Scanner, Tags, MAX_TEXT_CHARS,
};

const ALL: Encodings = Encodings::all();

fn options(min_chars: usize, encodings: Encodings) -> Options {
    Options::new(min_chars, encodings).unwrap()
}

fn strings(data: &[u8], min_chars: usize, encodings: Encodings) -> Vec<FoundString> {
    extract(data, &options(min_chars, encodings), usize::MAX).strings
}

/// `(offset, size, chars, encoding, text)` of each string.
fn summary(found: &[FoundString]) -> Vec<(u64, u64, u64, Encoding, String)> {
    found
        .iter()
        .map(|s| (s.offset, s.size, s.chars, s.encoding, s.text.clone()))
        .collect()
}

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn utf16be(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// Deterministic noise from a 32-bit linear congruential generator.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

/// Every encoding, separated by non-printable bytes.
fn mixed_sample() -> Vec<u8> {
    let mut data = b"\x01\x02ascii text here\x00".to_vec();
    data.extend_from_slice("Grüße aus Köln\x00".as_bytes());
    data.push(0xff);
    data.extend_from_slice(&utf16le("wide string"));
    data.extend_from_slice(&[0xff, 0xfe, 0x01]);
    data.extend_from_slice(&utf16be("big endian"));
    data.extend_from_slice(&[0x01, 0xc3]);
    data.extend_from_slice(b"tab\tseparated");
    data
}

#[test]
fn ascii_runs_respect_the_minimum_length() {
    let data = b"abc\x00abcd\x00";
    assert_eq!(
        summary(&strings(data, 4, ALL)),
        vec![(4, 4, 4, Encoding::Ascii, "abcd".into())]
    );
    assert_eq!(strings(data, 3, ALL).len(), 2);
}

#[test]
fn tab_belongs_to_a_run_and_line_feed_ends_it() {
    let found = strings(b"ab\tcd\nefgh", 4, Encodings::ASCII);
    assert_eq!(
        summary(&found),
        vec![
            (0, 5, 5, Encoding::Ascii, "ab\tcd".into()),
            (6, 4, 4, Encoding::Ascii, "efgh".into()),
        ]
    );
}

#[test]
fn multibyte_scalars_make_a_utf8_run_and_split_ascii_otherwise() {
    let text = "Grüße aus Köln";
    let utf8 = strings(text.as_bytes(), 4, Encodings::ASCII | Encodings::UTF8);
    assert_eq!(
        summary(&utf8),
        vec![(0, text.len() as u64, 14, Encoding::Utf8, text.into())]
    );
    let ascii = strings(text.as_bytes(), 4, Encodings::ASCII);
    let texts: Vec<&str> = ascii.iter().map(|s| s.text.as_str()).collect();
    assert_eq!(texts, vec!["e aus K"]);
    // UTF-8 alone does not report pure-ASCII runs.
    assert!(strings(b"plain", 4, Encodings::UTF8).is_empty());
}

#[test]
fn ill_formed_utf8_ends_runs() {
    // Overlong NUL, a surrogate, a byte that is never a lead and a C1
    // control (U+0085) each separate the ASCII runs.
    for separator in [&b"\xc0\x80"[..], b"\xed\xa0\x80", b"\xf5", b"\xc2\x85"] {
        let mut data = b"abcd".to_vec();
        data.extend_from_slice(separator);
        data.extend_from_slice(b"efgh");
        let found = strings(&data, 4, Encodings::ASCII | Encodings::UTF8);
        let texts: Vec<&str> = found.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, vec!["abcd", "efgh"], "{separator:02X?}");
        assert!(found.iter().all(|s| s.encoding == Encoding::Ascii));
    }
}

#[test]
fn an_incomplete_final_sequence_is_not_part_of_the_run() {
    let found = strings(b"abcd\xc3", 4, Encodings::ASCII | Encodings::UTF8);
    assert_eq!(summary(&found), vec![(0, 4, 4, Encoding::Ascii, "abcd".into())]);
}

#[test]
fn utf16_parity_is_absolute() {
    for prefix in [0usize, 1, 2, 3] {
        let mut data = vec![0x01; prefix];
        data.extend_from_slice(&utf16le("Hello"));
        data.push(0x01);
        let found = strings(&data, 4, Encodings::UTF16LE);
        assert_eq!(
            summary(&found),
            vec![(prefix as u64, 10, 5, Encoding::Utf16le, "Hello".into())],
            "prefix {prefix}"
        );
    }
    let found = strings(&utf16be("Hello"), 4, Encodings::UTF16BE);
    assert_eq!(summary(&found), vec![(0, 10, 5, Encoding::Utf16be, "Hello".into())]);
}

#[test]
fn utf16_includes_latin1_and_excludes_higher_code_units() {
    let found = strings(&utf16le("étés"), 4, Encodings::UTF16LE);
    assert_eq!(found[0].text, "étés");
    assert!(strings(&utf16le("ĀĀĀĀ"), 4, Encodings::UTF16LE).is_empty());
}

#[test]
fn little_endian_text_after_a_zero_byte_also_reads_as_big_endian() {
    let mut data = vec![0x00];
    data.extend_from_slice(&utf16le("Hello"));
    let found = strings(&data, 4, Encodings::UTF16LE | Encodings::UTF16BE);
    assert_eq!(
        summary(&found),
        vec![
            (0, 10, 5, Encoding::Utf16be, "Hello".into()),
            (1, 10, 5, Encoding::Utf16le, "Hello".into()),
        ]
    );
}

#[test]
fn long_runs_are_clipped_but_keep_their_full_length() {
    let data = vec![b'A'; MAX_TEXT_CHARS + 904];
    let found = strings(&data, 4, Encodings::ASCII);
    assert_eq!(found.len(), 1);
    assert!(found[0].clipped);
    assert_eq!(found[0].chars, data.len() as u64);
    assert_eq!(found[0].size, data.len() as u64);
    assert_eq!(found[0].text.len(), MAX_TEXT_CHARS);
}

#[test]
fn output_is_in_offset_then_encoding_order() {
    let found = strings(&mixed_sample(), 4, ALL);
    let keys: Vec<(u64, Encoding)> = found.iter().map(|s| (s.offset, s.encoding)).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    let texts: Vec<&str> = found.iter().map(|s| s.text.as_str()).collect();
    for expected in [
        "ascii text here",
        "Grüße aus Köln",
        "wide string",
        "big endian",
        "tab\tseparated",
    ] {
        assert!(texts.contains(&expected), "{expected:?} in {texts:?}");
    }
}

/// Feed `data` in chunks ending at `cuts`.
fn chunked(data: &[u8], options: &Options, cuts: &[usize]) -> Vec<FoundString> {
    let mut scanner = Scanner::new(*options);
    let mut found = Vec::new();
    let mut start = 0;
    for &cut in cuts.iter().chain(std::iter::once(&data.len())) {
        scanner.push(&data[start..cut], &mut found);
        start = cut;
    }
    scanner.finish(&mut found);
    found
}

#[test]
fn every_two_chunk_split_gives_the_whole_input_result() {
    let data = mixed_sample();
    let options = options(3, ALL);
    let whole = extract(&data, &options, usize::MAX).strings;
    for cut in 0..=data.len() {
        assert_eq!(chunked(&data, &options, &[cut]), whole, "cut {cut}");
    }
}

#[test]
fn random_chunk_sizes_give_the_whole_input_result_on_noise() {
    let mut data = noise(1 << 20, 7);
    // Plant every encoding in the noise.
    let sample = mixed_sample();
    for at in (0..data.len() - sample.len()).step_by(65_537) {
        data[at..at + sample.len()].copy_from_slice(&sample);
    }
    let options = options(4, ALL);
    let whole = extract(&data, &options, usize::MAX).strings;
    assert!(whole.len() > 100);
    let lengths = noise(64, 11);
    let mut cuts = Vec::new();
    let mut at = 0;
    for (i, length) in lengths.iter().cycle().enumerate() {
        at += usize::from(*length) * 97 + i % 5;
        if at >= data.len() {
            break;
        }
        cuts.push(at);
    }
    assert_eq!(chunked(&data, &options, &cuts), whole);
}

#[test]
fn found_strings_carry_their_tags() {
    let found = strings(b"\x00https://example.invalid/a\x00%s=%d\x00", 4, Encodings::ASCII);
    assert_eq!(found[0].tags, Tags::URL);
    assert_eq!(found[1].tags, Tags::FORMAT);
}

#[test]
fn the_limit_truncates_in_offset_order() {
    let data = b"aaaa\x00bbbb\x00cccc\x00";
    let extraction = extract(data, &options(4, Encodings::ASCII), 2);
    assert!(extraction.truncated);
    let texts: Vec<&str> = extraction.strings.iter().map(|s| s.text.as_str()).collect();
    assert_eq!(texts, vec!["aaaa", "bbbb"]);
    assert!(!extract(data, &options(4, Encodings::ASCII), 3).truncated);
}

#[test]
fn json_uses_encoding_and_tag_identifiers() {
    let found = strings(&utf16le("/usr/lib/x"), 4, Encodings::UTF16LE);
    let value = serde_json::to_value(&found[0]).unwrap();
    assert_eq!(value["encoding"], "utf16le");
    assert_eq!(value["tags"], serde_json::json!(["path"]));
    assert_eq!(value["clipped"], false);
    assert_eq!(Encoding::from_id("utf8"), Some(Encoding::Utf8));
}

#[test]
fn noise_is_deterministic_and_bounded() {
    let data = noise(1 << 20, 99);
    let options = options(3, ALL);
    let first = extract(&data, &options, usize::MAX);
    assert_eq!(first, extract(&data, &options, usize::MAX));
    for s in &first.strings {
        let end = s.offset + s.size;
        assert!(end <= data.len() as u64);
        assert!(s.chars >= 3);
    }
}
