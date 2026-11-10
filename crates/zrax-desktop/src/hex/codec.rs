//! Bytes as text in the hex grid's text column, and offsets typed into
//! its goto field.
//!
//! Source: `web/hex-utils.js` (`encChar`, `parseGoto`). The code-page
//! tables are the same data: IBM code page 437 and EBCDIC code page 037.

/// How the text column reads bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    /// Printable ASCII; everything else is a dot.
    Ascii,
    /// ISO 8859-1: ASCII plus `0xA0..=0xFF`.
    Latin1,
    /// IBM PC code page 437, with its graphics for control bytes.
    Cp437,
    /// EBCDIC code page 037.
    Ebcdic,
    /// UTF-16 code units, little-endian; one glyph per two bytes.
    Utf16Le,
    /// UTF-16 code units, big-endian; one glyph per two bytes.
    Utf16Be,
}

impl TextEncoding {
    /// Every encoding, in menu order.
    pub const ALL: [TextEncoding; 6] = [
        TextEncoding::Ascii,
        TextEncoding::Latin1,
        TextEncoding::Cp437,
        TextEncoding::Ebcdic,
        TextEncoding::Utf16Le,
        TextEncoding::Utf16Be,
    ];

    /// The name in the encoding control.
    pub fn label(self) -> &'static str {
        match self {
            TextEncoding::Ascii => "ascii",
            TextEncoding::Latin1 => "latin-1",
            TextEncoding::Cp437 => "cp437 (dos)",
            TextEncoding::Ebcdic => "ebcdic (cp037)",
            TextEncoding::Utf16Le => "utf-16le",
            TextEncoding::Utf16Be => "utf-16be",
        }
    }

    /// The settings and column-header identifier.
    pub fn id(self) -> &'static str {
        match self {
            TextEncoding::Ascii => "ascii",
            TextEncoding::Latin1 => "latin1",
            TextEncoding::Cp437 => "cp437",
            TextEncoding::Ebcdic => "ebcdic",
            TextEncoding::Utf16Le => "utf16le",
            TextEncoding::Utf16Be => "utf16be",
        }
    }

    /// Bytes one glyph of the text column stands for.
    pub fn unit_bytes(self) -> usize {
        match self {
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => 2,
            _ => 1,
        }
    }
}

/// The glyph for a byte that has no printable form in the encoding.
pub const UNPRINTABLE: char = '.';

/// Code page 437 graphics for `0x00..=0x1F` (`0x00` itself is shown as a dot).
const CP437_CONTROL: [char; 32] = [
    '\u{00b7}', '\u{263a}', '\u{263b}', '\u{2665}', '\u{2666}', '\u{2663}', '\u{2660}', '\u{2022}',
    '\u{25d8}', '\u{25cb}', '\u{25d9}', '\u{2642}', '\u{2640}', '\u{266a}', '\u{266b}', '\u{263c}',
    '\u{25ba}', '\u{25c4}', '\u{2195}', '\u{203c}', '\u{00b6}', '\u{00a7}', '\u{25ac}', '\u{21a8}',
    '\u{2191}', '\u{2193}', '\u{2192}', '\u{2190}', '\u{221f}', '\u{2194}', '\u{25b2}', '\u{25bc}',
];

/// Code page 437 for `0x80..=0xFF`.
const CP437_HIGH: [char; 128] = [
    '\u{00c7}', '\u{00fc}', '\u{00e9}', '\u{00e2}', '\u{00e4}', '\u{00e0}', '\u{00e5}', '\u{00e7}',
    '\u{00ea}', '\u{00eb}', '\u{00e8}', '\u{00ef}', '\u{00ee}', '\u{00ec}', '\u{00c4}', '\u{00c5}',
    '\u{00c9}', '\u{00e6}', '\u{00c6}', '\u{00f4}', '\u{00f6}', '\u{00f2}', '\u{00fb}', '\u{00f9}',
    '\u{00ff}', '\u{00d6}', '\u{00dc}', '\u{00a2}', '\u{00a3}', '\u{00a5}', '\u{20a7}', '\u{0192}',
    '\u{00e1}', '\u{00ed}', '\u{00f3}', '\u{00fa}', '\u{00f1}', '\u{00d1}', '\u{00aa}', '\u{00ba}',
    '\u{00bf}', '\u{2310}', '\u{00ac}', '\u{00bd}', '\u{00bc}', '\u{00a1}', '\u{00ab}', '\u{00bb}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255d}', '\u{255c}', '\u{255b}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252c}', '\u{251c}', '\u{2500}', '\u{253c}', '\u{255e}', '\u{255f}',
    '\u{255a}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256c}', '\u{2567}',
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256b}',
    '\u{256a}', '\u{2518}', '\u{250c}', '\u{2588}', '\u{2584}', '\u{258c}', '\u{2590}', '\u{2580}',
    '\u{03b1}', '\u{00df}', '\u{0393}', '\u{03c0}', '\u{03a3}', '\u{03c3}', '\u{00b5}', '\u{03c4}',
    '\u{03a6}', '\u{0398}', '\u{03a9}', '\u{03b4}', '\u{221e}', '\u{03c6}', '\u{03b5}', '\u{2229}',
    '\u{2261}', '\u{00b1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00f7}', '\u{2248}',
    '\u{00b0}', '\u{2219}', '\u{00b7}', '\u{221a}', '\u{207f}', '\u{00b2}', '\u{25a0}', '\u{00a0}',
];

/// EBCDIC code page 037 to Unicode, including its control characters.
const EBCDIC_CP037: [char; 256] = [
    '\u{0000}', '\u{0001}', '\u{0002}', '\u{0003}', '\u{009c}', '\u{0009}', '\u{0086}', '\u{007f}',
    '\u{0097}', '\u{008d}', '\u{008e}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{000e}', '\u{000f}',
    '\u{0010}', '\u{0011}', '\u{0012}', '\u{0013}', '\u{009d}', '\u{0085}', '\u{0008}', '\u{0087}',
    '\u{0018}', '\u{0019}', '\u{0092}', '\u{008f}', '\u{001c}', '\u{001d}', '\u{001e}', '\u{001f}',
    '\u{0080}', '\u{0081}', '\u{0082}', '\u{0083}', '\u{0084}', '\u{000a}', '\u{0017}', '\u{001b}',
    '\u{0088}', '\u{0089}', '\u{008a}', '\u{008b}', '\u{008c}', '\u{0005}', '\u{0006}', '\u{0007}',
    '\u{0090}', '\u{0091}', '\u{0016}', '\u{0093}', '\u{0094}', '\u{0095}', '\u{0096}', '\u{0004}',
    '\u{0098}', '\u{0099}', '\u{009a}', '\u{009b}', '\u{0014}', '\u{0015}', '\u{009e}', '\u{001a}',
    ' ', '\u{00a0}', '\u{00e2}', '\u{00e4}', '\u{00e0}', '\u{00e1}', '\u{00e3}', '\u{00e5}',
    '\u{00e7}', '\u{00f1}', '\u{00a2}', '.', '<', '(', '+', '|', '&', '\u{00e9}', '\u{00ea}',
    '\u{00eb}', '\u{00e8}', '\u{00ed}', '\u{00ee}', '\u{00ef}', '\u{00ec}', '\u{00df}', '!', '$',
    '*', ')', ';', '\u{00ac}', '-', '/', '\u{00c2}', '\u{00c4}', '\u{00c0}', '\u{00c1}',
    '\u{00c3}', '\u{00c5}', '\u{00c7}', '\u{00d1}', '\u{00a6}', ',', '%', '_', '>', '?',
    '\u{00f8}', '\u{00c9}', '\u{00ca}', '\u{00cb}', '\u{00c8}', '\u{00cd}', '\u{00ce}', '\u{00cf}',
    '\u{00cc}', '`', ':', '#', '@', '\'', '=', '"', '\u{00d8}', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', '\u{00ab}', '\u{00bb}', '\u{00f0}', '\u{00fd}', '\u{00fe}', '\u{00b1}', '\u{00b0}',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '\u{00aa}', '\u{00ba}', '\u{00e6}', '\u{00b8}',
    '\u{00c6}', '\u{00a4}', '\u{00b5}', '~', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '\u{00a1}',
    '\u{00bf}', '\u{00d0}', '\u{00dd}', '\u{00de}', '\u{00ae}', '^', '\u{00a3}', '\u{00a5}',
    '\u{00b7}', '\u{00a9}', '\u{00a7}', '\u{00b6}', '\u{00bc}', '\u{00bd}', '\u{00be}', '[', ']',
    '\u{00af}', '\u{00a8}', '\u{00b4}', '\u{00d7}', '{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', '\u{00ad}', '\u{00f4}', '\u{00f6}', '\u{00f2}', '\u{00f3}', '\u{00f5}', '}', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', '\u{00b9}', '\u{00fb}', '\u{00fc}', '\u{00f9}', '\u{00fa}',
    '\u{00ff}', '\\', '\u{00f7}', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '\u{00b2}', '\u{00d4}',
    '\u{00d6}', '\u{00d2}', '\u{00d3}', '\u{00d5}', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '\u{00b3}', '\u{00db}', '\u{00dc}', '\u{00d9}', '\u{00da}', '\u{009f}',
];

/// The glyph of one byte in a single-byte encoding. UTF-16 encodings read
/// two bytes at a time; see [`utf16_glyph`].
pub fn byte_glyph(encoding: TextEncoding, byte: u8) -> char {
    match encoding {
        TextEncoding::Ebcdic => {
            let character = EBCDIC_CP037[usize::from(byte)];
            let code = u32::from(character);
            let is_printable = code >= 32 && !(127..160).contains(&code);
            if is_printable {
                character
            } else {
                UNPRINTABLE
            }
        }
        _ if (32..127).contains(&byte) => char::from(byte),
        TextEncoding::Latin1 if byte >= 0xA0 => char::from(byte),
        TextEncoding::Cp437 => match byte {
            0 => UNPRINTABLE,
            1..=31 => CP437_CONTROL[usize::from(byte)],
            127 => '\u{2302}',
            _ => CP437_HIGH[usize::from(byte - 128)],
        },
        _ => UNPRINTABLE,
    }
}

/// The glyph of one UTF-16 code unit: printable Basic Multilingual Plane
/// characters as themselves; controls, surrogates and noncharacters as a
/// dot.
pub fn utf16_glyph(unit: u16) -> char {
    let is_printable = matches!(unit, 32..=126 | 160..=0xD7FF | 0xE000..=0xFFFD);
    if is_printable {
        char::from_u32(u32::from(unit)).unwrap_or(UNPRINTABLE)
    } else {
        UNPRINTABLE
    }
}

/// Parse what was typed into the goto field into a byte offset.
///
/// Accepted, after removing spaces and underscores, case-insensitive:
/// `0x1F00` and `1F00h` (hex), `7936` (decimal), bare hex digits such as
/// `1f00`, `50%` of the file, and any of these with a leading `+` or `-`
/// relative to `cursor`. Returns `None` for anything else. The result is
/// not clamped to the file.
pub fn parse_goto(text: &str, cursor: u64, size: u64) -> Option<i128> {
    let cleaned: String = text
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .flat_map(char::to_lowercase)
        .collect();
    let (direction, digits) = match cleaned.as_bytes().first()? {
        b'+' => (1, &cleaned[1..]),
        b'-' => (-1, &cleaned[1..]),
        _ => (0, cleaned.as_str()),
    };
    let value = parse_goto_value(digits, size)?;
    Some(if direction == 0 {
        value
    } else {
        i128::from(cursor) + direction * value
    })
}

fn parse_goto_value(digits: &str, size: u64) -> Option<i128> {
    let is_decimal = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    // `from_str_radix` would also take a sign; only digits are an offset.
    let hex = |text: &str| {
        let is_hex = !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit());
        is_hex
            .then(|| i128::from_str_radix(text, 16).ok())
            .flatten()
    };
    if let Some(percent) = digits.strip_suffix('%') {
        let (whole, fraction) = percent.split_once('.').unwrap_or((percent, "0"));
        if !is_decimal(whole) || !is_decimal(fraction) {
            return None;
        }
        let percent: f64 = percent.parse().ok()?;
        // A position within the file: precise enough for navigation.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let offset = (percent / 100.0 * size.saturating_sub(1) as f64).floor() as u64;
        return Some(i128::from(offset));
    }
    if let Some(hex_digits) = digits.strip_prefix("0x") {
        return hex(hex_digits);
    }
    if let Some(hex_digits) = digits.strip_suffix('h') {
        return hex(hex_digits);
    }
    if is_decimal(digits) {
        return digits.parse().ok();
    }
    hex(digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_shows_printable_bytes_and_dots() {
        assert_eq!(byte_glyph(TextEncoding::Ascii, b'A'), 'A');
        assert_eq!(byte_glyph(TextEncoding::Ascii, 0x1A), '.');
        assert_eq!(byte_glyph(TextEncoding::Ascii, 0x7F), '.');
        assert_eq!(byte_glyph(TextEncoding::Ascii, 0xE9), '.');
    }

    #[test]
    fn single_byte_code_pages_follow_their_tables() {
        assert_eq!(byte_glyph(TextEncoding::Latin1, 0xE9), 'é');
        assert_eq!(byte_glyph(TextEncoding::Latin1, 0x85), '.');
        assert_eq!(byte_glyph(TextEncoding::Cp437, 0x00), '.');
        assert_eq!(byte_glyph(TextEncoding::Cp437, 0x01), '☺');
        assert_eq!(byte_glyph(TextEncoding::Cp437, 0x7F), '⌂');
        assert_eq!(byte_glyph(TextEncoding::Cp437, 0x80), 'Ç');
        assert_eq!(byte_glyph(TextEncoding::Cp437, 0xDB), '█');
        assert_eq!(byte_glyph(TextEncoding::Ebcdic, 0xC1), 'A');
        assert_eq!(byte_glyph(TextEncoding::Ebcdic, 0xF0), '0');
        assert_eq!(byte_glyph(TextEncoding::Ebcdic, 0x40), ' ');
        assert_eq!(byte_glyph(TextEncoding::Ebcdic, 0x00), '.');
    }

    #[test]
    fn utf16_units_hide_controls_surrogates_and_noncharacters() {
        assert_eq!(utf16_glyph(0x0041), 'A');
        assert_eq!(utf16_glyph(0x00E9), 'é');
        assert_eq!(utf16_glyph(0x001F), '.');
        assert_eq!(utf16_glyph(0x007F), '.');
        assert_eq!(utf16_glyph(0x0085), '.');
        assert_eq!(utf16_glyph(0xD800), '.');
        assert_eq!(utf16_glyph(0xFFFE), '.');
    }

    #[test]
    fn goto_accepts_every_documented_form() {
        assert_eq!(parse_goto("0x1F00", 0, 100), Some(0x1F00));
        assert_eq!(parse_goto("1f00h", 0, 100), Some(0x1F00));
        assert_eq!(parse_goto("7936", 0, 100), Some(7936));
        assert_eq!(parse_goto("1f", 0, 100), Some(0x1F));
        assert_eq!(parse_goto(" 0x_10 00 ", 0, 100), Some(0x1000));
        assert_eq!(parse_goto("+16", 100, 1000), Some(116));
        assert_eq!(parse_goto("-0x10", 8, 1000), Some(-8));
        assert_eq!(parse_goto("50%", 0, 1001), Some(500));
        assert_eq!(parse_goto("12.5%", 0, 801), Some(100));
        assert_eq!(parse_goto("100%", 0, 0), Some(0));
    }

    #[test]
    fn goto_rejects_everything_else() {
        for text in ["", "  ", "+", "0x", "xyz", "12g", "%", "1.%", "--4", "0x-4"] {
            assert_eq!(parse_goto(text, 0, 100), None, "{text:?}");
        }
    }
}
