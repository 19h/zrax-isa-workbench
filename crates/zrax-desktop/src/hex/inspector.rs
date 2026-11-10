//! The data inspector: the bytes at the cursor read as numbers, text and
//! time.
//!
//! Source: `renderDataInspector` in `web/workbench.js` and `fmtF`, `unixT`
//! and `utf8At` in `web/hex-utils.js`.

/// Bytes the inspector reads at the cursor: enough for a 64-bit value.
pub const WINDOW_BYTES: usize = 8;

/// The placeholder for a value the remaining bytes are too few for.
const NO_VALUE: &str = "—";

/// Seconds since the Unix epoch at 1980-01-01 and 2040-01-01 (UTC). A
/// 32-bit value outside this range is unlikely to be a timestamp.
const TIME32_FIRST: u32 = 315_532_800;
const TIME32_LAST: u32 = 2_208_988_800;

const SECONDS_PER_DAY: u32 = 86_400;

/// One row of the inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The interpretation: `u16`, `f32`, `utf-8`.
    pub kind: &'static str,
    /// The value as text.
    pub text: String,
    /// A second form below it: the hexadecimal of an unsigned integer.
    pub detail: Option<String>,
}

fn row(kind: &'static str, text: impl Into<String>) -> Value {
    Value {
        kind,
        text: text.into(),
        detail: None,
    }
}

/// The first `N` bytes of `bytes` in reading order for `little_endian`.
fn leading<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.get(..N)?.try_into().ok()
}

/// Every interpretation of the bytes at the cursor. `bytes` starts at the
/// cursor and holds up to [`WINDOW_BYTES`]; fewer near the end of the file.
/// Returns nothing for an empty window.
pub fn values(bytes: &[u8], little_endian: bool) -> Vec<Value> {
    let Some(&first) = bytes.first() else {
        return Vec::new();
    };
    let mut rows = vec![
        row("bin", format!("{:04b} {:04b}", first >> 4, first & 0x0F)),
        Value {
            kind: "u8",
            text: first.to_string(),
            detail: Some(format!("0x{first:02X}")),
        },
        row("i8", i8::from_ne_bytes([first]).to_string()),
    ];

    let unsigned = |text: String, hex: String| (text, Some(hex));
    let missing = || (NO_VALUE.to_string(), None);
    let (u16_row, i16_row) = match leading::<2>(bytes) {
        Some(raw) => {
            let (unsigned_value, signed_value) = if little_endian {
                (u16::from_le_bytes(raw), i16::from_le_bytes(raw))
            } else {
                (u16::from_be_bytes(raw), i16::from_be_bytes(raw))
            };
            (
                unsigned(
                    unsigned_value.to_string(),
                    format!("0x{unsigned_value:04X}"),
                ),
                (signed_value.to_string(), None),
            )
        }
        None => (missing(), missing()),
    };
    let (u32_row, i32_row) = match leading::<4>(bytes) {
        Some(raw) => {
            let (unsigned_value, signed_value) = if little_endian {
                (u32::from_le_bytes(raw), i32::from_le_bytes(raw))
            } else {
                (u32::from_be_bytes(raw), i32::from_be_bytes(raw))
            };
            (
                unsigned(
                    unsigned_value.to_string(),
                    format!("0x{unsigned_value:08X}"),
                ),
                (signed_value.to_string(), None),
            )
        }
        None => (missing(), missing()),
    };
    let (u64_row, i64_row) = match leading::<8>(bytes) {
        Some(raw) => {
            let (unsigned_value, signed_value) = if little_endian {
                (u64::from_le_bytes(raw), i64::from_le_bytes(raw))
            } else {
                (u64::from_be_bytes(raw), i64::from_be_bytes(raw))
            };
            (
                unsigned(
                    unsigned_value.to_string(),
                    format!("0x{unsigned_value:016X}"),
                ),
                (signed_value.to_string(), None),
            )
        }
        None => (missing(), missing()),
    };
    for (kind, (text, detail)) in [
        ("u16", u16_row),
        ("i16", i16_row),
        ("u32", u32_row),
        ("i32", i32_row),
        ("u64", u64_row),
        ("i64", i64_row),
    ] {
        rows.push(Value { kind, text, detail });
    }

    let word = leading::<4>(bytes).map(|raw| {
        if little_endian {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        }
    });
    let double = leading::<8>(bytes).map(|raw| {
        if little_endian {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        }
    });
    rows.push(row(
        "f32",
        word.map_or_else(
            || NO_VALUE.to_string(),
            |bits| float_text(f64::from(f32::from_bits(bits)), 7),
        ),
    ));
    rows.push(row(
        "f64",
        double.map_or_else(
            || NO_VALUE.to_string(),
            |bits| float_text(f64::from_bits(bits), 15),
        ),
    ));
    rows.push(row("utf-8", utf8_text(bytes)));
    rows.push(row(
        "time32",
        word.map_or_else(|| NO_VALUE.to_string(), unix_time_text),
    ));
    rows
}

/// A floating-point value with `digits` significant digits: plain decimal
/// between 1e-4 and 1e10, exponent notation outside (JavaScript's
/// `toPrecision` and `toExponential`, as `fmtF` uses them).
pub fn float_text(value: f64, digits: usize) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "+inf" } else { "-inf" }.into();
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let magnitude = value.abs();
    if (1e-4..1e10).contains(&magnitude) {
        // Round to `digits` significant digits, then print the shortest
        // decimal of the rounded value, which drops trailing zeros.
        let rounded: f64 = format!("{value:.*e}", digits.saturating_sub(1))
            .parse()
            .unwrap_or(value);
        return rounded.to_string();
    }
    let fraction_digits = if digits > 7 { 10 } else { 5 };
    let text = format!("{value:.fraction_digits$e}");
    // Rust writes `1.5e10`; JavaScript writes `1.5e+10`.
    match text.split_once('e') {
        Some((mantissa, exponent)) if !exponent.starts_with('-') => {
            format!("{mantissa}e+{exponent}")
        }
        _ => text,
    }
}

/// The first UTF-8 sequence of `bytes` as `é  U+00E9 · 2 bytes`, a control
/// character as `U+001A control`, or `invalid sequence`.
pub fn utf8_text(bytes: &[u8]) -> String {
    for length in 1..=bytes.len().min(4) {
        let Ok(text) = std::str::from_utf8(&bytes[..length]) else {
            continue;
        };
        let Some(character) = text.chars().next() else {
            continue;
        };
        let code = u32::from(character);
        if code < 0x20 || code == 0x7F {
            return format!("U+{code:04X} control");
        }
        let plural = if length > 1 { "s" } else { "" };
        return format!("{character}  U+{code:04X} · {length} byte{plural}");
    }
    "invalid sequence".into()
}

/// A 32-bit Unix time as `2024-05-06 07:08:09Z`, or a note that it is
/// outside 1980..=2040.
pub fn unix_time_text(seconds: u32) -> String {
    if !(TIME32_FIRST..=TIME32_LAST).contains(&seconds) {
        return format!("{NO_VALUE} (out of range)");
    }
    let (year, month, day) = civil_from_days(seconds / SECONDS_PER_DAY);
    let second_of_day = seconds % SECONDS_PER_DAY;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        second_of_day / 3600,
        second_of_day % 3600 / 60,
        second_of_day % 60
    )
}

/// The proleptic Gregorian date of `days` since 1970-01-01, by Howard
/// Hinnant's `civil_from_days` (public domain), for non-negative days.
fn civil_from_days(days: u32) -> (u32, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days fall at the end of a year.
    const DAYS_TO_UNIX_EPOCH: u32 = 719_468;
    const DAYS_PER_ERA: u32 = 146_097;
    let shifted = days + DAYS_TO_UNIX_EPOCH;
    let era = shifted / DAYS_PER_ERA;
    let day_of_era = shifted % DAYS_PER_ERA;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u32::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(rows: &[Value], kind: &str) -> String {
        rows.iter()
            .find(|value| value.kind == kind)
            .map(|value| value.text.clone())
            .unwrap()
    }

    /// The first bytes of the reference DFU file: `1A 3F 8D 00 00 00 00 00`.
    const REFERENCE: [u8; 8] = [0x1A, 0x3F, 0x8D, 0x00, 0x00, 0x00, 0x00, 0x00];

    #[test]
    fn little_endian_values_match_the_browser_inspector() {
        let rows = values(&REFERENCE, true);
        assert_eq!(text_of(&rows, "bin"), "0001 1010");
        assert_eq!(text_of(&rows, "u8"), "26");
        assert_eq!(text_of(&rows, "i8"), "26");
        assert_eq!(text_of(&rows, "u16"), "16154");
        assert_eq!(text_of(&rows, "u32"), "9256730");
        assert_eq!(text_of(&rows, "i64"), "9256730");
        assert_eq!(text_of(&rows, "f32"), "1.29714e-38");
        assert_eq!(text_of(&rows, "f64"), "4.5734322858e-317");
        assert_eq!(text_of(&rows, "utf-8"), "U+001A control");
        assert_eq!(text_of(&rows, "time32"), "— (out of range)");
        let details: Vec<Option<&str>> = rows.iter().map(|v| v.detail.as_deref()).collect();
        assert_eq!(details[1], Some("0x1A"));
        assert_eq!(details[3], Some("0x3F1A"));
        assert_eq!(details[5], Some("0x008D3F1A"));
        assert_eq!(details[7], Some("0x00000000008D3F1A"));
    }

    #[test]
    fn big_endian_reads_the_same_bytes_in_the_other_order() {
        let rows = values(&[0xFF, 0xFE, 0x00, 0x01], false);
        assert_eq!(text_of(&rows, "u16"), "65534");
        assert_eq!(text_of(&rows, "i16"), "-2");
        assert_eq!(text_of(&rows, "u32"), "4294836225");
        assert_eq!(text_of(&rows, "i8"), "-1");
    }

    #[test]
    fn short_windows_leave_wide_values_blank() {
        let rows = values(&[0x41, 0x42], true);
        assert_eq!(text_of(&rows, "u16"), "16961");
        assert_eq!(text_of(&rows, "u32"), "—");
        assert_eq!(text_of(&rows, "f64"), "—");
        assert_eq!(text_of(&rows, "time32"), "—");
        assert_eq!(text_of(&rows, "utf-8"), "A  U+0041 · 1 byte");
        assert_eq!(values(&[], true), Vec::new());
    }

    #[test]
    fn floats_switch_notation_at_the_documented_bounds() {
        assert_eq!(float_text(1.5, 7), "1.5");
        assert_eq!(float_text(0.1 + 0.2, 15), "0.3");
        assert_eq!(float_text(123_456_789.0, 7), "123456800");
        assert_eq!(float_text(1e10, 7), "1.00000e+10");
        assert_eq!(float_text(-0.0, 7), "-0");
        assert_eq!(float_text(0.0, 7), "0");
        assert_eq!(float_text(f64::NAN, 7), "NaN");
        assert_eq!(float_text(f64::NEG_INFINITY, 7), "-inf");
        assert_eq!(float_text(1e-5, 15), "1.0000000000e-5");
    }

    #[test]
    fn utf8_sequences_report_code_point_and_length() {
        assert_eq!(utf8_text("é".as_bytes()), "é  U+00E9 · 2 bytes");
        assert_eq!(utf8_text("€x".as_bytes()), "€  U+20AC · 3 bytes");
        assert_eq!(utf8_text(&[0xFF, 0x41]), "invalid sequence");
        assert_eq!(utf8_text(&[0xC3]), "invalid sequence");
    }

    #[test]
    fn times_are_utc_and_bounded_to_plausible_years() {
        assert_eq!(unix_time_text(315_532_800), "1980-01-01 00:00:00Z");
        assert_eq!(unix_time_text(1_709_210_096), "2024-02-29 12:34:56Z");
        assert_eq!(unix_time_text(2_208_988_800), "2040-01-01 00:00:00Z");
        assert_eq!(unix_time_text(315_532_799), "— (out of range)");
        assert_eq!(unix_time_text(u32::MAX), "— (out of range)");
    }
}
