//! Character fields: OSTA CS0 strings (UDF 2.60 2.1.1, 6.4), dstrings
//! (ECMA-167 1/7.2.12, UDF 2.60 2.1.3), entity identifiers (1/7.4, UDF 2.60
//! 2.1.5) and timestamps (1/7.3, UDF 2.60 2.1.4).

/// OSTA Compressed Unicode compression IDs: 8 bits per character, 16 bits
/// per character (big-endian), and the deleted-name forms of both (UDF 2.60
/// 2.1.1, 2.3.4.2.1).
const COMPRESSION_8: u8 = 8;
const COMPRESSION_16: u8 = 16;

/// Offset and length of the identifier in an entity identifier (`regid`):
/// flags (0), identifier (1, 23 B), suffix (24, 8 B).
const REGID_IDENTIFIER: std::ops::Range<usize> = 1..24;

/// Offset of the identifier suffix in an entity identifier.
pub(super) const REGID_SUFFIX: usize = 24;

/// Size of an entity identifier.
pub(super) const REGID_SIZE: usize = 32;

/// Size of a timestamp (ECMA-167 1/7.3 figure 1/7).
pub(super) const TIMESTAMP_SIZE: usize = 12;

/// Time zone value meaning "not specified" (1/7.3.1).
const NO_TIME_ZONE: i16 = -2047;

/// Largest time zone offset in minutes (1/7.3.1).
const MAX_TIME_ZONE: i16 = 1440;

/// Decode an OSTA CS0 string: a compression ID followed by 8-bit
/// characters (Unicode code points below 256) or 16-bit big-endian code
/// units. `None` for another compression ID, including the deleted-name
/// IDs 254 and 255, or 16-bit units of odd length. Unpaired surrogates
/// become U+FFFD, as Linux `udf_name_from_CS0` maps invalid units.
pub(super) fn cs0(bytes: &[u8]) -> Option<String> {
    let (&compression, characters) = bytes.split_first()?;
    match compression {
        COMPRESSION_8 => Some(characters.iter().map(|&b| char::from(b)).collect()),
        COMPRESSION_16 if characters.len() % 2 == 0 => {
            let units = characters
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
            Some(
                char::decode_utf16(units)
                    .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect(),
            )
        }
        _ => None,
    }
}

/// A dstring field: the used length is the last byte, and an all-zero
/// field is the empty string (UDF 2.60 2.1.3). A length past the field is
/// read as the whole field; an undecodable string as its printable bytes.
/// Control characters, such as the NUL bytes some writers leave inside
/// volume set identifiers, become spaces.
pub(super) fn dstring(field: &[u8]) -> String {
    let Some((&used, characters)) = field.split_last() else {
        return String::new();
    };
    let used = usize::from(used).min(characters.len());
    if used == 0 {
        return String::new();
    }
    let recorded = &characters[..used];
    let decoded = cs0(recorded).unwrap_or_else(|| printable(recorded));
    decoded
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// The identifier of an entity identifier as text, without NUL padding:
/// `*OSTA UDF Compliant`, `+NSR03`.
pub(super) fn regid_identifier(regid: &[u8]) -> String {
    let identifier = regid.get(REGID_IDENTIFIER).unwrap_or_default();
    let end = identifier
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(identifier.len());
    printable(&identifier[..end])
}

/// Bytes as text, with bytes outside printable ASCII as `.`.
fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect()
}

/// A UDF revision recorded in binary-coded decimal (`0x0250` is 2.50, UDF
/// 2.60 2.1.5.3).
pub(super) fn revision_text(revision: u16) -> String {
    let [minor, major] = revision.to_le_bytes();
    format!("{major:X}.{minor:02X}")
}

/// A timestamp (ECMA-167 1/7.3): type and time zone (0, 2: type in the
/// high 4 bits, a signed 12-bit offset in minutes from UTC in the low 12
/// bits, -2047 for none), year (2, Int16), month (4), day (5), hour (6),
/// minute (7), second (8). `None` when all fields are 0 ("not specified")
/// or a field is out of range.
pub(super) fn timestamp_text(field: &[u8]) -> Option<String> {
    let field = field.get(..TIMESTAMP_SIZE)?;
    if field.iter().all(|&b| b == 0) {
        return None;
    }
    let type_and_zone = u16::from_le_bytes([field[0], field[1]]);
    let year = i16::from_le_bytes([field[2], field[3]]);
    let [month, day, hour, minute, second] = [field[4], field[5], field[6], field[7], field[8]];
    let in_range = (1..=9999).contains(&year)
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 60;
    if !in_range {
        return None;
    }
    // Sign-extend the low 12 bits.
    let zone_bits = i16::try_from(type_and_zone & 0x0fff).expect("12 bits");
    let zone = if zone_bits >= 0x0800 {
        zone_bits - 0x1000
    } else {
        zone_bits
    };
    let offset = if zone == NO_TIME_ZONE || zone.abs() > MAX_TIME_ZONE {
        String::new()
    } else {
        let sign = if zone < 0 { '-' } else { '+' };
        let minutes = zone.unsigned_abs();
        format!(" UTC{sign}{:02}:{:02}", minutes / 60, minutes % 60)
    };
    Some(format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}{offset}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cs0_decodes_8_and_16_bit_strings() {
        assert_eq!(cs0(b"\x08caf\xe9").as_deref(), Some("caf\u{e9}"));
        assert_eq!(
            cs0(&[16, 0x00, b'a', 0x20, 0xac]).as_deref(),
            Some("a\u{20ac}")
        );
        assert_eq!(cs0(&[16, 0xd8, 0x00]).as_deref(), Some("\u{fffd}"));
        assert_eq!(cs0(&[16, 0x00]), None);
        assert_eq!(cs0(&[254, b'x']), None);
        assert_eq!(cs0(&[]), None);
    }

    #[test]
    fn dstrings_use_the_length_in_the_last_byte() {
        let mut field = [0u8; 32];
        field[..5].copy_from_slice(b"\x08ZRAX");
        field[31] = 5;
        assert_eq!(dstring(&field), "ZRAX");
        assert_eq!(dstring(&[0; 32]), "");
        field[31] = 200;
        assert_eq!(dstring(&field), "ZRAX");
        field[..7].copy_from_slice(b"\x08AB\0\0CD");
        field[31] = 7;
        assert_eq!(dstring(&field), "AB  CD");
    }

    #[test]
    fn entity_identifiers_and_revisions() {
        let mut regid = [0u8; REGID_SIZE];
        regid[1..20].copy_from_slice(b"*OSTA UDF Compliant");
        assert_eq!(regid_identifier(&regid), "*OSTA UDF Compliant");
        assert_eq!(revision_text(0x0250), "2.50");
        assert_eq!(revision_text(0x0102), "1.02");
    }

    #[test]
    fn timestamps_carry_the_time_zone() {
        // Type 1 (local time), +120 minutes; 2026-10-13 20:08:19.
        let mut field = [0u8; TIMESTAMP_SIZE];
        field[0..2].copy_from_slice(&(0x1000u16 | 0x0078).to_le_bytes());
        field[2..4].copy_from_slice(&2026i16.to_le_bytes());
        field[4..9].copy_from_slice(&[10, 13, 20, 8, 19]);
        assert_eq!(
            timestamp_text(&field).as_deref(),
            Some("2026-10-13 20:08:19 UTC+02:00")
        );
        // -300 minutes (Eastern Standard Time, UDF 2.60 2.1.4.1 note 1).
        let west = (0x1000u16 | (0x1000 - 300)).to_le_bytes();
        field[0..2].copy_from_slice(&west);
        assert!(timestamp_text(&field).unwrap().ends_with("UTC-05:00"));
        field[4] = 13;
        assert_eq!(timestamp_text(&field), None);
        assert_eq!(timestamp_text(&[0; TIMESTAMP_SIZE]), None);
    }
}
